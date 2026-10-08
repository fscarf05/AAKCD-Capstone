"""Run with:  python -m unittest -v"""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import enrich
from alerts import build_alert
from detector import DetectorConfig, ScanDetector, Suppression
from zeek_parser import ConnectionEvent, LogFollower, ZeekConnParser

ATTACKER, VICTIM = "192.168.56.10", "192.168.56.20"


def ev(ts, src=ATTACKER, dst=VICTIM, port=80, proto="tcp", state="REJ"):
    return ConnectionEvent(ts, src, dst, port, proto, state)


def run(detector, events):
    return [f for f in (detector.process(e) for e in events) if f]


class TestParser(unittest.TestCase):
    def test_tsv_with_header(self):
        p = ZeekConnParser()
        for line in ["#separator \\x09",
                     "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state"]:
            self.assertIsNone(p.parse_line(line))
        e = p.parse_line("1790000000.5\tCabc\t10.0.0.1\t50000\t10.0.0.2\t22\ttcp\tS0")
        self.assertEqual(e, ConnectionEvent(1790000000.5, "10.0.0.1", "10.0.0.2", 22, "tcp", "S0"))

    def test_json_line(self):
        line = json.dumps({"ts": 1790000000.0, "id.orig_h": "10.0.0.1", "id.orig_p": 5,
                           "id.resp_h": "10.0.0.2", "id.resp_p": 443, "proto": "tcp", "conn_state": "SF"})
        self.assertEqual(ZeekConnParser().parse_line(line).dst_port, 443)

    def test_unset_and_malformed_lines_are_skipped(self):
        p = ZeekConnParser()
        p.parse_line("#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p")
        self.assertIsNone(p.parse_line("1790000000.0\t10.0.0.1\t10.0.0.2\t-"))
        self.assertIsNone(p.parse_line("{not json"))
        self.assertIsNone(ZeekConnParser().parse_line("data before any #fields header"))


class TestDetector(unittest.TestCase):
    def test_benign_traffic_raises_nothing(self):
        # 3 clients, 500 connections, only ports 443/53
        events = [ev(i, src=f"192.168.56.{21 + i % 3}", dst="8.8.8.8", port=443 if i % 2 else 53, state="SF")
                  for i in range(500)]
        self.assertEqual(run(ScanDetector(), events), [])

    def test_vertical_scan_escalates_medium_then_high(self):
        findings = run(ScanDetector(), [ev(i * 0.01, port=p) for i, p in enumerate(range(1, 201))])
        self.assertEqual([f.severity for f in findings], ["MEDIUM", "HIGH"])
        self.assertEqual(findings[0].distinct_targets, 20)    # fires exactly at the threshold
        self.assertEqual(findings[1].distinct_targets, 100)
        self.assertEqual(findings[0].scan_type, "vertical")
        self.assertEqual(findings[0].confidence, "high")

    def test_horizontal_sweep_maps_to_T1595_001(self):
        findings = run(ScanDetector(), [ev(i, dst=f"192.168.56.{i}", port=22, state="S0") for i in range(1, 51)])
        self.assertEqual(findings[0].scan_type, "horizontal")
        self.assertEqual(build_alert(findings[0])["mitre_technique_id"], "T1595.001")

    def test_slow_scan_below_rate_is_not_detected(self):
        # 1 port every 5s => max 13 targets per 60s window. Documents a known evasion.
        self.assertEqual(run(ScanDetector(), [ev(i * 5, port=p) for i, p in enumerate(range(1, 301))]), [])

    def test_cooldown_suppresses_repeats_but_allows_new_alert_after(self):
        cfg = DetectorConfig(high_threshold=10_000, cooldown_seconds=300)
        d = ScanDetector(cfg)
        first = run(d, [ev(i * 0.01, port=p) for i, p in enumerate(range(1, 500))])
        self.assertEqual(len(first), 1)                       # one MEDIUM, no spam
        later = run(d, [ev(400 + i * 0.01, port=p) for i, p in enumerate(range(1, 30))])
        self.assertEqual(len(later), 1)                       # cooldown expired -> alert again

    def test_suppressed_scan_is_reported_once_with_reason(self):
        notes = []
        d = ScanDetector(DetectorConfig(high_threshold=10_000, cooldown_seconds=300), on_suppressed=notes.append)
        run(d, [ev(i * 0.01, port=p) for i, p in enumerate(range(1, 100))])          # alerts
        self.assertEqual(notes, [])                                                  # nothing suppressed yet
        run(d, [ev(60 + i * 0.01, port=p) for i, p in enumerate(range(1, 100))])     # 2nd scan, 60s later
        self.assertEqual(len(notes), 1)                                              # one note, not ~80
        self.assertEqual(notes[0].src_ip, ATTACKER)
        self.assertEqual(notes[0].severity, "MEDIUM")
        self.assertAlmostEqual(notes[0].seconds_since_alert, 60, delta=1)
        self.assertEqual(notes[0].cooldown_seconds, 300)
        run(d, [ev(120 + i * 0.01, port=p) for i, p in enumerate(range(1, 100))])    # 3rd scan, 60s later
        self.assertEqual(len(notes), 2)

    def test_quick_rescan_with_short_cooldown_is_reported(self):
        notes = []
        d = ScanDetector(DetectorConfig(high_threshold=10_000, cooldown_seconds=30), on_suppressed=notes.append)
        run(d, [ev(i * 0.01, port=p) for i, p in enumerate(range(1, 100))])          # alerts
        run(d, [ev(10 + i * 0.01, port=p) for i, p in enumerate(range(1, 100))])     # re-scan 10s later
        self.assertEqual(len(notes), 1)                                              # demo scan 3 case
        self.assertAlmostEqual(notes[0].seconds_since_alert, 10, delta=1)

    def test_short_cooldown_lets_repeat_scan_alert(self):
        d = ScanDetector(DetectorConfig(high_threshold=10_000, cooldown_seconds=30))
        first = run(d, [ev(i * 0.01, port=p) for i, p in enumerate(range(1, 50))])
        second = run(d, [ev(40 + i * 0.01, port=p) for i, p in enumerate(range(1, 50))])
        self.assertEqual((len(first), len(second)), (1, 1))                          # demo re-scan after 40s works

    def test_allowlisted_scanner_is_ignored(self):
        d = ScanDetector(DetectorConfig(allowlist=("192.168.56.0/28",)))
        self.assertEqual(run(d, [ev(i * 0.01, port=p) for i, p in enumerate(range(1, 200))]), [])

    def test_out_of_order_events_still_detected(self):
        events = [ev(i * 0.1, port=p) for i, p in enumerate(range(1, 41))]
        events.reverse()
        self.assertEqual(len(run(ScanDetector(), events)), 1)

    def test_completed_connections_give_low_confidence(self):
        findings = run(ScanDetector(), [ev(i * 0.1, port=p, state="SF") for i, p in enumerate(range(1, 25))])
        self.assertEqual(findings[0].confidence, "low")


class TestAlert(unittest.TestCase):
    REQUIRED = {"alert_id", "timestamp", "agent_name", "kill_chain_stage", "severity", "confidence",
                "mitre_tactic_id", "mitre_tactic", "mitre_technique_id", "mitre_technique",
                "src_ip", "summary", "evidence", "recommendations"}

    def test_alert_has_schema_and_is_json_serialisable(self):
        f = run(ScanDetector(), [ev(i * 0.01, port=p) for i, p in enumerate(range(1, 21))])[0]
        alert = build_alert(f)
        self.assertEqual(set(alert), self.REQUIRED)
        self.assertEqual(alert["mitre_tactic_id"], "TA0043")
        self.assertEqual(alert["mitre_technique_id"], "T1595")
        json.dumps(alert)


class TestEnrichment(unittest.TestCase):
    def _alert(self):
        f = run(ScanDetector(), [ev(i * 0.01, port=p) for i, p in enumerate(range(1, 21))])[0]
        return build_alert(f)

    def test_parse_handles_markdown_fences(self):
        reply = '```json\n{"analyst_summary": "s", "likely_intent": "i", "recommended_actions": ["a", "b", "c"]}\n```'
        self.assertEqual(enrich.parse_llm_json(reply)["recommended_actions"], ["a", "b", "c"])

    def test_parse_rejects_missing_keys(self):
        with self.assertRaises(ValueError):
            enrich.parse_llm_json('{"analyst_summary": "s"}')

    def test_prompt_has_facts_but_no_braces(self):
        prompt = enrich.build_prompt(self._alert())
        self.assertIn("mitre_technique_id: T1595", prompt)
        self.assertIn("evidence.distinct_targets: 20", prompt)
        self.assertNotIn("{", prompt)

    def test_prompt_excludes_alert_time_id_and_rule_recommendations(self):
        alert = self._alert()
        prompt = enrich.build_prompt(alert)
        self.assertNotIn(alert["timestamp"], prompt)          # model confused this with scan time
        self.assertNotIn(alert["alert_id"], prompt)
        self.assertNotIn(alert["recommendations"][0], prompt) # model copied these verbatim
        self.assertIn("evidence.first_seen", prompt)

    def test_no_api_key_falls_back_and_keeps_detection(self):
        alert = self._alert()
        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": ""}):
            out = enrich.enrich_alert(alert)
        self.assertEqual(out["ai_status"], "unavailable")
        self.assertEqual({k: out[k] for k in alert}, alert)   # detection fields untouched

    def test_llm_error_falls_back(self):
        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "x"}), \
             mock.patch.object(enrich, "_run_crew", side_effect=RuntimeError("429 rate limited")):
            out = enrich.enrich_alert(self._alert())
        self.assertEqual(out["ai_status"], "unavailable")
        self.assertIn("429", out["ai_error"])

    def test_successful_enrichment_adds_ai_fields_only(self):
        alert = self._alert()
        reply = '{"analyst_summary": "s", "likely_intent": "i", "recommended_actions": ["a", "b", "c"]}'
        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "x"}), \
             mock.patch.object(enrich, "_run_crew", return_value=reply):
            out = enrich.enrich_alert(alert)
        self.assertEqual(out["ai_status"], "ok")
        self.assertEqual(out["ai_recommended_actions"], ["a", "b", "c"])
        self.assertEqual(out["severity"], alert["severity"])
        self.assertEqual(out["mitre_technique_id"], alert["mitre_technique_id"])

    def test_slow_llm_is_abandoned_within_time_budget(self):
        import time as _t
        def slow(alert, model):
            _t.sleep(3)
            return "{}"
        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "x"}), \
             mock.patch.object(enrich, "_run_crew", side_effect=slow):
            started = _t.monotonic()
            out = enrich.enrich_alert(self._alert(), time_budget=0.5)
            elapsed = _t.monotonic() - started
        self.assertEqual(out["ai_status"], "unavailable")
        self.assertIn("no reply", out["ai_error"])
        self.assertLess(elapsed, 1.5)                          # detection not held up by a slow API

    def test_backup_model_used_when_first_fails(self):
        reply = '{"analyst_summary": "s", "likely_intent": "i", "recommended_actions": ["a", "b", "c"]}'
        def by_model(alert, model):
            if model == "gemini/busy":
                raise RuntimeError("503 UNAVAILABLE")
            return reply
        env = {"GEMINI_API_KEY": "x", "AAKCD_LLM_MODEL": "gemini/busy, gemini/backup"}
        with mock.patch.dict(os.environ, env), mock.patch.object(enrich, "_run_crew", side_effect=by_model):
            out = enrich.enrich_alert(self._alert())
        self.assertEqual(out["ai_status"], "ok")
        self.assertEqual(out["ai_model"], "gemini/backup")


HEADER = "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\n"


def conn_line(ts, port):
    return f"{ts}\tC{port}\t10.0.0.1\t50000\t10.0.0.2\t{port}\ttcp\tREJ\n"


class TestLogFollower(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "conn.log")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, text, mode="a"):
        with open(self.path, mode, encoding="utf-8", newline="\n") as f:
            f.write(text)

    def test_existing_lines_skipped_by_default_but_header_learned(self):
        self.write(HEADER + conn_line(1, 22) + conn_line(2, 23), "w")
        fol = LogFollower(self.path)
        self.assertEqual(fol.poll(), [])                       # old scan does not re-alert
        self.write(conn_line(3, 80))
        self.assertEqual([e.dst_port for e in fol.poll()], [80])
        fol.close()

    def test_from_start_reads_existing_lines(self):
        self.write(HEADER + conn_line(1, 22) + conn_line(2, 23), "w")
        fol = LogFollower(self.path, from_start=True)
        self.assertEqual([e.dst_port for e in fol.poll()], [22, 23])
        fol.close()

    def test_half_written_line_is_completed_later(self):
        self.write(HEADER, "w")
        fol = LogFollower(self.path)
        full = conn_line(1, 443)
        self.write(full[:10])
        self.assertEqual(fol.poll(), [])
        self.write(full[10:])
        self.assertEqual([e.dst_port for e in fol.poll()], [443])
        fol.close()

    @unittest.skipIf(os.name == "nt", "Windows cannot rename a file that is open")
    def test_survives_zeek_rotation(self):
        self.write(HEADER + conn_line(1, 22), "w")
        fol = LogFollower(self.path)
        fol.poll()
        self.write(conn_line(2, 23))                            # written just before rotation
        os.rename(self.path, self.path + ".archived")          # Zeek rotates
        self.assertEqual([e.dst_port for e in fol.poll()], [23])   # old file drained, no crash
        self.write(HEADER + conn_line(3, 80), "w")             # Zeek creates a new conn.log
        self.assertEqual([e.dst_port for e in fol.poll()], [80])
        self.write(conn_line(4, 81))
        self.assertEqual([e.dst_port for e in fol.poll()], [81])
        fol.close()

    def test_survives_truncation(self):
        self.write(HEADER + conn_line(1, 22) + conn_line(2, 23), "w")
        fol = LogFollower(self.path)
        fol.poll()
        self.write(HEADER + conn_line(3, 80), "w")             # same file, shorter content
        self.assertEqual([e.dst_port for e in fol.poll()], [80])
        fol.close()

    def test_waits_for_missing_file(self):
        fol = LogFollower(self.path)
        self.assertEqual(fol.poll(), [])
        self.write(HEADER + conn_line(1, 22), "w")             # appears after agent started
        self.assertEqual([e.dst_port for e in fol.poll()], [22])
        fol.close()


if __name__ == "__main__":
    unittest.main()
