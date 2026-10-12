import json
from datetime import datetime
from pathlib import Path, PureWindowsPath
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from agents.delivery.delivery_agent import DeliveryAgent
from agents.delivery.demo import demo_event
from agents.delivery.jsonl_output import append_alerts
from shared.alert_schema import Alert
from evaluation.run_delivery import evaluate, load_cases, DEFAULT_DATASET

ROOT = Path(__file__).resolve().parents[1]


class DeliveryIntegrationTests(unittest.TestCase):
    def test_all_detection_outputs_follow_team_contract(self):
        for case in load_cases(DEFAULT_DATASET):
            for alert in DeliveryAgent(ai_enabled=False).analyse_event(case['event']):
                data = alert.to_dict()
                self.assertEqual(data['agent'], 'delivery')
                self.assertEqual(data['stage'], 'delivery')
                self.assertIn(data['severity'], {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'})
                self.assertIn(data['confidence'], {'low', 'medium', 'high'})
                self.assertIsInstance(data['evidence'], dict)
                self.assertTrue(data['recommended_actions'])
                self.assertTrue(all(isinstance(x, str) for x in data['recommended_actions']))
                self.assertNotIn('activity', data)
                self.assertNotIn('kill_chain_stage', data)
                self.assertIsNotNone(datetime.fromisoformat(data['timestamp']).tzinfo)
                self.assertEqual(Alert(**data).to_dict(), data)

    def test_unknown_ip_omitted_and_file_context_retained(self):
        for value in [None, 'Unknown', 'Local File Test', 'invalid', 123]:
            alert = DeliveryAgent(False).analyse_event({'attachment':'a.exe','source_ip':value})[0]
            self.assertNotIn('source_ip', alert.to_dict())
        alert = DeliveryAgent(False).analyse_file(ROOT / 'test_samples/invoice.exe')[0]
        self.assertNotIn('source_ip', alert.to_dict())
        self.assertTrue(alert.evidence['file_path'].endswith('invoice.exe'))

    def test_exact_file_path_contract_on_rules_and_ai(self):
        events = [
            {'attachment': 'invoice.exe', 'file_path': '/tmp/invoice.exe'},
            {'attachment': 'invoice.exe', 'source_file': '/tmp/invoice.exe'},
            {'attachment': 'invoice.exe', 'file_path': r'C:\Users\Student\invoice.exe'},
        ]
        with patch('http.client.HTTPConnection') as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = json.dumps({'done':True, 'response':json.dumps({
                'suspicious':True, 'reason':'Suspicious attachment for review.',
                'category':'attachment'})}).encode()
            for event in events:
                alerts = DeliveryAgent(True).analyse_event(event)
                self.assertEqual(len(alerts), 2)
                for alert in alerts:
                    supplied = event.get('file_path') or event['source_file']
                    expected = str(PureWindowsPath(supplied)) if PureWindowsPath(supplied).is_absolute() else str(Path(supplied).resolve())
                    self.assertEqual(alert.evidence['file_path'], expected)
                    self.assertNotIn('source_file', alert.evidence)
                    self.assertTrue(alert.timestamp.endswith('Z'))
            alert = DeliveryAgent(False).analyse_event({'attachment':'invoice.exe'})[0]
            self.assertNotIn('file_path', alert.evidence)

    def test_demo_preserves_correlation_metadata(self):
        event = demo_event('192.0.2.10','team-demo-1')
        alerts = DeliveryAgent(False).analyse_event(event)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].source_ip, '192.0.2.10')
        self.assertEqual(alerts[0].severity, 'CRITICAL')
        self.assertTrue(Path(alerts[0].evidence['file_path']).is_absolute())
        self.assertEqual(Path(alerts[0].evidence['file_path']).read_bytes(), b'')
        self.assertTrue(alerts[0].evidence['simulation'])
        self.assertEqual(alerts[0].evidence['scenario_id'], 'team-demo-1')
        with self.assertRaises(ValueError):
            demo_event('not-an-ip','team-demo-1')

    def test_jsonl_appends_and_escapes_newlines(self):
        alert = DeliveryAgent(False).analyse_event({'attachment':'a.exe'})[0]
        alert.description = 'first line\nsecond line'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'nested/alerts.jsonl'
            append_alerts([alert], path)
            append_alerts([alert], path)
            lines = path.read_text().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[0])['description'], alert.description)
            self.assertEqual(json.loads(lines[1]), alert.to_dict())

    def test_ai_enrichment_does_not_hide_rule_alerts(self):
        with patch('http.client.HTTPConnection') as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = json.dumps({'done':True, 'response':json.dumps({
                'suspicious':False,'reason':'Insufficient evidence from filename alone.', 'category':'none'})}).encode()
            alerts = DeliveryAgent(True).analyse_event({'attachment':'a.exe'})
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0].ai_status, 'ok')
            self.assertIn('Insufficient', alerts[0].ai_summary)
            self.assertEqual(alerts[0].severity, 'HIGH')
            connection.return_value.request.side_effect = ConnectionRefusedError()
            alert = DeliveryAgent(True).analyse_event({'attachment':'a.exe'})[0]
            self.assertEqual(alert.ai_status, 'unavailable')
            self.assertNotIn('ai_summary', alert.to_dict())
            self.assertEqual(alert.evidence['ai_error'], 'connection_error')

    def test_baseline_predictions_unchanged(self):
        m = evaluate(load_cases(DEFAULT_DATASET))['runs']['rules']['metrics']
        self.assertEqual([m[k] for k in ('true_positives','false_positives','true_negatives','false_negatives')], [12,8,12,8])

    def test_wazuh_fixture_structure_and_rule_routing(self):
        # Static routing check only; manager-side wazuh-logtest is still required.
        group = ET.parse(ROOT/'wazuh/delivery/local_rules.xml').getroot()
        rules = group.findall('rule')
        ids = [r.attrib['id'] for r in rules]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(100000 <= int(i) <= 120000 for i in ids))
        parent = rules[0]
        fields = {f.attrib['name']:f.text for f in parent.findall('field')}
        self.assertEqual(fields, {'agent':'^delivery$', 'stage':'^delivery$'})
        samples = [json.loads(line) for line in (ROOT/'wazuh/delivery/sample_alerts.jsonl').read_text().splitlines()]
        self.assertEqual([s['severity'] for s in samples], ['LOW','MEDIUM','HIGH','CRITICAL'])
        for row, rule in zip(samples,rules[1:]):
            self.assertEqual(Alert(**row).to_dict(), row)
            self.assertEqual(rule.findtext('if_sid'), ids[0])
            self.assertEqual(rule.find('field').text, '^'+row['severity']+'$')
        snippet = ET.parse(ROOT/'wazuh/delivery/ossec_localfile_snippet.xml').getroot()
        self.assertEqual(snippet.findtext('log_format'), 'json')


if __name__ == '__main__':
    unittest.main()
