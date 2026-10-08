import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from evaluation.run_delivery import load_cases, metrics, evaluate, main, DEFAULT_DATASET


class EvaluationTests(unittest.TestCase):
    def test_dataset_balance(self):
        cases = load_cases(DEFAULT_DATASET)
        self.assertEqual(len(cases), 40)
        self.assertEqual(sum(c['suspicious'] for c in cases), 20)

    def test_known_metrics(self):
        rows = [{'outcome': k, 'elapsed_seconds': 1} for k in ['TP', 'TP', 'FP', 'TN', 'FN']]
        result = metrics(rows)
        self.assertAlmostEqual(result['precision'], 2 / 3)
        self.assertAlmostEqual(result['recall'], 2 / 3)
        self.assertAlmostEqual(result['f1'], 2 / 3)
        self.assertEqual(result['false_positive_rate'], .5)
        self.assertEqual(result['accuracy'], .6)
        self.assertEqual(result['p95_seconds'], 1)
        self.assertIsNone(metrics([])['precision'])

    def test_rules_ignore_ai_environment(self):
        with patch.dict('os.environ', {'DELIVERY_AI_ENABLED': '1'}), patch('http.client.HTTPConnection') as connection:
            report = evaluate(load_cases(DEFAULT_DATASET))
        connection.assert_not_called()
        self.assertEqual(report['runs']['rules']['metrics']['cases'], 40)

    def test_failure_is_not_valid_ai_comparison(self):
        class FailedAgent:
            def __init__(self, ai_enabled):
                self.ai_analysis = SimpleNamespace(available=True) if ai_enabled else None
            def analyse_event(self, event):
                if self.ai_analysis:
                    self.ai_analysis.available = False
                return []
        result = evaluate(load_cases(DEFAULT_DATASET)[:2], True, FailedAgent)
        self.assertFalse(result['comparison']['valid_full_ai_comparison'])
        self.assertEqual(result['runs']['rules_plus_ai']['ai_status_counts'],
                         {'failed': 1, 'skipped_after_failure': 1})

    def test_successful_benign_verdict_counts_as_completed(self):
        class BenignAgent:
            def __init__(self, ai_enabled):
                self.ai_analysis = SimpleNamespace(available=True) if ai_enabled else None
            def analyse_event(self, event):
                return []
        result = evaluate(load_cases(DEFAULT_DATASET)[:2], True, BenignAgent)
        self.assertTrue(result['comparison']['valid_full_ai_comparison'])
        self.assertEqual(result['runs']['rules_plus_ai']['ai_status_counts'], {'completed': 2})

    def test_invalid_labels_and_duplicate_ids(self):
        for mutate in [lambda c: c[0].update(suspicious='false'),
                       lambda c: c[1].update(id=c[0]['id']),
                       lambda c: c[0].update(event={})]:
            cases = load_cases(DEFAULT_DATASET)
            mutate(cases)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'bad.json'
                path.write_text(json.dumps(cases))
                with self.assertRaises(ValueError):
                    load_cases(path)

    def test_cli_writes_reports(self):
        with tempfile.TemporaryDirectory() as directory, patch('builtins.print'):
            self.assertEqual(main(['--output-dir', directory]), 0)
            report = json.loads((Path(directory) / 'results.json').read_text())
            self.assertEqual(len(report['dataset_sha256']), 64)
            self.assertTrue((Path(directory) / 'summary.md').exists())

    def test_cli_failure_exit_code(self):
        with tempfile.TemporaryDirectory() as directory, patch('builtins.print'), patch('http.client.HTTPConnection') as connection:
            connection.return_value.request.side_effect = ConnectionRefusedError()
            self.assertEqual(main(['--with-ai', '--output-dir', directory]), 2)
            report = json.loads((Path(directory) / 'results.json').read_text())
            self.assertEqual(report['runs']['rules_plus_ai']['ai_status_counts']['failed'], 1)


if __name__ == '__main__':
    unittest.main()
