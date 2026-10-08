import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agents.delivery.delivery_agent import DeliveryAgent
from agents.delivery.ollama_analysis import MAX_RESPONSE_BYTES
from shared.json_output import save_agent_output


def rule_fields(alert):
    return {k: v for k, v in alert.to_dict().items()
            if k not in {'timestamp', 'ai_status', 'ai_summary', 'ai_recommended_actions'}
            and k != 'evidence'}


class TestOllamaAnalysis(unittest.TestCase):
    def setUp(self):
        self.patcher = patch('agents.delivery.ollama_analysis.http.client.HTTPConnection')
        self.factory = self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.connection = self.factory.return_value
        self.response = self.connection.getresponse.return_value
        self.response.status = 200
        self.reply()

    def reply(self, suspicious=True, category='phishing'):
        self.response.read.return_value = json.dumps({
            'done': True,
            'response': json.dumps({'suspicious': suspicious,
                                    'reason': 'Requests credentials under a pretext.',
                                    'category': category})
        }).encode()

    def test_default_disabled_and_explicit_override(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(DeliveryAgent().analyse_event({'body': 'Hello'}), [])
        with patch.dict(os.environ, {'DELIVERY_AI_ENABLED': 'true'}):
            self.assertIsNotNone(DeliveryAgent().ai_analysis)
            self.assertIsNone(DeliveryAgent(ai_enabled=False).ai_analysis)
        self.factory.assert_not_called()

    def test_ai_only_finding_and_local_request(self):
        event = {'email_body': 'Please send your credentials to our help desk.',
                 'source_ip': '192.0.2.10', 'secret': 'DO NOT SEND'}
        alert = DeliveryAgent(ai_enabled=True).analyse_event(event)[0]
        self.assertIn('AI-assisted', alert.description)
        self.assertEqual(alert.source_ip, '192.0.2.10')
        self.assertEqual(alert.confidence, 'low')
        self.factory.assert_called_once_with('127.0.0.1', 11434, timeout=30)
        args = self.connection.request.call_args.args
        self.assertEqual(args[:2], ('POST', '/api/generate'))
        payload = json.loads(args[2])
        self.assertEqual(payload['model'], 'llama3.2:3b')
        self.assertFalse(payload['stream'])
        self.assertNotIn('DO NOT SEND', args[2].decode())
        self.connection.close.assert_called_once()

    def test_rule_alerts_preserved_including_early_return(self):
        for event in [{'attachment': 'invoice.pdf.exe', 'body': 'urgent'},
                      {'attachment': 'a.exe', 'body': 'urgent', 'url': 'http://x/login'}]:
            expected = DeliveryAgent(ai_enabled=False).analyse_event(event)
            actual = DeliveryAgent(ai_enabled=True).analyse_event(event)
            self.assertEqual([rule_fields(a) for a in expected],
                             [rule_fields(a) for a in actual[:-1]])
            self.assertEqual(len(actual), len(expected) + 1)

    def test_benign_ai_does_not_remove_rules(self):
        self.reply(suspicious=False)
        event = {'attachment': 'a.exe'}
        self.assertEqual([rule_fields(a) for a in DeliveryAgent(ai_enabled=True).analyse_event(event)],
                         [rule_fields(a) for a in DeliveryAgent(ai_enabled=False).analyse_event(event)])

    def test_failures_fall_back_and_stop_retries(self):
        for failure in [ConnectionRefusedError(), TimeoutError(), OSError()]:
            with self.subTest(failure=failure):
                self.connection.request.side_effect = failure
                self.connection.request.reset_mock()
                agent = DeliveryAgent(ai_enabled=True)
                event = {'attachment': 'a.exe'}
                expected = DeliveryAgent(ai_enabled=False).analyse_event(event)
                for _ in range(2):
                    self.assertEqual([rule_fields(a) for a in agent.analyse_event(event)],
                                     [rule_fields(a) for a in expected])
                self.connection.request.assert_called_once()

    def test_http_errors_and_redirects_are_not_followed(self):
        for status in [301, 307, 404, 500]:
            self.response.status = status
            self.assertEqual(len(DeliveryAgent(ai_enabled=True).analyse_event(
                {'attachment': 'a.exe'})), 1)

    def test_invalid_responses(self):
        invalid = [b'not json', b'\xff', b'[]', b'{}',
                   b'{"done": false}', b'{"done": true, "response": null}',
                   b'x' * (MAX_RESPONSE_BYTES + 1)]
        for finding in [[], {}, {'suspicious': 'true'},
                        {'suspicious': True, 'reason': 'x', 'category': []},
                        {'suspicious': True, 'reason': 'x', 'category': 'unknown'},
                        {'suspicious': True, 'reason': ' ' , 'category': 'link'},
                        {'suspicious': True, 'reason': 'x' * 1001, 'category': 'link'}]:
            invalid.append(json.dumps({'done': True, 'response': json.dumps(finding)}).encode())
        for raw in invalid:
            with self.subTest(raw=raw[:80]):
                self.response.read.return_value = raw
                self.assertEqual(len(DeliveryAgent(ai_enabled=True).analyse_event(
                    {'attachment': 'a.exe'})), 1)

    def test_input_limits_and_aliases(self):
        DeliveryAgent(ai_enabled=True).analyse_event({'text': 'x' * 20000,
                                                     'attachment_name': 'report.pdf'})
        payload = json.loads(self.connection.request.call_args.args[2])
        sample = json.loads(payload['prompt'])
        self.assertEqual(len(sample['body']), 6000)
        self.assertEqual(sample['attachment'], 'report.pdf')

    def test_file_compatibility_and_json_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sample.txt'
            path.write_text('Please send your credentials to our help desk.')
            agent = DeliveryAgent(ai_enabled=True)
            alerts = agent.analyze_file(path)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(agent.analyze({'text': 'hello'}).agent, 'delivery')
            self.assertEqual(len(agent.analyze_event({'text': 'hello'})), 1)
            previous = os.getcwd()
            try:
                os.chdir(directory)
                output = save_agent_output(alerts)
                record = json.loads(output.read_text())[0]
            finally:
                os.chdir(previous)
            self.assertEqual(set(record), set(alerts[0].to_dict()) | {'timestamp'})

    def test_benign_none_category_regression(self):
        self.reply(suspicious=False, category='none')
        agent = DeliveryAgent(ai_enabled=True)
        self.assertEqual(agent.analyse_event({'body': 'Lunch is at noon.'}), [])
        self.assertEqual(agent.ai_analysis.last_status, 'completed')
        self.assertTrue(agent.ai_analysis.available)
        self.assertFalse(agent.ai_analysis.last_finding['suspicious'])
        self.assertIsNone(agent.ai_analysis.last_error)

    def test_structured_schema_requested(self):
        DeliveryAgent(ai_enabled=True).analyse_event({'body': 'hello'})
        payload = json.loads(self.connection.request.call_args.args[2])
        self.assertEqual(payload['format']['properties']['suspicious']['type'], 'boolean')
        self.assertIn('none', payload['format']['properties']['category']['enum'])

    def test_invalid_answer_recovers_next_case_and_resets_error(self):
        self.response.read.return_value = b'not json'
        agent = DeliveryAgent(ai_enabled=True)
        with self.assertLogs('agents.delivery.ollama_analysis', level='WARNING') as logs:
            agent.analyse_event({'body': 'PRIVATE TEST CONTENT'})
        self.assertNotIn('PRIVATE TEST CONTENT', str(logs.output))
        self.assertEqual(agent.ai_analysis.last_status, 'failed')
        self.assertEqual(agent.ai_analysis.last_error, 'malformed_json_or_fields')
        self.assertTrue(agent.ai_analysis.available)
        self.reply(False, 'none')
        agent.analyse_event({'body': 'Hello'})
        self.assertEqual(agent.ai_analysis.last_status, 'completed')
        self.assertIsNone(agent.ai_analysis.last_error)
        self.assertEqual(agent.ai_analysis.invalid_responses, 0)

    def test_repeated_invalid_answers_disable_ai(self):
        self.response.read.return_value = b'not json'
        agent = DeliveryAgent(ai_enabled=True)
        for _ in range(3):
            agent.analyse_event({'body': 'Hello'})
        self.assertFalse(agent.ai_analysis.available)
        agent.analyse_event({'body': 'Hello'})
        self.assertEqual(agent.ai_analysis.last_status, 'skipped_after_failure')
        self.assertEqual(self.connection.request.call_count, 3)

    def test_suspicious_none_and_truncation_are_failures(self):
        self.reply(True, 'none')
        agent = DeliveryAgent(ai_enabled=True)
        self.assertEqual(agent.analyse_event({'body': 'Hello'}), [])
        self.assertEqual(agent.ai_analysis.last_error, 'suspicious_without_category')
        self.reply()
        envelope = json.loads(self.response.read.return_value)
        envelope['done_reason'] = 'length'
        self.response.read.return_value = json.dumps(envelope).encode()
        agent.analyse_event({'body': 'Hello'})
        self.assertEqual(agent.ai_analysis.last_error, 'output_truncated')

    def test_empty_event_does_not_contact_ollama(self):
        self.assertEqual(DeliveryAgent(ai_enabled=True).analyse_event({}), [])
        self.factory.assert_not_called()


if __name__ == '__main__':
    unittest.main()
