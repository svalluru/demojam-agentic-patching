"""The risk model request: the four features, plus the CVE and host the risk-score pod logs.

    python3 -m unittest discover -s tests
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_roi_v2 import load_console  # noqa: E402


class RiskRequest(unittest.TestCase):
    def setUp(self):
        self.c = load_console()
        self.saved = (self.c.http_json, self.c.RISK_URL, self.c.circuit)
        self.sent = []

        def fake_http_json(url, method='GET', body=None, **kw):
            self.sent.append(body)
            return {'predictions': [70.0 for _ in body['instances']]}

        self.c.http_json = fake_http_json
        self.c.RISK_URL = 'https://risk.example/v1/models/risk-score:predict'
        self.c.circuit = lambda *a, **k: None

    def tearDown(self):
        self.c.http_json, self.c.RISK_URL, self.c.circuit = self.saved

    def agent(self):
        a = self.c.InfoAgent.__new__(self.c.InfoAgent)
        a._trace = lambda *x, **k: None
        return a

    def test_each_instance_carries_cve_and_host_beside_the_features(self):
        hosts = [{'host': 'node1', 'age_days': 4}, {'host': 'node2', 'age_days': 9}]
        scores = self.agent()._risk_live(8.1, hosts, 'CVE-2026-114406')
        self.assertEqual(scores, [70.0, 70.0])
        sent = self.sent[0]['instances']
        self.assertEqual([i['host'] for i in sent], ['node1', 'node2'])
        self.assertEqual({i['cve_id'] for i in sent}, {'CVE-2026-114406'})
        # The model's inputs are unchanged.
        self.assertEqual(sent[0]['cvss'], 8.1)
        self.assertEqual(sent[1]['age_days'], 9)
        self.assertEqual({i['affected_hosts'] for i in sent}, {2})
        self.assertEqual({i['type'] for i in sent}, {'security'})


if __name__ == '__main__':
    unittest.main()
