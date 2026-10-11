"""Loopback integration smoke tests for the interactive handoff's live APIs."""
import json
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen
from http.server import ThreadingHTTPServer

from reference.demo_server import Handler


class DemoAPIIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def fetch_json(self, path):
        with urlopen(self.base + path, timeout=10) as response:
            self.assertEqual(response.status, 200)
            self.assertIn("application/json", response.headers["Content-Type"])
            self.assertEqual(response.headers.get("Cache-Control"), "no-store")
            return json.load(response)

    def test_malicious_proposal_api_denies_and_recovers(self):
        report = self.fetch_json("/api/scenario?id=review-navigation")
        case = report["scenario"]
        self.assertEqual(case["decision"], "OP_DENIED")
        self.assertEqual(case["unauthorized_dispatch_count"], 0)
        self.assertEqual(case["outcome"], "SAFE_COMPLETE")

    def test_assurance_api_exposes_measured_policy_evidence(self):
        report = self.fetch_json("/api/assurance")
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["attempted"], 264)
        self.assertEqual(report["blocked"], 264)
        self.assertEqual(report["safe_recoveries"], 264)
        self.assertEqual(report["effect_attempted"], 72)
        self.assertEqual(report["effect_blocked"], 72)

    def test_confirmation_api_distinguishes_intent_from_approval(self):
        allowed = self.fetch_json("/api/confirmation?id=trusted-approval")
        injected = self.fetch_json("/api/confirmation?id=page-injected")
        self.assertEqual(allowed["case"]["decision"], "SIMULATED_EXECUTED")
        self.assertEqual(allowed["case"]["execution_count"], 1)
        self.assertEqual(injected["case"]["decision"], "OP_DENIED")
        self.assertEqual(injected["case"]["execution_count"], 0)

    def test_unknown_demo_identifier_fails_closed(self):
        with self.assertRaises(HTTPError) as caught:
            urlopen(self.base + "/api/confirmation?id=not-real", timeout=10)
        self.assertEqual(caught.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
