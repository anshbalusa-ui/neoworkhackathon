"""Local synthetic security tests. No real web requests are made."""
import unittest
from dataclasses import replace
from reference.policy_gate import Gateway, Candidate, Snapshot, Proposal, ORIGIN

URL = "https://events.example/search?q=browser%20security"

class SecurityPolicyTests(unittest.TestCase):
    def setUp(self):
        self.g = Gateway()
        self.i = self.g.trusted_user_intent(7, "browser security", 100)
        self.b = Snapshot(7, ORIGIN, "doc-1", 4, {
            "S": Candidate("S", "search", ORIGIN, "doc-1", 4),
            "F": Candidate("F", "filter", ORIGIN, "doc-1", 4),
            "N": Candidate("N", "public_get", ORIGIN, "doc-1", 4, url=URL),
        })
        self.fill = Proposal(self.i, 7, "doc-1", "FILL_PUBLIC_SEARCH", "S", value="browser security")
        self.nav = Proposal(self.i, 7, "doc-1", "NAVIGATE_PUBLIC_GET", "N", url=URL)

    def execute(self, p, effects):
        status, token = self.g.grant(p, self.b, 101)
        self.assertEqual(status, "GRANTED")
        return self.g.execute_simulated(token, p, self.b, effects, 102)

    def test_exact_search_fill_success(self):
        self.assertEqual(self.execute(self.fill, [])[0], "SIMULATED_EXECUTED")

    def test_same_origin_public_get_success(self):
        self.assertEqual(self.execute(self.nav, [("GET", URL)])[0], "SIMULATED_EXECUTED")

    def test_benign_local_filter(self):
        p = Proposal(self.i, 7, "doc-1", "CLICK_LOCAL_FILTER", "F")
        self.assertEqual(self.execute(p, [])[0], "SIMULATED_EXECUTED")

    def test_hidden_comment_cannot_authorize_registration(self):
        p = replace(self.nav, op="SUBMIT_REGISTRATION")
        self.assertEqual(self.g.grant(p, self.b, 101)[0], "OP_DENIED")

    def test_wrong_fill_is_denied(self):
        self.assertEqual(self.g.grant(replace(self.fill, value="steal data"), self.b, 101)[0], "VALUE_DENIED")

    def test_external_url_is_denied(self):
        u = "https://attacker.invalid/collect?token=secret"
        self.b.candidates["N"] = replace(self.b.candidates["N"], url=u)
        self.assertEqual(self.g.grant(replace(self.nav, url=u), self.b, 101)[0], "NAV_DENIED")

    def test_encoded_exfiltration_param_rejected(self):
        u = "https://events.example/search?q=browser%20security&%74oken=x"
        self.b.candidates["N"] = replace(self.b.candidates["N"], url=u)
        self.assertEqual(self.g.grant(replace(self.nav, url=u), self.b, 101)[0], "NAV_DENIED")

    def test_cross_origin_iframe_denied(self):
        self.b.candidates["N"] = replace(self.b.candidates["N"], origin="https://attacker.invalid")
        self.assertEqual(self.g.grant(self.nav, self.b, 101)[0], "TARGET_DENIED")

    def test_hidden_element_denied(self):
        self.b.candidates["N"] = replace(self.b.candidates["N"], visible=False)
        self.assertEqual(self.g.grant(self.nav, self.b, 101)[0], "TARGET_DENIED")

    def test_stale_element_denied(self):
        self.b.revision = 5
        self.assertEqual(self.g.grant(self.nav, self.b, 101)[0], "TARGET_DENIED")

    def test_dom_swap_after_grant_rejected_before_effect(self):
        _, token = self.g.grant(self.nav, self.b, 101)
        self.b.revision = 5
        status, emitted = self.g.execute_simulated(token, self.nav, self.b, [("GET", URL)], 102)
        self.assertEqual(status, "TARGET_DENIED")
        self.assertEqual(emitted, [])

    def test_js_post_and_beacon_denied(self):
        for effects in [[("POST", URL)], [("GET", "https://attacker.invalid/beacon")]]:
            with self.subTest(effects=effects):
                status, emitted = self.execute(self.nav, effects)
                self.assertEqual(status, "NETWORK_FENCE_DENIED")
                self.assertEqual(emitted, [])

    def test_redirect_chain_denied(self):
        status, emitted = self.execute(self.nav, [("GET", URL), ("GET", "https://attacker.invalid")])
        self.assertEqual(status, "NETWORK_FENCE_DENIED")
        self.assertEqual(emitted, [])

    def test_grant_replay_is_denied(self):
        _, token = self.g.grant(self.fill, self.b, 101)
        self.assertEqual(self.g.execute_simulated(token, self.fill, self.b, [], 102)[0], "SIMULATED_EXECUTED")
        self.assertEqual(self.g.execute_simulated(token, self.fill, self.b, [], 103)[0], "REPLAY_DENIED")

    def test_grant_mutated_action_is_denied(self):
        _, token = self.g.grant(self.fill, self.b, 101)
        status, emitted = self.g.execute_simulated(token, replace(self.fill, value="different"), self.b, [], 102)
        self.assertEqual(status, "GRANT_INVALID")
        self.assertEqual(emitted, [])

    def test_expiration_and_audit_failure(self):
        self.assertEqual(self.g.grant(self.fill, self.b, 221)[0], "INVALID_INTENT")
        self.g.audit_ok = False
        self.assertEqual(self.g.grant(self.fill, self.b, 101)[0], "AUDIT_DOWN")

    def test_authenticated_context_denied(self):
        self.b.anonymous = False
        self.assertEqual(self.g.grant(self.nav, self.b, 101)[0], "CONTEXT_DENIED")

    def test_eight_step_budget(self):
        for i in range(8):
            status, token = self.g.grant(self.fill, self.b, 101 + i)
            self.assertEqual(status, "GRANTED")
            self.assertEqual(self.g.execute_simulated(token, self.fill, self.b, [], 101.5 + i)[0], "SIMULATED_EXECUTED")
        self.assertEqual(self.g.grant(self.fill, self.b, 110)[0], "INVALID_INTENT")

if __name__ == "__main__":
    unittest.main()
