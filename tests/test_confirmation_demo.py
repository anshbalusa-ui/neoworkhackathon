"""Interactive confirmation-demo evidence must follow gateway policy exactly."""
import unittest

from reference.confirmation_scenario import generate_confirmation


class ConfirmationDemoTests(unittest.TestCase):
    def test_all_scenarios_match_trusted_intent_policy(self):
        report = generate_confirmation()
        by_id = {case["id"]: case for case in report["cases"]}
        self.assertEqual(len(by_id), 4)
        self.assertEqual(by_id["no-approval"]["decision"], "REQUIRE_CONFIRMATION")
        self.assertEqual(by_id["trusted-approval"]["decision"], "SIMULATED_EXECUTED")
        self.assertEqual(by_id["target-changed"]["decision"], "ADAPTER_DENIED")
        self.assertEqual(by_id["page-injected"]["decision"], "OP_DENIED")
        self.assertEqual(sum(case["execution_count"] for case in by_id.values()), 1)
        self.assertEqual(by_id["page-injected"]["approval_issued"], False)
        self.assertEqual(by_id["trusted-approval"]["approval_issued"], True)
        self.assertEqual(by_id["target-changed"]["execution_count"], 0)

    def test_report_is_deterministic_in_results(self):
        # Nonces change, but policy trace and public outcomes remain deterministic.
        self.assertEqual(generate_confirmation(), generate_confirmation())


if __name__ == "__main__":
    unittest.main()
