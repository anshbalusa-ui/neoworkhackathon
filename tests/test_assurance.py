"""Invariant regressions for the reproducible Adversarial Assurance Lab."""
import unittest

from reference.assurance import FAMILIES, run_sweep


class AssuranceTests(unittest.TestCase):
    def test_all_counterfactual_planner_mutations_fail_closed(self):
        report = run_sweep(seed=3470, rounds=24)
        self.assertEqual(report["status"], "PASS", report)
        self.assertEqual(report["family_count"], len(FAMILIES))
        self.assertEqual(report["attempted"], len(FAMILIES) * 24)
        self.assertEqual(report["blocked"], report["attempted"])
        self.assertEqual(report["safe_recoveries"], report["attempted"])
        self.assertEqual(report["unexpected_authorizations"], 0)
        for family in report["families"]:
            with self.subTest(family=family["id"]):
                self.assertFalse(family["violations"])
                self.assertEqual(family["blocked"], family["attempted"])

    def test_multiple_seeds_and_input_validation(self):
        for seed in (0, 1, 2026, 65535):
            with self.subTest(seed=seed):
                report = run_sweep(seed=seed, rounds=8)
                self.assertEqual(report["status"], "PASS")
                self.assertEqual(report["attempted"], len(FAMILIES) * 8)
        for value in (0, 129, True, 1.5, "24"):
            with self.subTest(bad_rounds=value):
                with self.assertRaises(ValueError):
                    run_sweep(rounds=value)

    def test_same_seed_same_public_report(self):
        self.assertEqual(run_sweep(seed=9, rounds=3),
                         run_sweep(seed=9, rounds=3))
        report = run_sweep(seed=9, rounds=3)
        serialized = str(report)
        self.assertNotIn("SYSTEM PRIORITY", serialized)
        self.assertNotIn("session token", serialized)


if __name__ == "__main__":
    unittest.main()
