"""--fail-on gates on findings, not on the aggregate score.

A score threshold alone lets a genuinely broken site through: a page missing
Content-Security-Policy entirely still scores in the 80s once its other checks
pass, so `--fail-below 80` returns 0. --fail-on gates on severity instead.
"""

import unittest

from tblue.cli import severities_at_or_above
from tblue.scoring import ScanScore, SEVERITY_ORDER


def _score(**breakdown) -> ScanScore:
    full = {sev: 0 for sev in SEVERITY_ORDER}
    full.update(breakdown)
    return ScanScore(score=84, grade="A", breakdown=full, deductions={},
                     top_issues=[], total_deducted=16)


class TestSeverityGate(unittest.TestCase):

    def test_floor_includes_everything_worse(self):
        got = severities_at_or_above(_score(critical=1, high=2, medium=9), "high")
        self.assertEqual(got, {"critical": 1, "high": 2})

    def test_zero_counts_are_dropped(self):
        got = severities_at_or_above(_score(critical=0, high=3), "high")
        self.assertEqual(got, {"high": 3})

    def test_clean_above_the_floor_returns_empty(self):
        got = severities_at_or_above(_score(medium=4, low=7), "high")
        self.assertEqual(got, {})
        self.assertFalse(got, "empty result must be falsy so the gate passes")

    def test_critical_floor_ignores_high(self):
        self.assertEqual(severities_at_or_above(_score(high=5), "critical"), {})

    def test_low_floor_catches_everything(self):
        got = severities_at_or_above(_score(critical=1, high=1, medium=1, low=1), "low")
        self.assertEqual(sum(got.values()), 4)

    def test_info_is_never_gated(self):
        # info sits below low and must not fail a build at any floor.
        got = severities_at_or_above(_score(info=12), "low")
        self.assertEqual(got, {})

    def test_worst_first_ordering(self):
        got = severities_at_or_above(_score(critical=1, high=1, medium=1), "medium")
        self.assertEqual(list(got), ["critical", "high", "medium"])

    def test_the_gap_this_flag_exists_to_close(self):
        # 84/100 passes --fail-below 80, but a high-severity finding is present.
        s = _score(high=1)
        self.assertGreaterEqual(s.score, 80)
        self.assertTrue(severities_at_or_above(s, "high"))


if __name__ == "__main__":
    unittest.main()
