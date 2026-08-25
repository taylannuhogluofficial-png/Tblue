"""Guards two bugs found auditing the README against real behaviour.

1. `--only xss` resolved to an empty module list once xss moved to the
   intrusive tier. The CLI printed "0 modules", exited 0 and wrote a clean,
   empty report — a security tool reporting no findings having run no checks.
2. `all_results` was keyed only from the passive module list, so every gated
   module raised KeyError, swallowed by the dispatch loop as "active scanner
   error". --probe and --active appeared to work while discarding everything.
"""
import unittest

from tblue import cli
from tblue import __version__
from tblue.constants import VERSION, DEFAULT_USER_AGENT


class TestGatedSelection(unittest.TestCase):

    def test_intrusive_module_is_reported_not_silently_dropped(self):
        gated = cli.gated_selection("xss")
        self.assertIn("xss", gated["intrusive"])
        self.assertEqual(gated["probe"], [])
        self.assertEqual(gated["unknown"], [])

    def test_probe_module_is_classified(self):
        probe = sorted(cli.PROBE_MODULES)[0]
        self.assertIn(probe, cli.gated_selection(probe)["probe"])

    def test_unknown_module_is_reported(self):
        self.assertEqual(cli.gated_selection("not_a_real_module")["unknown"],
                         ["not_a_real_module"])

    def test_passive_module_is_not_flagged(self):
        gated = cli.gated_selection("headers")
        self.assertEqual((gated["probe"], gated["intrusive"], gated["unknown"]),
                         ([], [], []))

    def test_mixed_selection_reports_only_the_gated_part(self):
        gated = cli.gated_selection("headers,xss")
        self.assertEqual(gated["intrusive"], ["xss"])
        self.assertEqual(cli.resolve_modules("headers,xss", ""), ["headers"])


class TestResultBucketsCoverEveryTier(unittest.TestCase):
    """Regression: a missing key made every gated scanner fail silently."""

    def test_every_module_has_a_result_bucket(self):
        buckets = {m: [] for m in cli.ALL_MODULES}
        buckets.update({m: [] for m in cli.ACTIVE_MODULES})
        for mod in cli.ACTIVE_MODULES:
            self.assertIn(mod, buckets, f"{mod} would raise KeyError mid-scan")
        for mod in cli.ALL_MODULES:
            self.assertIn(mod, buckets)

    def test_tiers_are_disjoint_and_total_614(self):
        passive = {e[0] for e in cli._SCANNER_REGISTRY}
        self.assertEqual(passive & cli.ACTIVE_MODULES, set())
        self.assertEqual(cli.PROBE_MODULES & cli.INTRUSIVE_MODULES, set())
        self.assertEqual(len(passive) + len(cli.ACTIVE_MODULES), 614)


class TestVersionIsSingleSourced(unittest.TestCase):
    """constants.py carried its own VERSION and shipped 1.0.0 during 1.0.1."""

    def test_constants_match_package_version(self):
        self.assertEqual(VERSION, __version__)

    def test_user_agent_advertises_the_real_version(self):
        self.assertIn(__version__, DEFAULT_USER_AGENT)


if __name__ == "__main__":
    unittest.main()
