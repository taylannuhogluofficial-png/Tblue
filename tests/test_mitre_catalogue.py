"""Guards Tblue's ATT&CK mappings against drift and typos.

Motivation: a public report noted a technique carrying the wrong name.
An audit against the published catalogue found three real errors:

  * T1430 "Location Tracking"        — Mobile ATT&CK, absent from Enterprise
  * T1596.005 "Search Open Technical Databases" — that is the parent T1596's
    name; .005 is "Scan Databases" (CT logs belong under .003)
  * T1598.002 "Spearphishing Service" — .002 is "Spearphishing Attachment"

These tests encode the invariants that would have caught all three without
requiring network access at test time.
"""
import re
import unittest
from pathlib import Path

import tblue.mitre as M

_SRC   = Path(M.__file__).read_text()
_PAIRS = re.findall(r'_T\("(T[0-9.]+)",\s*"([^"]+)",\s*"([^"]+)"\)', _SRC)

# ATT&CK Enterprise tactics as of the version this module targets (v16).
_TACTICS = {
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
}

# IDs that belong to a non-Enterprise matrix and must never appear here.
_NON_ENTERPRISE = {"T1430"}


class TestMitreCatalogue(unittest.TestCase):

    def test_mappings_exist(self):
        self.assertGreater(len(_PAIRS), 100)

    def test_every_id_is_well_formed(self):
        for tid, _, _ in _PAIRS:
            self.assertRegex(tid, r"^T\d{4}(\.\d{3})?$", f"malformed id {tid}")

    def test_no_non_enterprise_techniques(self):
        """T1430 is Mobile-only; mixing matrices makes the tag meaningless."""
        for tid, name, _ in _PAIRS:
            self.assertNotIn(tid, _NON_ENTERPRISE,
                             f"{tid} ({name}) is not an Enterprise technique")

    def test_every_tactic_is_real(self):
        for tid, _, tactic in _PAIRS:
            self.assertIn(tactic, _TACTICS, f"{tid} has unknown tactic {tactic!r}")

    def test_one_canonical_name_per_id(self):
        """The same technique ID must not appear under two different names."""
        names = {}
        for tid, name, _ in _PAIRS:
            names.setdefault(tid, set()).add(name)
        clashes = {t: sorted(n) for t, n in names.items() if len(n) > 1}
        self.assertEqual(clashes, {}, f"conflicting names: {clashes}")

    def test_subtechnique_never_carries_parent_name(self):
        """T1596.005 was labelled with T1596's name — catch that shape."""
        parents = {tid: name for tid, name, _ in _PAIRS if "." not in tid}
        for tid, name, _ in _PAIRS:
            if "." not in tid:
                continue
            parent = tid.split(".")[0]
            if parent in parents:
                self.assertNotEqual(
                    name.strip(), parents[parent].strip(),
                    f"{tid} reuses parent {parent}'s name {name!r}")

    def test_subtechnique_name_is_qualified(self):
        """Sub-technique labels use 'Parent: Sub' so the leaf is explicit."""
        for tid, name, _ in _PAIRS:
            if "." in tid:
                self.assertIn(":", name, f"{tid} name {name!r} is not qualified")

    def test_urls_point_at_the_right_technique(self):
        for tid, _, _ in _PAIRS:
            info = M._T(tid, "x", "Collection")
            self.assertEqual(
                info["url"],
                f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/")

    def test_declared_matrix_and_version(self):
        self.assertEqual(M.ATTACK_MATRIX, "enterprise")
        self.assertTrue(M.ATTACK_VERSION)
