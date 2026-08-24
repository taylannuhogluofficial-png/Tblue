"""Tests for STRIDE threat model report generator."""
import unittest
import json
import os
import tempfile
from tblue.report.stride import generate, _classify


class TestStrideReport(unittest.TestCase):

    def _all_results(self, findings):
        return {"test": findings}

    def test_classify_xss_is_spoofing(self):
        cats = _classify("xss")
        self.assertIn("S", cats)

    def test_classify_path_traversal_is_tampering(self):
        cats = _classify("path_traversal")
        self.assertIn("T", cats)

    def test_classify_rate_limit_is_dos(self):
        cats = _classify("rate_limiting")
        self.assertIn("D", cats)

    def test_classify_ssrf_is_elevation(self):
        cats = _classify("ssrf_params")
        self.assertIn("E", cats)

    def test_classify_unknown_defaults_to_info(self):
        cats = _classify("some_unknown_finding_type_xyz")
        self.assertIn("I", cats)

    def test_generate_creates_json_and_md(self):
        findings = [
            {"url": "https://example.com", "type": "xss", "severity": "FAIL",
             "detail": "XSS found in param"},
            {"url": "https://example.com", "type": "rate_limiting", "severity": "WARN",
             "detail": "No rate limiting"},
        ]
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "stride.json")
            generate("https://example.com", self._all_results(findings), out, scan_score=72)
            self.assertTrue(os.path.exists(out))
            md_path = out.replace(".json", ".md")
            self.assertTrue(os.path.exists(md_path))

            with open(out) as f:
                data = json.load(f)
            self.assertEqual(data["target"], "https://example.com")
            self.assertIn("threats", data)
            self.assertIn("Spoofing", data["threats"])

    def test_generate_empty_results_no_error(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "stride.json")
            generate("https://example.com", {}, out)
            self.assertTrue(os.path.exists(out))

    def test_pass_findings_excluded(self):
        findings = [
            {"url": "https://example.com", "type": "xss", "severity": "PASS", "detail": ""},
        ]
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "stride.json")
            generate("https://example.com", self._all_results(findings), out)
            with open(out) as f:
                data = json.load(f)
            spoofing = data["threats"]["Spoofing"]["findings"]
            self.assertEqual(len(spoofing), 0)


if __name__ == "__main__":
    unittest.main()
