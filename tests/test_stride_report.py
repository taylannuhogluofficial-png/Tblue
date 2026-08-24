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


class TestStrideScanScoreSerialisation(unittest.TestCase):
    """Regression: the CLI passes a ScanScore dataclass, not an int.

    The original tests passed scan_score=72, which json.dump handles fine,
    so a raw dataclass in the payload crashed only in real runs:
    TypeError: Object of type ScanScore is not JSON serializable
    """

    def _score(self):
        from tblue.scoring import score_results
        return score_results({"headers": [
            {"type": "hsts_missing", "status": "FAIL", "url": "https://example.com", "detail": "no HSTS"},
        ]})

    def test_generate_accepts_scanscore_dataclass(self):
        score = self._score()
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "s.json")
            generate("https://example.com",
                     {"headers": [{"type": "xss", "status": "FAIL",
                                   "url": "https://example.com", "detail": "x"}]},
                     out, scan_score=score)
            with open(out) as f:
                model = json.load(f)
        self.assertIsInstance(model["score"], dict)
        self.assertEqual(model["score"]["grade"], score.grade)
        self.assertEqual(model["score"]["score"], score.score)

    def test_markdown_renders_score_not_repr(self):
        score = self._score()
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "s.json")
            generate("https://example.com",
                     {"headers": [{"type": "xss", "status": "FAIL",
                                   "url": "https://example.com", "detail": "x"}]},
                     out, scan_score=score)
            with open(out.replace(".json", ".md")) as f:
                md = f.read()
        self.assertIn(f"{score.score}/100", md)
        self.assertNotIn("ScanScore(", md)

    def test_int_score_still_supported(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "s.json")
            generate("https://example.com", {"headers": []}, out, scan_score=72)
            with open(out) as f:
                self.assertEqual(json.load(f)["score"], 72)
