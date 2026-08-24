"""Tests for Proof-of-Concept report generator."""
import unittest
import json
import os
import tempfile
import shlex
from tblue.report.poc import generate, _find_template


class TestPoCReport(unittest.TestCase):

    def _all_results(self, findings):
        return {"test": findings}

    def test_find_template_known_type(self):
        tmpl, desc = _find_template("pci_4_2_1_no_tls")
        self.assertIn("curl", tmpl)
        self.assertTrue(len(desc) > 5)

    def test_find_template_unknown_type_returns_generic(self):
        tmpl, desc = _find_template("totally_unknown_type_xyz")
        self.assertIn("curl", tmpl)

    def test_generate_creates_json_and_md(self):
        findings = [
            {"url": "https://example.com", "type": "pci_4_2_1_no_tls",
             "status": "FAIL", "detail": "Page served over HTTP"},
            {"url": "https://example.com", "type": "cors_wildcard_api",
             "status": "WARN", "detail": "CORS wildcard on API"},
        ]
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "poc.json")
            generate("https://example.com", self._all_results(findings), out, scan_score=55)
            self.assertTrue(os.path.exists(out))
            md_path = out.replace(".json", ".md")
            self.assertTrue(os.path.exists(md_path))

            with open(out) as f:
                data = json.load(f)
            self.assertEqual(data["target"], "https://example.com")
            self.assertGreater(data["poc_count"], 0)
            for poc in data["pocs"]:
                self.assertIn("poc_command", poc)
                self.assertIn("curl", poc["poc_command"])

    def test_generate_deduplicates_finding_types(self):
        findings = [
            {"url": "https://example.com/a", "type": "xss_reflected",
             "status": "FAIL", "detail": "XSS in param a"},
            {"url": "https://example.com/b", "type": "xss_reflected",
             "status": "FAIL", "detail": "XSS in param b"},
        ]
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "poc.json")
            generate("https://example.com", self._all_results(findings), out)
            with open(out) as f:
                data = json.load(f)
            types = [p["finding_type"] for p in data["pocs"]]
            self.assertEqual(len(types), len(set(types)))

    def test_pass_findings_excluded(self):
        findings = [
            {"url": "https://example.com", "type": "ssl_ok",
             "status": "PASS", "detail": "TLS is fine"},
        ]
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "poc.json")
            generate("https://example.com", self._all_results(findings), out)
            with open(out) as f:
                data = json.load(f)
            self.assertEqual(data["poc_count"], 0)

    def test_url_substitution_in_command(self):
        findings = [
            {"url": "https://example.com/api", "type": "cors_origin_reflection",
             "status": "FAIL", "detail": "Origin reflected"},
        ]
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "poc.json")
            generate("https://example.com", self._all_results(findings), out)
            with open(out) as f:
                data = json.load(f)
            if data["pocs"]:
                cmd = data["pocs"][0]["poc_command"]
                self.assertNotIn("{url}", cmd)
                self.assertNotIn("{host}", cmd)


if __name__ == "__main__":
    unittest.main()


class TestPocScanScoreAndQuoting(unittest.TestCase):
    """Regressions: ScanScore serialisation, and shell-safe PoC commands."""

    def _findings(self, url="https://example.com"):
        return {"headers": [{"type": "hsts_missing", "status": "FAIL",
                             "url": url, "detail": "no HSTS"}]}

    def test_generate_accepts_scanscore_dataclass(self):
        from tblue.scoring import score_results
        score = score_results(self._findings())
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "p.json")
            generate("https://example.com", self._findings(), out, scan_score=score)
            with open(out) as f:
                model = json.load(f)
        self.assertIsInstance(model["score"], dict)
        self.assertEqual(model["score"]["grade"], score.grade)

    def test_int_score_still_supported(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "p.json")
            generate("https://example.com", self._findings(), out, scan_score=72)
            with open(out) as f:
                self.assertEqual(json.load(f)["score"], 72)

    def test_shell_metacharacters_in_url_are_quoted(self):
        """A hostile target must not be able to inject shell commands into
        a PoC the user copy-pastes."""
        hostile = "https://evil.test/;touch /tmp/tblue_poc_rce;#"
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "p.json")
            generate(hostile, self._findings(hostile), out)
            with open(out) as f:
                pocs = json.load(f)["pocs"]
        self.assertTrue(pocs)
        for p in pocs:
            cmd = p["poc_command"]
            # Tokenise the way a shell would, treating ; | & as operators.
            # If quoting works the hostile URL stays one word, so the
            # injected `touch` can never surface as a bare command token.
            lexer = shlex.shlex(cmd, posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            self.assertNotIn("touch", list(lexer),
                             f"shell injection survived quoting: {cmd!r}")
