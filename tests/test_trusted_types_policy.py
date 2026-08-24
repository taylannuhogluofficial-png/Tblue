"""Tests for TrustedTypesPolicyScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.trusted_types_policy import TrustedTypesPolicyScanner

URL = "https://example.com"


class TestTrustedTypesPolicy(unittest.TestCase):
    def _make(self):
        s = TrustedTypesPolicyScanner.__new__(TrustedTypesPolicyScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = headers or {}
        return r

    # ── Missing enforce ────────────────────────────────────────────────────────

    def test_missing_tt_directive_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                headers={"content-security-policy": "default-src 'self'"}
            )
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("trusted-types" in r["type"].lower() or "trusted" in r["type"].lower() for r in warns))

    def test_no_csp_at_all_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={})
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(len(warns) > 0)

    # ── Report-only mode ───────────────────────────────────────────────────────

    def test_tt_in_report_only_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "content-security-policy": "default-src 'self'",
                "content-security-policy-report-only": (
                    "default-src 'self'; require-trusted-types-for 'script'"
                ),
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("report-only" in r["type"].lower() or "report only" in r["type"].lower() for r in warns))

    # ── Enforced ──────────────────────────────────────────────────────────────

    def test_tt_enforced_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "content-security-policy": (
                    "default-src 'self'; require-trusted-types-for 'script'; trusted-types default"
                ),
            })
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── unsafe-eval with TT ────────────────────────────────────────────────────

    def test_unsafe_eval_with_tt_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "content-security-policy": (
                    "default-src 'self'; require-trusted-types-for 'script'; "
                    "script-src 'self' 'unsafe-eval'"
                ),
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("unsafe-eval" in r["type"].lower() or "eval" in r["type"].lower() for r in warns))

    # ── meta CSP TT (FAIL) ─────────────────────────────────────────────────────

    def test_tt_in_meta_csp_fails(self):
        body = (
            '<html><head>'
            "<meta http-equiv='content-security-policy' "
            "content=\"require-trusted-types-for 'script'\">"
            '</head><body>hello</body></html>'
        )
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body, headers={})
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("meta" in r["type"].lower() for r in fails))

    # ── TT API used without enforcement ───────────────────────────────────────

    def test_tt_api_without_enforcement_warns(self):
        body = (
            '<script>'
            'const policy = trustedTypes.createPolicy("default", { createHTML: s => s });'
            '</script>'
        )
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body, headers={
                "content-security-policy": "default-src 'self'"
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("api" in r["type"].lower() or "enforcement" in r["type"].lower() for r in warns))

    # ── Dangerous sinks without TT ─────────────────────────────────────────────

    def test_innerhtml_without_tt_warns(self):
        body = '<script>element.innerHTML = userInput;</script>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body, headers={
                "content-security-policy": "default-src 'self'"
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("sink" in r["type"].lower() or "innerhtml" in r["type"].lower() or "dangerous" in r["type"].lower() for r in warns))

    # ── No response ────────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
