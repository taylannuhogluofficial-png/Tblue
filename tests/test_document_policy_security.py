"""Tests for DocumentPolicySecurityScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.document_policy_security import DocumentPolicySecurityScanner

URL = "https://example.com"


class TestDocumentPolicySecurity(unittest.TestCase):
    def _make(self):
        s = DocumentPolicySecurityScanner.__new__(DocumentPolicySecurityScanner)
        s.http = MagicMock()
        return s

    def _resp(self, status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = ""
        r.headers = headers or {}
        return r

    # ── No header ─────────────────────────────────────────────────────────────

    def test_no_document_policy_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={})
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── Report-only only ─────────────────────────────────────────────────────

    def test_report_only_without_enforce_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "document-policy-report-only": "no-document-write"
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("report-only" in r["type"].lower() for r in warns))

    # ── Dangerous feature: js-profiling ──────────────────────────────────────

    def test_js_profiling_enabled_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "document-policy": "no-document-write, js-profiling=?1"
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("js-profiling" in r["type"].lower() or "profiling" in r["type"].lower() for r in warns))

    # ── Missing Require-Document-Policy ──────────────────────────────────────

    def test_missing_require_doc_policy_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "document-policy": "no-document-write"
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("require-document-policy" in r["type"].lower() or "require" in r["type"].lower() for r in warns))

    # ── Well-configured Document-Policy ──────────────────────────────────────

    def test_good_document_policy_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "document-policy": "no-document-write, sync-xhr=?0",
                "require-document-policy": "no-document-write",
            })
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── Presence + Require-Document-Policy present ────────────────────────────

    def test_with_require_doc_policy_no_warn_about_missing(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "document-policy": "no-document-write",
                "require-document-policy": "no-document-write",
            })
            results = s.scan(URL)
        type_strings = [r["type"] for r in results]
        self.assertFalse(any("require-document-policy" in t.lower() and "missing" in t.lower() for t in type_strings))

    # ── No response ────────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
