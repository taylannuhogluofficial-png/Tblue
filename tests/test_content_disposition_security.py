"""Tests for ContentDispositionSecurityScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.content_disposition_security import ContentDispositionSecurityScanner

URL         = "https://example.com"
UPLOAD_URL  = "https://example.com/uploads/file.svg"
API_URL     = "https://example.com/api/v1/data"


class TestContentDispositionSecurity(unittest.TestCase):
    def _make(self):
        s = ContentDispositionSecurityScanner.__new__(ContentDispositionSecurityScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = headers or {}
        return r

    # ── Inline dangerous MIME on upload path ──────────────────────────────────

    def test_svg_inline_on_upload_path_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                "<svg><script>alert(1)</script></svg>",
                headers={"content-type": "image/svg+xml"}
            )
            results = s.scan(UPLOAD_URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("inline" in r["type"].lower() or "dangerous" in r["type"].lower() or "svg" in r["type"].lower() for r in fails))

    def test_html_inline_on_upload_path_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                "<html><script>evil()</script></html>",
                headers={"content-type": "text/html"}
            )
            results = s.scan(UPLOAD_URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(len(fails) > 0)

    def test_js_on_upload_path_fails(self):
        upload_js = "https://example.com/media/userscript.js"
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                "alert('xss')",
                headers={"content-type": "text/javascript"}
            )
            results = s.scan(upload_js)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(len(fails) > 0)

    # ── Attachment correctly set ──────────────────────────────────────────────

    def test_attachment_on_svg_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                "<svg></svg>",
                headers={
                    "content-type": "image/svg+xml",
                    "content-disposition": "attachment; filename=\"file.svg\"",
                }
            )
            results = s.scan(UPLOAD_URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── Path traversal in filename ────────────────────────────────────────────

    def test_path_traversal_in_filename_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                "content",
                headers={"content-disposition": 'attachment; filename="../../etc/passwd"'}
            )
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("traversal" in r["type"].lower() or "path" in r["type"].lower() for r in fails))

    def test_windows_path_traversal_in_filename_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                "content",
                headers={"content-disposition": 'attachment; filename="..\\..\\windows\\system32\\hosts"'}
            )
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(len(fails) > 0)

    # ── RTL override in filename ──────────────────────────────────────────────

    def test_rtl_override_in_filename_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                "content",
                headers={"content-disposition": "attachment; filename*=UTF-8''%e2%80%aetxt.exe"}
            )
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("rtl" in r["type"].lower() or "unicode" in r["type"].lower() or "override" in r["type"].lower() for r in warns))

    # ── Dangerous file extension ──────────────────────────────────────────────

    def test_exe_attachment_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                "MZ...",
                headers={
                    "content-disposition": "attachment; filename=\"malware.exe\"",
                    "content-type": "application/octet-stream",
                }
            )
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("exe" in r["type"].lower() or "dangerous" in r["type"].lower() or "extension" in r["type"].lower() for r in warns))

    def test_ps1_attachment_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                "Get-Process",
                headers={
                    "content-disposition": "attachment; filename=\"setup.ps1\"",
                    "content-type": "application/octet-stream",
                }
            )
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(len(warns) > 0)

    # ── Normal page — no CD header ────────────────────────────────────────────

    def test_no_content_disposition_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                "<html>hello</html>",
                headers={"content-type": "text/html"}
            )
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── No response ────────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
