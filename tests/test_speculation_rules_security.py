"""Tests for SpeculationRulesSecurityScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.speculation_rules_security import SpeculationRulesSecurityScanner

URL = "https://example.com"

_SAFE_RULES = '{"prefetch":[{"urls":["/blog/1","/blog/2"]}]}'
_WILDCARD_RULES = '{"prefetch":[{"where":{"href_matches":"*"}}]}'
_SENSITIVE_RULES = '{"prefetch":[{"urls":["/checkout","/payment","/admin/dashboard"]}]}'
_EAGER_PRERENDER = '{"prerender":[{"urls":["/articles/1"],"eagerness":"eager"}]}'
_IMMEDIATE_PRERENDER = '{"prerender":[{"urls":["/"],"eagerness":"immediate"}]}'


def _spec_body(rules_json):
    return (
        '<html><head>'
        f'<script type="speculationrules">{rules_json}</script>'
        '</head><body>hello</body></html>'
    )


class TestSpeculationRulesSecurity(unittest.TestCase):
    def _make(self):
        s = SpeculationRulesSecurityScanner.__new__(SpeculationRulesSecurityScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = headers or {}
        return r

    # ── HTTP header exposure ───────────────────────────────────────────────────

    def test_speculation_rules_header_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "speculation-rules": '"/speculation-rules.json"'
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("header" in r["type"].lower() or "http header" in r["type"].lower() for r in warns))

    # ── Safe inline rules ─────────────────────────────────────────────────────

    def test_safe_inline_rules_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=_spec_body(_SAFE_RULES))
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── Wildcard href_matches ─────────────────────────────────────────────────

    def test_wildcard_href_matches_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=_spec_body(_WILDCARD_RULES))
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("wildcard" in r["type"].lower() for r in warns))

    # ── Sensitive paths ───────────────────────────────────────────────────────

    def test_sensitive_paths_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=_spec_body(_SENSITIVE_RULES))
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("sensitive" in r["type"].lower() for r in fails))

    def test_logout_in_rules_fails(self):
        rules = '{"prefetch":[{"urls":["/logout","/home"]}]}'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=_spec_body(rules))
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("sensitive" in r["type"].lower() for r in fails))

    # ── Eagerness ─────────────────────────────────────────────────────────────

    def test_eager_prerender_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=_spec_body(_EAGER_PRERENDER))
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("eager" in r["type"].lower() or "eager" in r.get("detail", "").lower() for r in warns))

    def test_immediate_prerender_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=_spec_body(_IMMEDIATE_PRERENDER))
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("immediate" in r["type"].lower() or "immediate" in r.get("detail", "").lower() for r in warns))

    # ── No-Vary-Search combo ───────────────────────────────────────────────────

    def test_speculation_rules_with_no_vary_search_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "speculation-rules": '"/rules.json"',
                "no-vary-search": "params=(q)",
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("no-vary-search" in r["type"].lower() or "cache" in r["type"].lower() for r in warns))

    # ── No speculation rules ──────────────────────────────────────────────────

    def test_no_speculation_rules_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body="<html><body>hello</body></html>")
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
