"""Tests for SubdomainEnumPassiveScanner."""
import json
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.subdomain_enum_passive import SubdomainEnumPassiveScanner

URL = "https://example.com"


class TestSubdomainEnumPassive(unittest.TestCase):
    def _make(self):
        s = SubdomainEnumPassiveScanner.__new__(SubdomainEnumPassiveScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.status_code = status
        r.text = body
        return r

    # ── crt.sh results ────────────────────────────────────────────────────────

    def test_high_value_subdomains_detected(self):
        crtsh_data = json.dumps([
            {"name_value": "admin.example.com"},
            {"name_value": "staging.example.com"},
            {"name_value": "jenkins.example.com"},
            {"name_value": "example.com"},
        ])

        def side(url, **kw):
            if "crt.sh" in url:
                return self._resp(crtsh_data)
            return self._resp("", 404)

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("high-value" in r["type"].lower() for r in warns))

    def test_wildcard_cert_warns(self):
        crtsh_data = json.dumps([
            {"name_value": "*.example.com"},
        ])

        def side(url, **kw):
            if "crt.sh" in url:
                return self._resp(crtsh_data)
            return self._resp("", 404)

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("wildcard" in r["type"].lower() for r in warns))

    def test_many_subdomains_warns(self):
        entries = [{"name_value": f"sub{i}.example.com"} for i in range(10)]
        crtsh_data = json.dumps(entries)

        def side(url, **kw):
            if "crt.sh" in url:
                return self._resp(crtsh_data)
            return self._resp("", 404)

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("subdomains" in r["type"].lower() for r in warns))

    # ── HackerTarget results ──────────────────────────────────────────────────

    def test_hackertarget_high_value_detected(self):
        ht_data = "vpn.example.com,1.2.3.4\ngitlab.example.com,1.2.3.5\nwww.example.com,1.2.3.6"

        def side(url, **kw):
            if "crt.sh" in url:
                return self._resp("[]")
            if "hackertarget" in url:
                return self._resp(ht_data)
            return self._resp("", 404)

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("high-value" in r["type"].lower() for r in warns))

    def test_hackertarget_api_limit_ignored(self):
        def side(url, **kw):
            if "crt.sh" in url:
                return self._resp("[]")
            if "hackertarget" in url:
                return self._resp("error check your API count")
            return self._resp("", 404)

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── Clean / no results ────────────────────────────────────────────────────

    def test_no_results_passes(self):
        def side(url, **kw):
            if "crt.sh" in url:
                return self._resp("[]")
            return self._resp("", 404)

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    def test_api_failures_pass(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp("", 503)
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    def test_non_sensitive_subs_counts_only(self):
        entries = [{"name_value": f"www{i}.example.com"} for i in range(10)]
        crtsh_data = json.dumps(entries)

        def side(url, **kw):
            if "crt.sh" in url:
                return self._resp(crtsh_data)
            return self._resp("", 404)

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        # Should warn about total count but no "high-value" warn
        high_value_warns = [r for r in results if "high-value" in r["type"].lower()]
        self.assertEqual(len(high_value_warns), 0)
        count_warns = [r for r in results if "subdomains" in r["type"].lower()]
        self.assertTrue(len(count_warns) > 0)
