"""Tests for Log4ShellPassiveScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.log4shell_passive import Log4ShellPassiveScanner

URL = "https://example.com"


class TestLog4ShellPassive(unittest.TestCase):
    def _make(self):
        s = Log4ShellPassiveScanner.__new__(Log4ShellPassiveScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = headers or {}
        return r

    def _not_found(self):
        return self._resp("Not Found", 404)

    # ── Vulnerable version in header ──────────────────────────────────────────

    def test_vulnerable_log4j_in_header_fails(self):
        def side(url, **kw):
            if url == URL:
                return self._resp("OK", 200, {"X-Powered-By": "log4j-2.14.1"})
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("log4j" in r["type"].lower() or "log4shell" in r["type"].lower() for r in fails))

    def test_safe_log4j_version_warns_only(self):
        def side(url, **kw):
            if url == URL:
                return self._resp("OK", 200, {"X-Powered-By": "log4j-2.17.1"})
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertEqual(len(fails), 0)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(len(warns) > 0)

    # ── JNDI in response body ─────────────────────────────────────────────────

    def test_jndi_pattern_in_body_fails(self):
        body = 'Error: javax.naming.InitialContext not found for lookup ${jndi:ldap://test}'

        def side(url, **kw):
            if url == URL:
                return self._resp(body, 500)
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("jndi" in r["type"].lower() or "log4shell" in r["type"].lower() for r in fails))

    # ── Log4j class in body with affected version ─────────────────────────────

    def test_log4j_class_with_affected_version_fails(self):
        body = (
            "at org.apache.logging.log4j.core.Logger.logMessage(Logger.java:146)\n"
            "log4j-2.16.0 PatternLayout\n"
        )

        def side(url, **kw):
            if url == URL:
                return self._resp(body, 500)
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(len(fails) > 0)

    # ── Log4j config file accessible ──────────────────────────────────────────

    def test_log4j_config_exposed_fails(self):
        config_body = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<Configuration status="WARN">\n'
            '<Appenders><Console name="Console"><PatternLayout/></Console></Appenders>\n'
            '</Configuration>'
        )

        def side(url, **kw):
            if url == URL:
                return self._resp("OK", 200, {})
            if "/log4j2.xml" in url or "/log4j.xml" in url:
                return self._resp(config_body)
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("config" in r["type"].lower() or "log4j" in r["type"].lower() for r in fails))

    # ── Clean page ────────────────────────────────────────────────────────────

    def test_clean_page_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._not_found()
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
