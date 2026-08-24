"""Tests for PRSSIScanner."""
from unittest.mock import MagicMock, patch

import pytest

from tblue.scanner.prssi import PRSSIScanner

URL = "https://example.com/app/dashboard"
SIMPLE_URL = "https://example.com"


def _session():
    return MagicMock()


def _scanner():
    return PRSSIScanner(_session())


def _resp(body="", status=200):
    r = MagicMock()
    r.text = body
    r.status_code = status
    r.headers = {}
    r.url = URL
    return r


# ── No relative stylesheets ───────────────────────────────────────────────────

class TestNoRelativeStylesheets:
    def test_absolute_stylesheet_passes(self):
        s = _scanner()
        html = "<html><head><link rel='stylesheet' href='/css/style.css'></head></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_protocol_relative_stylesheet_passes(self):
        s = _scanner()
        html = "<html><head><link rel='stylesheet' href='//cdn.example.com/style.css'></head></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_https_stylesheet_passes(self):
        s = _scanner()
        html = "<html><head><link rel='stylesheet' href='https://cdn.example.com/style.css'></head></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        assert all(r["status"] == "PASS" for r in results)

    def test_none_response_passes(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_stylesheets_at_all_passes(self):
        s = _scanner()
        html = "<html><body><p>Hello world</p></body></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)


# ── Relative stylesheets found ────────────────────────────────────────────────

class TestRelativeStylesheets:
    def test_relative_stylesheet_warns(self):
        """Relative stylesheet without path confusion → WARN."""
        s = _scanner()
        html = "<html><head><link rel='stylesheet' href='style.css'></head></html>"
        error_html = "<html><head><title>Error 404</title></head></html>"

        # Return error for all path-confusion probe URLs
        def get_side(url, **kw):
            if "extra" in url or "double" in url or "segment" in url:
                return _resp(error_html)
            return _resp(html)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert warns

    def test_relative_stylesheet_detail_mentions_fix(self):
        s = _scanner()
        html = "<html><head><link rel='stylesheet' href='theme.css'></head></html>"
        error_html = "<html><title>Error</title></html>"

        def get_side(url, **kw):
            if "extra" in url or "double" in url or "segment" in url:
                return _resp(error_html)
            return _resp(html)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert warns
        assert any("absolute" in r.get("detail", "") for r in warns)

    def test_multiple_relative_stylesheets_listed(self):
        s = _scanner()
        html = """<html><head>
          <link rel='stylesheet' href='style.css'>
          <link rel='stylesheet' href='theme.css'>
        </head></html>"""

        with patch.object(s.http, "get", return_value=_resp(html)):
            found = s._find_relative_stylesheets(html)
        assert "style.css" in found
        assert "theme.css" in found


# ── Path confusion detection ──────────────────────────────────────────────────

class TestPathConfusion:
    def test_same_title_at_extra_segment_triggers_fail(self):
        """Same <title> at /app/dashboard/extra → PRSSI FAIL."""
        s = _scanner()
        html = "<html><head><title>Dashboard</title><link rel='stylesheet' href='style.css'></head></html>"

        def get_side(url, **kw):
            return _resp(html)  # same page at all URLs

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails

    def test_different_title_at_extra_segment_warns_not_fails(self):
        """Different title at extra segment path → WARN only."""
        s = _scanner()
        main_html = "<html><head><title>Dashboard</title><link rel='stylesheet' href='style.css'></head></html>"
        extra_html = "<html><head><title>Not Found</title></head></html>"

        def get_side(url, **kw):
            if "extra" in url or "double" in url:
                return _resp(extra_html)
            return _resp(main_html)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        fails = [r for r in results if r["status"] == "FAIL"]
        assert warns
        assert not fails

    def test_none_at_extra_segment_not_confused(self):
        """None response at extra path → no confusion detected."""
        s = _scanner()
        html = "<html><head><title>App</title><link rel='stylesheet' href='style.css'></head></html>"

        def get_side(url, **kw):
            if "extra" in url or "double" in url:
                return None
            return _resp(html)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        # Should be WARN (relative stylesheet) but not FAIL (no confirmed confusion)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert not fails


# ── Result structure ──────────────────────────────────────────────────────────

class TestResultStructure:
    def test_required_keys_present(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp("<html></html>")):
            results = s.scan(SIMPLE_URL)
        assert results
        for r in results:
            assert "url" in r
            assert "type" in r
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")

    def test_fail_result_mentions_prssi(self):
        s = _scanner()
        html = "<html><head><title>App</title><link rel='stylesheet' href='style.css'></head></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        # May be WARN or FAIL depending on path confusion
        for r in results:
            if r["status"] in ("WARN", "FAIL"):
                assert "PRSSI" in r["type"] or "prssi" in r["type"].lower() or "relative" in r["type"].lower()
