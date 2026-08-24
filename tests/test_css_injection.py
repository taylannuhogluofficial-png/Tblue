"""Tests for CSSInjectionScanner."""
from unittest.mock import MagicMock, patch

import pytest

from tblue.scanner.css_injection import CSSInjectionScanner

URL = "https://example.com"
URL_WITH_PARAM = "https://example.com/page?theme=blue"


def _session():
    return MagicMock()


def _scanner():
    return CSSInjectionScanner(_session())


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.text = body
    r.status_code = status
    r.headers = headers or {}
    r.url = URL
    return r


# ── No injection surface ──────────────────────────────────────────────────────

class TestNoInjectionSurface:
    def test_plain_page_no_params_passes(self):
        s = _scanner()
        html = "<html><head><link rel='stylesheet' href='/style.css'></head></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_none_response_returns_pass(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_absolute_stylesheet_not_flagged(self):
        """Absolute stylesheet href /style.css should not trigger PRSSI-style warning."""
        s = _scanner()
        html = "<html><head><link rel='stylesheet' href='https://cdn.example.com/style.css'></head></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        # Should have only PASS
        assert all(r["status"] == "PASS" for r in results)


# ── Style attribute injection ─────────────────────────────────────────────────

class TestStyleAttributeInjection:
    def test_expression_in_style_attr_fails(self):
        s = _scanner()
        html = "<html><body><div style=\"width: expression(alert(1))\"></div></body></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails

    def test_javascript_in_style_attr_fails(self):
        s = _scanner()
        html = "<div style=\"background: javascript:alert(1)\"></div>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails

    def test_url_in_style_attr_fails(self):
        s = _scanner()
        html = "<div style=\"background: url(https://evil.com/track.gif)\"></div>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails

    def test_safe_style_attr_not_flagged(self):
        s = _scanner()
        html = "<div style=\"color: red; margin: 0;\"></div>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert not fails


# ── Stylesheet href with URL params ──────────────────────────────────────────

class TestStylesheetHref:
    def test_stylesheet_href_with_shared_param_warns(self):
        s = _scanner()
        html = """<html><head>
        <link rel="stylesheet" href="/style.css?theme=blue">
        </head></html>"""
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL_WITH_PARAM)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert warns

    def test_stylesheet_href_with_different_params_not_flagged(self):
        s = _scanner()
        html = """<html><head>
        <link rel="stylesheet" href="/style.css?v=123">
        </head></html>"""
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL_WITH_PARAM)
        # v=123 doesn't overlap with theme param
        warns = [r for r in results if r["status"] == "WARN"
                 and "stylesheet href" in r["type"]]
        assert not warns


# ── URL parameter reflection into CSS ────────────────────────────────────────

class TestURLParamReflection:
    def test_param_reflected_into_style_block_fails(self):
        s = _scanner()
        probe = "CSSINJPROBE7x9z"
        html_with_reflection = f"<html><head><style>body {{ color: {probe}; }}</style></head></html>"

        def get_side(url, **kw):
            if probe in url:
                return _resp(html_with_reflection)
            return _resp("<html></html>")

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL_WITH_PARAM)
        fails = [r for r in results if r["status"] == "FAIL" and "reflects" in r["type"]]
        assert fails

    def test_param_reflected_outside_css_not_flagged(self):
        s = _scanner()
        probe = "CSSINJPROBE7x9z"
        # Reflection is in body text, not in <style>
        html_with_reflection = f"<html><body><p>Your theme: {probe}</p></body></html>"

        def get_side(url, **kw):
            if probe in url:
                return _resp(html_with_reflection)
            return _resp("<html></html>")

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL_WITH_PARAM)
        css_fails = [r for r in results if r["status"] == "FAIL" and "reflects" in r["type"]]
        assert not css_fails


# ── Result structure ──────────────────────────────────────────────────────────

class TestResultStructure:
    def test_result_keys(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp("<html></html>")):
            results = s.scan(URL)
        assert results
        for r in results:
            assert "url" in r
            assert "type" in r
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")
