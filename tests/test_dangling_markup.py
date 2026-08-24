"""Tests for DanglingMarkupScanner."""
from unittest.mock import MagicMock, patch

import pytest

from tblue.scanner.dangling_markup import (
    DanglingMarkupScanner,
    _PROBE_VALUE,
)

URL = "https://example.com"
URL_WITH_PARAMS = "https://example.com/page?q=hello&lang=en"


def _scanner():
    return DanglingMarkupScanner(MagicMock())


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.text = body
    r.status_code = status
    r.headers = headers or {}
    r.url = URL
    return r


# ── Clean page ───────────────────────────────────────────────────────────────

class TestCleanPage:
    def test_clean_page_no_params_passes(self):
        s = _scanner()
        html = "<html><body><p>Hello</p></body></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_response_passes(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)


# ── Open resource-fetching attribute contexts ────────────────────────────────

class TestOpenContexts:
    def test_open_link_href_warns(self):
        """<link href='...unclosed at end of line triggers WARN."""
        s = _scanner()
        # Attribute value ends at end of line with no closing quote — multiline required
        html = "<html>\n<head>\n<link rel='stylesheet' href='//cdn.example.com/css?v=\n</head>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "link href" in r["type"]]
        assert warns

    def test_open_base_href_fails(self):
        """<base href='...unclosed at end of line triggers FAIL (high severity)."""
        s = _scanner()
        html = "<html>\n<head>\n<base href='https://cdn.example.com/static?path=\n</head>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL" and "base href" in r["type"]]
        assert fails

    def test_open_script_src_fails(self):
        """<script src='...unclosed at end of line triggers FAIL."""
        s = _scanner()
        html = "<html>\n<head>\n<script src='https://cdn.example.com/js?name=\n</head>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL" and "script src" in r["type"]]
        assert fails

    def test_properly_closed_tags_pass(self):
        """Properly closed tags don't trigger dangling markup."""
        s = _scanner()
        html = """<html>
          <head>
            <link rel="stylesheet" href="/style.css">
            <base href="https://example.com">
            <script src="/app.js"></script>
          </head>
        </html>"""
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        open_context = [
            r for r in results
            if r["status"] in ("WARN", "FAIL")
            and "open" in r.get("type", "").lower()
        ]
        assert not open_context


# ── Parameter reflection probing ─────────────────────────────────────────────

class TestParamProbing:
    def test_probe_reflected_in_attribute_warns(self):
        """Probe appearing inside an href attribute context triggers WARN."""
        s = _scanner()

        def get_side(url, **kwargs):
            if _PROBE_VALUE in url:
                # Probe is reflected inside an href attribute
                return _resp(f'<html><a href="/x?q={_PROBE_VALUE}">link</a></html>')
            return _resp("<html><body></body></html>")

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL_WITH_PARAMS)
        warns = [r for r in results if r["status"] == "WARN" and "reflected" in r["type"].lower()]
        assert warns

    def test_probe_angle_bracket_reflected_fails(self):
        """Probe with unencoded < in response triggers FAIL."""
        s = _scanner()

        def get_side(url, **kwargs):
            # urlencode encodes < as %3C — detect the angle probe that way
            if _PROBE_VALUE in url and "%3C" in url:
                return _resp(f"<html>{_PROBE_VALUE}<x injected</html>")
            elif _PROBE_VALUE in url:
                # Plain probe: no attribute context reflection
                return _resp("<html><body>nothing here</body></html>")
            return _resp("<html><body></body></html>")

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL_WITH_PARAMS)
        fails = [r for r in results if r["status"] == "FAIL" and "angle bracket" in r["type"].lower()]
        assert fails

    def test_probe_not_reflected_passes(self):
        """Probe not reflected in response = no dangling markup finding."""
        s = _scanner()

        with patch.object(s.http, "get", return_value=_resp("<html><body>safe</body></html>")):
            results = s.scan(URL_WITH_PARAMS)
        # No dangling markup findings
        dm_findings = [
            r for r in results
            if r["status"] in ("WARN", "FAIL")
            and "dangling" in r.get("type", "").lower()
        ]
        assert not dm_findings

    def test_unreachable_probe_skipped(self):
        """Unreachable probe response is skipped gracefully."""
        s = _scanner()

        call_count = [0]

        def get_side(url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return _resp("<html></html>")
            return None

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL_WITH_PARAMS)
        # Should not raise; may pass if no reflection found
        assert results


# ── No query params — no param probing ───────────────────────────────────────

def test_no_query_params_skips_probing():
    """URL without query string skips parameter probing."""
    s = _scanner()
    html = "<html><body><p>No params</p></body></html>"
    with patch.object(s.http, "get", return_value=_resp(html)) as mock_get:
        results = s.scan(URL)
    # Only one GET call (for the page itself), not multiple probes
    assert mock_get.call_count == 1
    assert any(r["status"] == "PASS" for r in results)


# ── Result structure ──────────────────────────────────────────────────────────

def test_result_keys():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html></html>")):
        results = s.scan(URL)
    for r in results:
        assert "url" in r
        assert "type" in r
        assert "status" in r
        assert r["status"] in ("PASS", "WARN", "FAIL")
