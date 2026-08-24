"""Tests for TrojanSourceScanner."""
from unittest.mock import MagicMock, patch

import pytest

from tblue.scanner.trojan_source import TrojanSourceScanner

URL = "https://example.com"


def _scanner():
    return TrojanSourceScanner(MagicMock())


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.text = body
    r.status_code = status
    r.headers = headers or {}
    r.url = URL
    return r


# ── No vulnerable content ────────────────────────────────────────────────────

class TestCleanPage:
    def test_clean_page_passes(self):
        s = _scanner()
        html = "<html><script>var x = 1; console.log('hello');</script></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_response_passes(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_empty_scripts_pass(self):
        s = _scanner()
        html = "<html><body><script></script></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)


# ── BIDI character detection ─────────────────────────────────────────────────

class TestBIDIChars:
    def test_rlo_override_in_inline_script_fails(self):
        """RIGHT-TO-LEFT OVERRIDE (U+202E) in inline script is FAIL."""
        s = _scanner()
        # U+202E is the classic Trojan Source char
        html = "<html><script>var x = '‮'; // hidden code</script></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL" and "BIDI" in r["type"]]
        assert fails

    def test_lro_override_in_inline_script_fails(self):
        """LEFT-TO-RIGHT OVERRIDE (U+202D) in inline script is FAIL."""
        s = _scanner()
        html = "<html><script>var x = '‭';</script></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL" and "BIDI" in r["type"]]
        assert fails

    def test_rle_in_script_fails(self):
        """RIGHT-TO-LEFT EMBEDDING (U+202B) in script is FAIL."""
        s = _scanner()
        html = "<html><script>// ‫ comment</script></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL" and "BIDI" in r["type"]]
        assert fails

    def test_rli_isolate_in_script_fails(self):
        """RIGHT-TO-LEFT ISOLATE (U+2067) in script is FAIL."""
        s = _scanner()
        html = "<html><script>/* ⁧ */</script></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL" and "BIDI" in r["type"]]
        assert fails

    def test_result_type_mentions_inline(self):
        """FAIL result type mentions 'inline script'."""
        s = _scanner()
        html = "<html><script>'‮'</script></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        bidi_fails = [r for r in results if "BIDI" in r.get("type", "")]
        assert any("inline" in r["type"] for r in bidi_fails)


# ── Invisible character detection ─────────────────────────────────────────────

class TestInvisibleChars:
    def test_zero_width_space_in_script_warns(self):
        """ZERO WIDTH SPACE (U+200B) in script is WARN."""
        s = _scanner()
        html = "<html><script>var x​y = 1;</script></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "invisible" in r["type"].lower()]
        assert warns

    def test_zero_width_joiner_in_script_warns(self):
        """ZERO WIDTH JOINER (U+200D) in script is WARN."""
        s = _scanner()
        html = "<html><script>var config‍ = {};</script></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "invisible" in r["type"].lower()]
        assert warns

    def test_word_joiner_in_script_warns(self):
        """WORD JOINER (U+2060) in script is WARN."""
        s = _scanner()
        html = "<html><script>var x = 1;⁠</script></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "invisible" in r["type"].lower()]
        assert warns


# ── External JS scanning ──────────────────────────────────────────────────────

class TestExternalJS:
    def test_bidi_in_same_origin_external_js_fails(self):
        """BIDI in same-origin external JS file triggers FAIL."""
        s = _scanner()
        html = '<html><script src="/app.js"></script></html>'
        js_content = "var x = '‮'; // RLO"

        def get_side(url, **kwargs):
            if "/app.js" in url:
                return _resp(js_content)
            return _resp(html)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL" and "BIDI" in r.get("type", "")]
        assert fails

    def test_cross_origin_js_skipped(self):
        """Cross-origin JS files are NOT fetched (could have legitimate i18n BIDI)."""
        s = _scanner()
        html = '<html><script src="https://cdn.external.com/lib.js"></script></html>'

        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        # Should pass since we skip cross-origin
        assert any(r["status"] == "PASS" for r in results)

    def test_unreachable_external_js_skipped(self):
        """Unreachable external JS does not cause a FAIL."""
        s = _scanner()
        html = '<html><script src="/missing.js"></script></html>'

        def get_side(url, **kwargs):
            if "/missing.js" in url:
                return None
            return _resp(html)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        # Should still pass (no BIDI found)
        assert any(r["status"] == "PASS" for r in results)

    def test_external_js_invisible_char_warns(self):
        """Invisible char in same-origin JS is WARN."""
        s = _scanner()
        html = '<html><script src="/utils.js"></script></html>'
        js_content = "var secret​ = 'key';"

        def get_side(url, **kwargs):
            if "/utils.js" in url:
                return _resp(js_content)
            return _resp(html)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "invisible" in r.get("type", "").lower()]
        assert warns


# ── BeautifulSoup exception handling ─────────────────────────────────────────

def test_beautifulsoup_exception_handled():
    """If BeautifulSoup raises, inline scan is skipped silently."""
    s = _scanner()
    html = "<html><script>'‮'</script></html>"

    with patch.object(s.http, "get", return_value=_resp(html)):
        with patch("tblue.scanner.trojan_source.BeautifulSoup", side_effect=Exception("parse error")):
            results = s.scan(URL)
    # Should not raise; PASS because inline scan was skipped
    assert results


# ── Result structure ──────────────────────────────────────────────────────────

def test_result_keys():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html></html>")):
        results = s.scan(URL)
    assert results
    for r in results:
        assert "url" in r
        assert "type" in r
        assert "status" in r
        assert r["status"] in ("PASS", "WARN", "FAIL")
