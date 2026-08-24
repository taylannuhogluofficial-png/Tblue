"""Tests for advanced SRI coverage and hash strength analysis."""

from unittest.mock import MagicMock
from tblue.scanner.sri_advanced import SRIAdvancedScanner


def _scanner(html=""):
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = html
        resp.headers = {}
        return resp

    session.request.side_effect = fake_request
    return SRIAdvancedScanner(session)


# ── No external resources ─────────────────────────────────────────────────────

def test_no_external_resources_no_findings():
    scanner = _scanner('<script src="/local.js"></script>')
    results = scanner.scan("https://example.com")
    assert results == []


# ── 100% coverage ─────────────────────────────────────────────────────────────

def test_full_sri_coverage_passes():
    html = (
        '<script src="https://cdn.example.net/lib.js" '
        'integrity="sha256-abc123" crossorigin="anonymous"></script>'
    )
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("100%" in r["type"] and r["status"] == "PASS" for r in results)


def test_stylesheet_with_sri_passes():
    html = (
        '<link rel="stylesheet" href="https://cdn.example.net/style.css" '
        'integrity="sha384-xyz789" crossorigin="anonymous">'
    )
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("100%" in r["type"] and r["status"] == "PASS" for r in results)


# ── Partial coverage ──────────────────────────────────────────────────────────

def test_partial_sri_coverage_warns():
    html = (
        '<script src="https://cdn.a.net/a.js" integrity="sha256-abc" crossorigin="anonymous"></script>'
        '<script src="https://cdn.b.net/b.js"></script>'
    )
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any(("partial" in r["type"].lower() or "low coverage" in r["type"].lower())
               and r["status"] in ("WARN", "FAIL") for r in results)


def test_zero_sri_coverage_fails():
    html = (
        '<script src="https://cdn.a.net/a.js"></script>'
        '<script src="https://cdn.b.net/b.js"></script>'
        '<script src="https://cdn.c.net/c.js"></script>'
    )
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("low coverage" in r["type"].lower() and r["status"] == "FAIL" for r in results)


# ── Hash strength ─────────────────────────────────────────────────────────────

def test_sha256_strong_no_flag():
    html = (
        '<script src="https://cdn.example.net/lib.js" '
        'integrity="sha256-validhash" crossorigin="anonymous"></script>'
    )
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert not any("weak hash" in r["type"].lower() for r in results)


def test_sha1_weak_fails():
    html = (
        '<script src="https://cdn.example.net/lib.js" '
        'integrity="sha1-weakhashabcdef" crossorigin="anonymous"></script>'
    )
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("weak hash" in r["type"].lower() and r["status"] == "FAIL" for r in results)


# ── crossorigin missing ───────────────────────────────────────────────────────

def test_integrity_without_crossorigin_warns():
    html = (
        '<script src="https://cdn.example.net/lib.js" '
        'integrity="sha256-validhash"></script>'
    )
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("without crossorigin" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


def test_integrity_with_crossorigin_clean():
    html = (
        '<script src="https://cdn.example.net/lib.js" '
        'integrity="sha256-validhash" crossorigin="anonymous"></script>'
    )
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert not any("without crossorigin" in r["type"].lower() for r in results)


# ── Protocol-relative URLs ────────────────────────────────────────────────────

def test_protocol_relative_counted_as_external():
    html = '<script src="//cdn.example.net/lib.js"></script>'
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("low coverage" in r["type"].lower() or "partial" in r["type"].lower()
               for r in results)


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_is_external_urlparse_raises_returns_true():
    """urlparse raises in _is_external → except Exception: return True at lines 41-42."""
    from unittest.mock import patch
    from tblue.scanner.sri_advanced import _is_external
    with patch("tblue.scanner.sri_advanced.urlparse", side_effect=ValueError("bad URL")):
        result = _is_external("https://cdn.malformed.com/", "example.com")
    assert result is True


def test_scan_resp_none_returns_empty():
    """http.get returns None in scan → return self.results at line 53."""
    from unittest.mock import patch, MagicMock
    scanner = SRIAdvancedScanner(MagicMock())
    with patch.object(scanner.http, "get", return_value=None):
        results = scanner.scan("https://example.com")
    assert results == []


def test_scan_http_get_raises_returns_empty():
    """http.get raises in scan try block → except Exception: return self.results at lines 54-55."""
    from unittest.mock import patch, MagicMock
    scanner = SRIAdvancedScanner(MagicMock())
    with patch.object(scanner.http, "get", side_effect=RuntimeError("network error")):
        results = scanner.scan("https://example.com")
    assert results == []


def test_inline_script_no_src_continues():
    """<script> without src → if not src_m: continue at line 73."""
    html = (
        '<script>var x = 1;</script>'
        '<script src="https://cdn.example.net/lib.js"></script>'
    )
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("coverage" in r["type"].lower() for r in results)


def test_link_non_stylesheet_continues():
    """<link rel="preconnect"> → if not _REL_STYLE_RE.search: continue at line 89."""
    html = (
        '<link rel="preconnect" href="https://cdn.example.net">'
        '<script src="https://cdn.example.net/lib.js"></script>'
    )
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("low coverage" in r["type"].lower() for r in results)


def test_stylesheet_link_no_href_continues():
    """<link rel="stylesheet"> without href → if not href_m: continue at line 92."""
    html = '<link rel="stylesheet" media="print">'
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert results == []


def test_stylesheet_local_href_continues():
    """<link rel="stylesheet" href="/local.css"> → if not _is_external: continue at line 95."""
    html = '<link rel="stylesheet" href="/local.css">'
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert results == []
