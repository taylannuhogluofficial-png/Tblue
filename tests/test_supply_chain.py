"""Tests for supply chain scanner (SRI, Permissions-Policy, COOP/COEP, trackers)."""

from unittest.mock import MagicMock
from tblue.scanner.supply_chain import SupplyChainScanner


def _scanner(html="", headers=None):
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = 200
    resp.text = html
    resp.headers = headers or {}
    session.request.return_value = resp
    return SupplyChainScanner(session)


# ── SRI ───────────────────────────────────────────────────────────────────────

def test_sri_missing_warns():
    html = '<script src="https://cdn.example.com/jquery.min.js"></script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert any("sri" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_sri_present_passes():
    html = ('<script src="https://cdn.example.com/jquery.min.js" '
            'integrity="sha384-abc123" crossorigin="anonymous"></script>')
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert any("sri" in r["type"].lower() and r["status"] == "PASS" for r in results)
    assert not any("sri" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_no_external_resources_passes():
    html = '<script src="/js/app.js"></script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    sri_results = [r for r in results if "sri" in r["type"].lower()]
    assert all(r["status"] == "PASS" for r in sri_results)


# ── Permissions-Policy ────────────────────────────────────────────────────────

def test_permissions_policy_present_passes():
    headers = {"Permissions-Policy": "camera=(), microphone=(), geolocation=()"}
    scanner = _scanner(headers=headers)
    results = scanner.scan("https://example.com")
    assert any("permissions-policy" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_permissions_policy_missing_warns():
    scanner = _scanner(headers={})
    results = scanner.scan("https://example.com")
    assert any("permissions-policy" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


# ── COOP ──────────────────────────────────────────────────────────────────────

def test_coop_present_passes():
    headers = {"Cross-Origin-Opener-Policy": "same-origin"}
    scanner = _scanner(headers=headers)
    results = scanner.scan("https://example.com")
    assert any("coop" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_coop_missing_warns():
    scanner = _scanner(headers={})
    results = scanner.scan("https://example.com")
    assert any("coop" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── COEP ──────────────────────────────────────────────────────────────────────

def test_coep_present_passes():
    headers = {"Cross-Origin-Embedder-Policy": "require-corp"}
    scanner = _scanner(headers=headers)
    results = scanner.scan("https://example.com")
    assert any("coep" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ── Third-party trackers ──────────────────────────────────────────────────────

def test_known_tracker_warns():
    html = '<script src="https://www.google-analytics.com/analytics.js"></script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert any("tracking" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_no_tracker_passes():
    html = '<script src="/js/app.js"></script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    tracker_results = [r for r in results if "supply chain" in r["type"].lower()]
    assert any(r["status"] == "PASS" for r in tracker_results)


# ── CORP ──────────────────────────────────────────────────────────────────────

def test_corp_present_passes():
    headers = {"Cross-Origin-Resource-Policy": "same-origin"}
    scanner = _scanner(headers=headers)
    results = scanner.scan("https://example.com")
    assert any("corp" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_corp_missing_warns():
    scanner = _scanner(headers={})
    results = scanner.scan("https://example.com")
    assert any("corp" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_corp_same_site_passes():
    headers = {"Cross-Origin-Resource-Policy": "same-site"}
    scanner = _scanner(headers=headers)
    results = scanner.scan("https://example.com")
    assert any("corp" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ── scan() edge cases ─────────────────────────────────────────────────────────

def test_none_response_returns_empty():
    session = MagicMock()
    session.request.return_value = None
    scanner = SupplyChainScanner(session)
    results = scanner.scan("https://example.com")
    assert results == []


def test_http_get_raises_returns_empty():
    from unittest.mock import patch
    scanner = _scanner()
    with patch.object(scanner.http, "get", side_effect=Exception("network error")):
        results = scanner.scan("https://example.com")
    assert results == []


# ── SRI edge cases ────────────────────────────────────────────────────────────

def test_script_tag_without_src_skipped():
    # <script> with no src attr — no src_m match → continue
    html = '<script>var x = 1;</script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    sri_results = [r for r in results if "sri" in r["type"].lower()]
    # No external resources → PASS
    assert any(r["status"] == "PASS" for r in sri_results)


def test_link_non_stylesheet_skipped():
    # <link rel="preload"> — not a stylesheet → skipped
    html = '<link rel="preload" href="https://cdn.example.com/font.woff2">'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    sri_results = [r for r in results if "sri" in r["type"].lower()]
    assert any(r["status"] == "PASS" for r in sri_results)


def test_link_without_href_skipped():
    # <link rel="stylesheet"> with no href attr → skipped
    html = '<link rel="stylesheet" media="print">'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    sri_results = [r for r in results if "sri" in r["type"].lower()]
    assert any(r["status"] == "PASS" for r in sri_results)


def test_external_stylesheet_without_sri_warns():
    # External stylesheet with no integrity attribute
    html = '<link rel="stylesheet" href="https://cdn.example.com/style.css">'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert any("sri" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_protocol_relative_script_is_external():
    # src="//cdn.example.com/..." — protocol-relative, always external
    html = '<script src="//cdn.example.com/jquery.min.js"></script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert any("sri" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_same_host_resource_not_external():
    # src on same domain should not be flagged as external
    html = '<script src="https://example.com/js/app.js"></script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    sri_results = [r for r in results if "sri" in r["type"].lower()]
    # No external resources → PASS (same host)
    assert any(r["status"] == "PASS" for r in sri_results)


# ── Third-party inventory ─────────────────────────────────────────────────────

def test_third_party_non_tracker_passes():
    # Third-party domain present but not a known tracker
    html = '<script src="https://cdn.myapp.io/app.js"></script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert any("no known trackers" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_same_host_resource_not_counted_as_third_party():
    # href pointing to the same host
    html = '<a href="https://example.com/page">link</a>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    tp_results = [r for r in results if "supply chain" in r["type"].lower()]
    assert any("no third-party" in r["type"].lower() and r["status"] == "PASS"
               for r in tp_results)
