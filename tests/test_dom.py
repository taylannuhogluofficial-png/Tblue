"""Tests for DOM pattern scanner (risky JS patterns, SRI, postMessage, open redirect)."""

from unittest.mock import MagicMock
from tblue.scanner.dom import DOMScanner
from tblue.definitions.dom_risks import DOM_RISKS


def _scanner(html=""):
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = html
        resp.headers = {}
        return resp

    session.request.side_effect = fake_request
    return DOMScanner(session)


# ── DOM risk patterns ─────────────────────────────────────────────────────────

def test_clean_page_dom_passes():
    scanner = _scanner("<html><body><p>Hello</p></body></html>")
    results = scanner.scan("https://example.com")
    dom = [r for r in results if r.get("type") == "DOM risk pattern"]
    assert any(r["status"] == "PASS" for r in dom)


def test_eval_pattern_warns():
    first_pattern = DOM_RISKS[0]["pattern"]
    html = f"<script>{first_pattern}</script>"
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    dom = [r for r in results if r.get("type") == "DOM risk pattern"]
    assert any(r["status"] == "WARN" for r in dom)


def test_multiple_dom_patterns_all_reported():
    # Use two known risky patterns
    p1 = DOM_RISKS[0]["pattern"]
    p2 = DOM_RISKS[1]["pattern"] if len(DOM_RISKS) > 1 else DOM_RISKS[0]["pattern"]
    html = f"<script>{p1} and {p2}</script>"
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    dom = [r for r in results if r.get("type") == "DOM risk pattern" and r["status"] == "WARN"]
    assert dom
    assert len(dom[0].get("patterns", [])) >= 1


def test_dom_warn_result_has_detail():
    first_pattern = DOM_RISKS[0]["pattern"]
    html = f"<script>{first_pattern}</script>"
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    warn = [r for r in results if r.get("type") == "DOM risk pattern" and r["status"] == "WARN"]
    assert warn
    assert warn[0].get("detail")


# ── External scripts without SRI ──────────────────────────────────────────────

def test_external_script_without_sri_warns():
    html = '<script src="https://cdn.example.com/lib.js"></script>'
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("sri" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_external_script_with_sri_passes():
    html = ('<script src="https://cdn.example.com/lib.js" '
            'integrity="sha384-abc123" crossorigin="anonymous"></script>')
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("sri" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_local_script_not_flagged_for_sri():
    html = '<script src="/js/app.js"></script>'
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert not any("sri" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_no_scripts_no_sri_result():
    html = '<html><body><p>Text only</p></body></html>'
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert not any("sri" in r["type"].lower() for r in results)


def test_mixed_scripts_some_without_sri_warns():
    html = (
        '<script src="https://cdn.a.com/with.js" integrity="sha256-x" crossorigin="anonymous"></script>'
        '<script src="https://cdn.b.com/without.js"></script>'
    )
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("sri" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── postMessage origin check ──────────────────────────────────────────────────

def test_postmessage_without_origin_warns():
    html = """<script>
    window.addEventListener('message', function(e) {
        document.getElementById('out').innerHTML = e.data;
    });
    </script>"""
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("postmessage" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_postmessage_with_origin_check_not_flagged():
    html = """<script>
    window.addEventListener('message', function(e) {
        if (e.origin !== 'https://trusted.example.com') return;
        document.getElementById('out').innerHTML = e.data;
    });
    </script>"""
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert not any("postmessage" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_no_postmessage_listener_not_flagged():
    html = "<script>var x = 1;</script>"
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert not any("postmessage" in r["type"].lower() for r in results)


# ── Open redirect patterns ─────────────────────────────────────────────────────

def test_location_href_from_variable_warns():
    html = """<script>
    var target = getQueryParam('redirect');
    window.location = target;
    </script>"""
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert any("open redirect" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_location_href_static_string_not_flagged():
    html = """<script>
    window.location = '/dashboard';
    </script>"""
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert not any("open redirect" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_no_js_no_redirect_result():
    html = "<html><body>Static page</body></html>"
    scanner = _scanner(html)
    results = scanner.scan("https://example.com")
    assert not any("open redirect" in r["type"].lower() for r in results)


# ── Error handling ────────────────────────────────────────────────────────────

def test_network_error_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("timeout")
    scanner = DOMScanner(session)
    results = scanner.scan("https://example.com")
    assert results == []


def test_none_response_returns_empty():
    session = MagicMock()
    session.request.return_value = None
    scanner = DOMScanner(session)
    results = scanner.scan("https://example.com")
    assert results == []
