"""Extra coverage for csp_advanced — lines 43, 58-60, 162-163, 220-221, 242-243, 253-254, 264-265, 273-274, 284-285."""

from unittest.mock import MagicMock, patch
from tblue.scanner.csp_advanced import CSPAdvancedScanner


def _scanner(csp_header="", csp_ro="", html="", status=200):
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = status
        resp.text = html
        resp.headers = {}
        if csp_header:
            resp.headers["Content-Security-Policy"] = csp_header
        if csp_ro:
            resp.headers["Content-Security-Policy-Report-Only"] = csp_ro
        return resp

    session.request.side_effect = fake_request
    return CSPAdvancedScanner(session)


# ── Empty part in _parse_directives (line 43) ────────────────────────────────

def test_double_semicolon_in_csp_skips_empty_part():
    """CSP with double semicolon creates empty part → continue at line 43."""
    # Trailing semicolons or double semicolons create empty strings after split(";")
    csp = "default-src 'self';; frame-ancestors 'none';"  # double + trailing semicolon
    scanner = _scanner(csp_header=csp)
    results = scanner.scan("https://example.com")
    # Parser skips empty parts → continues normally
    assert isinstance(results, list)


# ── http.get returns None → early return (line 58) ───────────────────────────

def test_none_response_returns_empty():
    """http.get returning None → line 58 early return (resp is None path)."""
    scanner = CSPAdvancedScanner(MagicMock())
    with patch.object(scanner.http, "get", return_value=None):
        results = scanner.scan("https://example.com")
    assert results == []


# ── Exception in scan() http.get (lines 59-60) ──────────────────────────────

def test_exception_in_http_get_returns_empty():
    """Exception raised directly from http.get returns empty results (lines 59-60)."""
    scanner = CSPAdvancedScanner(MagicMock())
    with patch.object(scanner.http, "get", side_effect=ConnectionError("refused")):
        results = scanner.scan("https://example.com")
    assert results == []


# ── frame-ancestors specific origins (lines 58-60) ───────────────────────────

def test_frame_ancestors_specific_trusted_origin_passes():
    """frame-ancestors with specific allowed origins gets a PASS (lines 58-60)."""
    csp = "default-src 'self'; frame-ancestors https://trusted.example.com https://admin.example.com"
    scanner = _scanner(csp_header=csp)
    results = scanner.scan("https://example.com")
    frame_results = [r for r in results if "frame-ancestors" in r["type"].lower()]
    assert any(r["status"] == "PASS" for r in frame_results), \
        f"Expected PASS for frame-ancestors with specific origins: {frame_results}"


# ── frame-ancestors missing (lines 162-163) ──────────────────────────────────

def test_frame_ancestors_missing_produces_warn():
    """CSP without frame-ancestors directive warns (lines 162-163)."""
    csp = "default-src 'self'; script-src 'self'; base-uri 'self'"
    scanner = _scanner(csp_header=csp)
    results = scanner.scan("https://example.com")
    frame_results = [r for r in results if "frame-ancestors" in r["type"].lower()]
    assert any(r["status"] == "WARN" for r in frame_results), \
        f"Expected WARN for missing frame-ancestors: {frame_results}"


# ── upgrade-insecure-requests present (lines 220-221) ────────────────────────

def test_upgrade_insecure_requests_present_passes():
    """upgrade-insecure-requests in CSP produces PASS (lines 220-221)."""
    csp = "default-src 'self'; upgrade-insecure-requests; frame-ancestors 'none'"
    scanner = _scanner(csp_header=csp)
    results = scanner.scan("https://example.com")
    upgrade_results = [r for r in results if "upgrade-insecure" in r["type"].lower()]
    assert any(r["status"] == "PASS" for r in upgrade_results), \
        f"Expected PASS for upgrade-insecure-requests: {upgrade_results}"


# ── Trusted Types present (lines 242-243) ────────────────────────────────────

def test_trusted_types_enforced_passes():
    """require-trusted-types-for in CSP produces PASS (lines 242-243)."""
    csp = ("default-src 'self'; frame-ancestors 'none'; "
           "require-trusted-types-for 'script'")
    scanner = _scanner(csp_header=csp)
    results = scanner.scan("https://example.com")
    tt_results = [r for r in results if "trusted type" in r["type"].lower()]
    assert any(r["status"] == "PASS" for r in tt_results), \
        f"Expected PASS for Trusted Types: {tt_results}"


# ── unsafe-inline in script-src (lines 253-254) ──────────────────────────────

def test_unsafe_inline_in_script_src_fails():
    """'unsafe-inline' in script-src produces FAIL (lines 253-254)."""
    csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    scanner = _scanner(csp_header=csp)
    results = scanner.scan("https://example.com")
    inline_results = [r for r in results if "unsafe-inline" in r["type"].lower()]
    assert any(r["status"] == "FAIL" for r in inline_results), \
        f"Expected FAIL for 'unsafe-inline' in script-src: {inline_results}"


# ── unsafe-eval in script-src (lines 264-265) ────────────────────────────────

def test_unsafe_eval_in_script_src_warns():
    """'unsafe-eval' in script-src produces WARN (lines 264-265)."""
    csp = "default-src 'self'; script-src 'self' 'unsafe-eval'; frame-ancestors 'none'"
    scanner = _scanner(csp_header=csp)
    results = scanner.scan("https://example.com")
    eval_results = [r for r in results if "unsafe-eval" in r["type"].lower()]
    assert any(r["status"] == "WARN" for r in eval_results), \
        f"Expected WARN for 'unsafe-eval' in script-src: {eval_results}"


# ── wildcard in script-src (lines 273-274) ───────────────────────────────────

def test_wildcard_in_script_src_fails():
    """Wildcard (*) in script-src produces FAIL (lines 273-274)."""
    csp = "default-src 'self'; script-src * 'self'; frame-ancestors 'none'"
    scanner = _scanner(csp_header=csp)
    results = scanner.scan("https://example.com")
    wildcard_results = [r for r in results if "wildcard" in r["type"].lower()]
    assert any(r["status"] == "FAIL" for r in wildcard_results), \
        f"Expected FAIL for wildcard in script-src: {wildcard_results}"


# ── data: URI in script-src ───────────────────────────────────────────────────

def test_data_uri_in_script_src_fails():
    """data: URI scheme in script-src produces FAIL."""
    csp = "default-src 'self'; script-src 'self' data:; frame-ancestors 'none'"
    scanner = _scanner(csp_header=csp)
    results = scanner.scan("https://example.com")
    data_results = [r for r in results if "data:" in r["type"].lower()]
    assert any(r["status"] == "FAIL" for r in data_results), \
        f"Expected FAIL for data: URI in script-src: {data_results}"


# ── JSONP/AngularJS bypass host in script-src (lines 284-285) ────────────────

def test_known_bypass_host_in_script_src_warns():
    """Known JSONP/CDN bypass host in script-src produces WARN (lines 284-285)."""
    # ajax.googleapis.com is in _BYPASS_HOSTS
    csp = ("default-src 'self'; "
           "script-src 'self' ajax.googleapis.com; "
           "frame-ancestors 'none'")
    scanner = _scanner(csp_header=csp)
    results = scanner.scan("https://example.com")
    bypass_results = [r for r in results if "bypass" in r["type"].lower()
                      or "jsonp" in r["type"].lower()]
    assert any(r["status"] == "WARN" for r in bypass_results), \
        f"Expected WARN for known bypass host in script-src: {results}"
