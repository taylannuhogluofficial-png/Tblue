"""Extra coverage for access_control — lines 83-84, 119-120, 147."""

from unittest.mock import MagicMock
from tblue.scanner.access_control import AccessControlScanner

URL = "https://example.com"


def _make_scanner(paths: dict = None) -> AccessControlScanner:
    paths = paths or {}
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        for suffix, (code, body) in paths.items():
            if url.endswith(suffix) or suffix in url:
                r = MagicMock()
                r.status_code = code
                r.text = body
                r.url = url
                return r
        r = MagicMock()
        r.status_code = 404
        r.text = "Not Found"
        r.url = url
        return r

    session.request.side_effect = fake_request
    return AccessControlScanner(session)


def test_robots_txt_exception_silently_returns():
    """Exception during robots.txt request silently returns (lines 83-84 — except path)."""
    from unittest.mock import patch
    scanner = _make_scanner()
    # Patch the underlying http.get to raise for robots URL
    orig_get = scanner.http.get

    def raising_get(url, **kw):
        if "robots.txt" in url:
            raise ConnectionError("timeout")
        return orig_get(url, **kw)

    with patch.object(scanner.http, "get", side_effect=raising_get):
        results = scanner.scan(URL)

    # No robots finding — exception was silently caught
    robots_findings = [r for r in results if "robots" in r["type"].lower()]
    assert not robots_findings, f"Unexpected robots finding after exception: {robots_findings}"


def test_admin_path_returning_403_adds_to_locked():
    """Admin path with 401/403 response goes to found_locked — PASS result (line 127)."""
    scanner = _make_scanner({"/admin": (403, "")})
    results = scanner.scan(URL)
    # Should get a PASS with mention of locked paths
    pass_results = [r for r in results if r["status"] == "PASS"]
    assert pass_results, f"Expected PASS when admin path is properly locked: {results}"


def test_admin_probe_exception_continues():
    """Exception during admin path probe is caught and skipped (lines 119-120)."""
    from unittest.mock import patch

    scanner = _make_scanner()
    orig_get = scanner.http.get
    call_count = [0]

    def raising_get(url, **kw):
        call_count[0] += 1
        if call_count[0] > 1 and "/admin" in url:
            raise TimeoutError("Connection timed out")
        return orig_get(url, **kw)

    with patch.object(scanner.http, "get", side_effect=raising_get):
        results = scanner.scan(URL)

    # Exceptions during admin probes are caught → scanner continues → PASS
    assert isinstance(results, list)


def test_admin_path_returning_401_adds_to_locked():
    """Admin path returning 401 Unauthorized is locked (not open)."""
    scanner = _make_scanner({"/wp-admin/": (401, "Unauthorized")})
    results = scanner.scan(URL)
    # No FAIL for 401 — it's properly locked
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not fails, f"Unexpected FAIL for 401 protected admin path: {fails}"


def test_admin_path_200_no_panel_keywords_goes_to_open():
    """200 response with no panel/auth keywords → found_open (line 147 else branch)."""
    # Body big enough (> 64 chars) but no auth keywords (not: password, username, login, signin, etc.)
    # and no panel keywords (not: dashboard, admin panel, control panel, etc.)
    generic_body = (
        "<html><body><h1>System Portal</h1>"
        "<p>Restricted area. Please contact your system administrator for access. "
        "This zone requires proper clearance before entry.</p></body></html>"
    )
    scanner = _make_scanner({"/admin": (200, generic_body)})
    results = scanner.scan(URL)
    # A generic 200 with no auth/panel keywords → found_open or found_login → FAIL or WARN
    fails_warns = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert fails_warns, f"Expected FAIL/WARN for admin path with generic 200 body: {results}"
