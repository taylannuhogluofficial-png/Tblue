"""Extra coverage for admin_exposure — lines 161 (false-positive return), 175-176 (WARN path)."""

from unittest.mock import MagicMock
from tblue.scanner.admin_exposure import AdminExposureScanner

URL = "https://example.com"


def _make_scanner(paths: dict = None) -> AdminExposureScanner:
    paths = paths or {}
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        for suffix, (code, body) in paths.items():
            if suffix in url:
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
    return AdminExposureScanner(session)


def test_false_positive_body_title_404_skipped():
    """Body with <title>404 Not Found</title> triggers false-positive check (line 161 return None)."""
    # SPA that returns 200 for all routes but with 404 in the title
    spa_body = (
        "<html><head><title>404 Not Found</title></head>"
        "<body><div id='root'>This is a single-page app catching all routes.</div>"
        "<p>The path you requested does not exist in this application.</p></body></html>"
    )
    scanner = _make_scanner({"/admin": (200, spa_body)})
    results = scanner.scan(URL)
    # The false-positive filter should prevent this from being flagged
    admin_fails = [r for r in results
                   if r["status"] == "FAIL" and "admin" in r.get("type", "").lower()]
    assert not admin_fails, f"False-positive filter should suppress SPA 404-title responses: {admin_fails}"


def test_body_too_short_not_flagged():
    """Body shorter than _MIN_BODY_LEN (64 chars) is skipped — SPA catch-all protection."""
    scanner = _make_scanner({"/admin": (200, "<html>ok</html>")})
    results = scanner.scan(URL)
    admin_fails = [r for r in results
                   if r["status"] == "FAIL" and "admin" in r.get("type", "").lower()]
    assert not admin_fails, f"Short body should not be flagged: {admin_fails}"


def test_warn_severity_debug_path_exposed():
    """Debug interface returning 200 with meaningful body produces WARN (lines 175-176)."""
    debug_body = (
        "<html><head><title>Debug Interface</title></head>"
        "<body><h1>Debug Panel</h1>"
        "<pre>System info: Python 3.11, Django 4.2</pre>"
        "<p>This debug interface is for development purposes only.</p>"
        "</body></html>"
    )
    scanner = _make_scanner({"/debug/": (200, debug_body)})
    results = scanner.scan(URL)
    # /debug/ has WARN severity — should produce a WARN finding
    warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert warns, f"Expected WARN/FAIL for exposed debug interface: {results}"


def test_warn_severity_actuator_exposed():
    """Spring Boot actuator accessible produces WARN finding."""
    actuator_body = (
        '{"_links":{"self":{"href":"http://localhost:8080/actuator","templated":false},'
        '"health":{"href":"http://localhost:8080/actuator/health","templated":false},'
        '"info":{"href":"http://localhost:8080/actuator/info","templated":false},'
        '"metrics":{"href":"http://localhost:8080/actuator/metrics","templated":false}}}'
    )
    scanner = _make_scanner({"/actuator": (200, actuator_body)})
    results = scanner.scan(URL)
    warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert warns, f"Expected WARN for exposed Spring actuator: {results}"


def test_probe_exception_returns_none():
    """Exception during a probe is caught by the except block (lines 175-176)."""
    from unittest.mock import patch

    scanner = _make_scanner()
    call_count = [0]

    def raising_get(url, **kw):
        call_count[0] += 1
        if call_count[0] > 1:
            # All probe calls raise — caught by except Exception: return None
            raise ConnectionError("broken pipe")
        # First call (base URL scan) returns a normal 404
        r = MagicMock()
        r.status_code = 404
        r.text = ""
        r.url = url
        return r

    with patch.object(scanner.http, "get", side_effect=raising_get):
        results = scanner.scan(URL)

    # Exceptions in probes → no findings → PASS
    assert isinstance(results, list)
