"""Extra branch coverage for tblue.scanner.mass_assignment."""

from unittest.mock import MagicMock
from tblue.scanner.mass_assignment import MassAssignmentScanner

URL = "https://example.com"


def _resp(body="", status=200, content_type="text/html"):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {"content-type": content_type}
    r.url = URL
    return r


def _scanner(html="", status=200, headers=None):
    session = MagicMock()
    resp = _resp(html, status)
    if headers:
        resp.headers = headers
    s = MassAssignmentScanner(session)
    # Mock all HTTP methods the scanner may call
    for method in ("get", "post", "put", "patch", "delete", "request"):
        setattr(s.http, method, MagicMock(return_value=resp))
    return s


def test_no_response_returns_pass():
    """When the target returns None, scan emits a single PASS result."""
    s = MassAssignmentScanner(MagicMock())
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0]["status"] == "PASS"


def test_marker_reflected_in_json_response_flags_finding():
    """If the probe marker is echoed in the JSON response body, a FAIL is raised."""
    body = '{"role":"admin","tblue_mass_assign_probe":"injected"}'
    resp = _resp(body, 200, "application/json")

    s = MassAssignmentScanner(MagicMock())
    for method in ("get", "post", "put", "patch", "delete", "request"):
        setattr(s.http, method, MagicMock(return_value=resp))
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "FAIL" in statuses or "WARN" in statuses


def test_plain_html_no_api_endpoints():
    """Simple HTML page with no API forms or links returns list of results."""
    html = "<html><body><p>Welcome</p></body></html>"
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)


def test_privileged_fields_in_registration_form_flagged():
    """Registration form containing 'is_admin' or 'role' field is flagged."""
    html = """
    <html><body>
      <form method="post" action="/register">
        <input type="text" name="username" />
        <input type="hidden" name="is_admin" value="false" />
        <input type="hidden" name="role" value="user" />
        <input type="submit" />
      </form>
    </body></html>
    """
    s = _scanner(html=html)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "WARN" in statuses or "FAIL" in statuses


def test_results_contain_required_keys():
    """Every result dict includes url, status, and a descriptive field."""
    s = _scanner(html="<html><body></body></html>")
    results = s.scan(URL)
    for r in results:
        assert "url" in r
        assert "status" in r
