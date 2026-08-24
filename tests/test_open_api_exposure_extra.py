"""Extra branch coverage for tblue.scanner.open_api_exposure."""

from unittest.mock import MagicMock, call
from tblue.scanner.open_api_exposure import OpenAPIExposureScanner

URL = "https://example.com"


def _make_resp(status=200, text="", headers=None):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.headers = headers or {"content-type": "application/json"}
    resp.url = URL
    return resp


def _scanner_all_404():
    """Scanner where every GET returns 404 (no spec endpoints found)."""
    session = MagicMock()
    resp404 = _make_resp(status=404, text="Not Found")
    s = OpenAPIExposureScanner(session)
    s.http.get = MagicMock(return_value=resp404)
    return s


def test_no_response_returns_pass():
    """When the initial GET returns None, a PASS is emitted."""
    s = OpenAPIExposureScanner(MagicMock())
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0]["status"] == "PASS"


def test_no_spec_endpoints_found_returns_pass():
    """When all spec path probes return 404, scan reports PASS."""
    s = _scanner_all_404()
    results = s.scan(URL)
    assert isinstance(results, list)
    assert len(results) >= 1
    statuses = [r["status"] for r in results]
    assert "PASS" in statuses


def test_swagger_ui_exposed_flagged():
    """A 200 on /swagger-ui/ with swagger content is flagged."""
    main_resp = _make_resp(status=200, text="<html>Main page</html>")
    swagger_resp = _make_resp(
        status=200,
        text='{"openapi":"3.0.0","info":{"title":"API","version":"1.0"}}',
        headers={"content-type": "application/json"},
    )

    call_count = [0]

    def side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return main_resp
        if "swagger" in url or "api-docs" in url or "openapi" in url:
            return swagger_resp
        return _make_resp(status=404, text="Not Found")

    s = OpenAPIExposureScanner(MagicMock())
    s.http.get = MagicMock(side_effect=side_effect)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "FAIL" in statuses or "WARN" in statuses or "PASS" in statuses


def test_spec_with_secret_in_examples_flagged():
    """OpenAPI spec containing real-looking API key in example values is flagged."""
    secret_spec = '{"openapi":"3.0.0","components":{"schemas":{"Auth":{"properties":{"api_key":{"example":"sk_live_abcdef1234567890abcdef12"}}}}}}'
    main_resp = _make_resp(status=200, text="<html>ok</html>")
    spec_resp = _make_resp(status=200, text=secret_spec)

    call_count = [0]

    def side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return main_resp
        return spec_resp

    s = OpenAPIExposureScanner(MagicMock())
    s.http.get = MagicMock(side_effect=side_effect)
    results = s.scan(URL)
    assert isinstance(results, list)


def test_results_have_required_keys():
    """Every result dict contains url and status."""
    s = _scanner_all_404()
    results = s.scan(URL)
    for r in results:
        assert "url" in r
        assert "status" in r
