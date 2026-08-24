"""Extra branch coverage for tblue.scanner.json_injection."""

from unittest.mock import MagicMock, patch
from tblue.scanner.json_injection import JSONInjectionScanner

URL = "https://example.com"
JSONP_URL = "https://example.com/api?callback=myFunc"


def _scanner():
    session = MagicMock()
    return JSONInjectionScanner(session)


def _resp(body="", status=200, content_type="text/html"):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {"content-type": content_type}
    r.url = URL
    return r


def test_no_response_returns_pass():
    """Branch: GET returns None → PASS result."""
    s = _scanner()
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_proto_pollution_hint_is_warn():
    """Branch: __proto__ in JSON response body → WARN."""
    s = _scanner()
    body = '{"__proto__": {"polluted": true}}'
    s.http.get = MagicMock(return_value=_resp(body, content_type="application/json"))
    results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_unescaped_html_in_json_response_is_warn():
    """Branch: JSON content-type response with <script> tag → WARN."""
    s = _scanner()
    body = '{"message": "<script>alert(1)</script>"}'
    s.http.get = MagicMock(return_value=_resp(body, content_type="application/json"))
    results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_jsonp_with_callback_param_is_checked():
    """Branch: URL has ?callback= param → JSONP check triggered."""
    s = _scanner()
    call_count = [0]
    def side(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp('myFunc({"data": 1})', content_type="text/javascript")
        # JSONP probe
        if "tblue_" in url:
            return _resp("tblue_/*<script>alert(1)</script>*/", content_type="application/javascript")
        return _resp("")
    s.http.get = MagicMock(side_effect=side)
    results = s.scan(JSONP_URL)
    assert isinstance(results, list)


def test_clean_html_returns_pass():
    """Branch: no JSON injection patterns in plain HTML page → PASS."""
    s = _scanner()
    s.http.get = MagicMock(return_value=_resp("<html><body>Hello</body></html>"))
    results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_json_api_in_links_probed():
    """Branch: page contains /api link that accepts JSON → probed for content-type enforcement."""
    s = _scanner()
    html = '<html><a href="/api/data">Data</a></html>'
    call_count = [0]
    def side(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(html)
        # API endpoint probe
        return _resp('{"status": "ok"}', content_type="application/json")
    s.http.get = MagicMock(side_effect=side)
    results = s.scan(URL)
    assert isinstance(results, list)
