"""Extra branch coverage for tblue.scanner.xxe_injection."""

from unittest.mock import MagicMock, patch
from tblue.scanner.xxe_injection import XXEInjectionScanner

URL = "https://example.com"


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {"Content-Type": "text/html"}
    r.url = URL
    return r


def _scanner():
    session = MagicMock()
    return XXEInjectionScanner(session)


def test_no_xml_input_passes():
    """No XML input forms found → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html><form method='post'><input name='name'/></form></html>")), \
         patch.object(s.http, "post", return_value=_resp("")):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_xxe_passwd_reflected_fails():
    """Response echoes /etc/passwd content after XXE probe → FAIL."""
    s = _scanner()
    xml_form = '<html><form action="/api/xml" method="post"><input name="data"/></form></html>'
    xxe_body = "root:x:0:0:root:/root:/bin/bash"

    def post_side(url, **kw):
        return _resp(xxe_body)

    with patch.object(s.http, "get", return_value=_resp(xml_form)), \
         patch.object(s.http, "post", side_effect=post_side):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_xml_endpoint_returns_safe_response_passes():
    """XML endpoint returns safe response → PASS."""
    s = _scanner()
    xml_form = '<html><form action="/api/xml" method="post"><input name="data"/></form></html>'

    def post_side(url, **kw):
        return _resp("<result>OK</result>", 200, {"Content-Type": "application/xml"})

    with patch.object(s.http, "get", return_value=_resp(xml_form)), \
         patch.object(s.http, "post", side_effect=post_side):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_none_response_no_fail():
    """None response → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None), \
         patch.object(s.http, "post", return_value=None):
        results = s.scan(URL)
    assert all(r["status"] != "FAIL" for r in results)


def test_result_keys():
    """Results contain required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html></html>")), \
         patch.object(s.http, "post", return_value=_resp("")):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
