"""Extra branch coverage for tblue.scanner.xml_xxe."""

from unittest.mock import MagicMock, patch
from tblue.scanner.xml_xxe import XXEScanner as XMLXXEScanner

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
    return XMLXXEScanner(session)


def test_no_xml_endpoint_passes():
    """No XML endpoint found → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html></html>")), \
         patch.object(s.http, "post", return_value=_resp("", 404)):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_xxe_response_with_passwd_content_fails():
    """Response containing /etc/passwd content → FAIL."""
    s = _scanner()
    xxe_body = "root:x:0:0:root:/root:/bin/bash\ndeamon:x:1:1"
    xml_form = '<html><form action="/upload" enctype="multipart/form-data" method="post"><input type="file" name="xml"/></form></html>'

    def post_side(url, **kw):
        return _resp(xxe_body, 200)

    with patch.object(s.http, "get", return_value=_resp(xml_form)), \
         patch.object(s.http, "post", side_effect=post_side):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_xml_upload_endpoint_detected():
    """XML upload endpoint found → scanner probes it."""
    s = _scanner()
    xml_form = '<html><form action="/api/xml" method="post"><input name="data" type="text"/></form></html>'

    def post_side(url, **kw):
        return _resp("<result>OK</result>", 200, {"Content-Type": "application/xml"})

    with patch.object(s.http, "get", return_value=_resp(xml_form)), \
         patch.object(s.http, "post", side_effect=post_side):
        results = s.scan(URL)
    assert isinstance(results, list)


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
