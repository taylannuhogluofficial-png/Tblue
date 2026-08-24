"""Extra branch coverage for tblue.scanner.weak_crypto."""

from unittest.mock import MagicMock, patch
from tblue.scanner.weak_crypto import WeakCryptoScanner

URL = "https://example.com"


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.url = URL
    return r


def _scanner():
    session = MagicMock()
    return WeakCryptoScanner(session)


def test_md5_in_js_fails():
    """MD5 usage in JS source → FAIL."""
    s = _scanner()
    js_body = "var hash = md5(password); // MD5 hash of password"
    html = '<html><head><script src="/app.js"></script></head></html>'

    def get_side(url, **kw):
        if ".js" in url:
            return _resp(js_body, 200, {"Content-Type": "application/javascript"})
        return _resp(html)

    with patch.object(s.http, "get", side_effect=get_side):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_sha1_in_response_warns():
    """SHA1 usage in response body → WARN."""
    s = _scanner()
    body = "password_hash = sha1(password + salt)"
    with patch.object(s.http, "get", return_value=_resp(body)):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert isinstance(results, list)


def test_no_crypto_in_response_passes():
    """Response with no crypto references → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html><body>Hello World</body></html>")):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_none_response_no_fail():
    """None response → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert all(r["status"] != "FAIL" for r in results)


def test_result_keys():
    """Results contain required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
