"""Tests for tblue.scanner.client_storage — ClientStorageScanner."""

from unittest.mock import MagicMock, patch
from tblue.scanner.client_storage import ClientStorageScanner

URL = "https://example.com"


def _make_scanner():
    return ClientStorageScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = {}
    return r


def _wrap_script(js: str) -> str:
    return f"<html><head><script>{js}</script></head><body></body></html>"


def test_unreachable_pass():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_clean_page_pass():
    s = _make_scanner()
    html = "<html><body><p>Hello world</p></body></html>"
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] == "FAIL" for r in results)


def test_password_in_localstorage_fails():
    """localStorage.setItem('password', ...) → FAIL."""
    s = _make_scanner()
    js = "localStorage.setItem('password', document.getElementById('pwd').value);"
    with patch.object(s.http, "get", return_value=_resp(200, _wrap_script(js))):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("password" in f["type"].lower() for f in fails)


def test_jwt_in_localstorage_fails():
    """localStorage.setItem('token', jwt) → FAIL."""
    s = _make_scanner()
    js = "localStorage.setItem('jwt_token', response.data.accessToken);"
    with patch.object(s.http, "get", return_value=_resp(200, _wrap_script(js))):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("jwt" in f["type"].lower() or "token" in f["type"].lower() for f in fails)


def test_auth_token_in_sessionstorage_fails():
    """sessionStorage.setItem('auth_token', ...) → FAIL."""
    s = _make_scanner()
    js = "sessionStorage.setItem('auth_token', data.token);"
    with patch.object(s.http, "get", return_value=_resp(200, _wrap_script(js))):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("token" in f["type"].lower() or "storage" in f["type"].lower() for f in fails)


def test_pii_credit_card_in_storage_fails():
    """localStorage.setItem with credit card key → FAIL."""
    s = _make_scanner()
    js = "localStorage.setItem('credit_card_number', cardInput.value);"
    with patch.object(s.http, "get", return_value=_resp(200, _wrap_script(js))):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("pii" in f["type"].lower() or "payment" in f["type"].lower()
               or "storage" in f["type"].lower() for f in fails)


def test_auth_read_from_storage_warns():
    """localStorage.getItem('token') used for auth decisions → WARN."""
    s = _make_scanner()
    js = "const tok = localStorage.getItem('auth_token'); if (tok) redirectToHome();"
    with patch.object(s.http, "get", return_value=_resp(200, _wrap_script(js))):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("auth" in w["type"].lower() or "storage" in w["type"].lower() for w in warns)


def test_sensitive_key_in_setitem_warns():
    """localStorage.setItem('api_key', ...) → WARN."""
    s = _make_scanner()
    js = "localStorage.setItem('api_key', config.key);"
    with patch.object(s.http, "get", return_value=_resp(200, _wrap_script(js))):
        results = s.scan(URL)
    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("sensitive" in r["type"].lower() or "storage" in r["type"].lower()
               or "api" in r["type"].lower() for r in warns_or_fails)


def test_bracket_auth_in_storage_warns():
    """localStorage['token'] = ... → WARN."""
    s = _make_scanner()
    js = "localStorage['auth_token'] = loginResponse.token;"
    with patch.object(s.http, "get", return_value=_resp(200, _wrap_script(js))):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("auth" in w["type"].lower() or "bracket" in w["type"].lower()
               or "storage" in w["type"].lower() for w in warns)


def test_indexeddb_sensitive_store_warns():
    """IndexedDB createObjectStore('credentials') → WARN."""
    s = _make_scanner()
    js = "db.createObjectStore('credentials', {keyPath: 'id'});"
    with patch.object(s.http, "get", return_value=_resp(200, _wrap_script(js))):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("indexeddb" in w["type"].lower() or "storage" in w["type"].lower() for w in warns)


def test_websql_deprecated_warns():
    """openDatabase() usage → WARN."""
    s = _make_scanner()
    js = "var db = openDatabase('mydb', '1.0', 'My database', 2 * 1024 * 1024);"
    with patch.object(s.http, "get", return_value=_resp(200, _wrap_script(js))):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("websql" in w["type"].lower() or "openDatabase" in w["detail"]
               or "web sql" in w["type"].lower() for w in warns)


def test_external_script_with_jwt_storage_fails():
    """JWT stored in localStorage in external first-party JS → FAIL."""
    s = _make_scanner()
    html = '<html><head><script src="/app.js"></script></head><body></body></html>'
    js_body = "function login(res) { localStorage.setItem('jwt_token', res.token); }"

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if "/app.js" in url:
            return _resp(200, js_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("storage" in f["type"].lower() or "jwt" in f["type"].lower() for f in fails)
