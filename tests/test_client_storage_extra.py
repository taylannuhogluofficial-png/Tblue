"""Extra branch coverage for tblue.scanner.client_storage."""

from unittest.mock import MagicMock, patch
from tblue.scanner.client_storage import ClientStorageScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return ClientStorageScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def test_no_response_returns_pass():
    """Covers the None-response early-exit path."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_jwt_stored_in_localstorage_flagged():
    """Covers the JWT-in-localStorage detection branch."""
    s = _scanner()
    html = """
    <html><body>
    <script>
      localStorage.setItem('auth_token', response.jwt);
      localStorage.setItem('access_token', data.token);
    </script>
    </body></html>
    """
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    assert any(r["status"] in ("FAIL", "WARN") for r in results)


def test_password_stored_in_sessionstorage_flagged():
    """Covers the password-in-sessionStorage detection branch."""
    s = _scanner()
    html = """
    <html><body>
    <script>
      sessionStorage.setItem('password', userPassword);
      sessionStorage.setItem('passwd', form.pwd.value);
    </script>
    </body></html>
    """
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    assert any(r["status"] in ("FAIL", "WARN") for r in results)


def test_localstorage_auth_decision_warns():
    """Covers the auth-decision-via-getItem branch."""
    s = _scanner()
    html = """
    <html><body>
    <script>
      const token = localStorage.getItem('auth_token');
      if (token) { showAdminPanel(); }
      const role = sessionStorage.getItem('role');
      if (role === 'admin') { enableAdmin(); }
    </script>
    </body></html>
    """
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    assert any(r["status"] in ("WARN", "FAIL") for r in results)


def test_clean_page_returns_pass():
    """Covers the clean page path with no sensitive storage usage."""
    s = _scanner()
    html = """
    <html><body>
    <script>
      localStorage.setItem('theme', 'dark');
      localStorage.setItem('language', 'en');
      const lang = localStorage.getItem('language');
    </script>
    </body></html>
    """
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


def test_indexeddb_sensitive_store_flagged():
    """Covers the IndexedDB sensitive object store name branch."""
    s = _scanner()
    html = """
    <html><body>
    <script>
      const db = indexedDB.open('app', 1);
      db.onupgradeneeded = function(e) {
        e.target.result.createObjectStore('credentials', {keyPath: 'id'});
        e.target.result.createObjectStore('passwords', {keyPath: 'username'});
      };
    </script>
    </body></html>
    """
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    assert any(r["status"] in ("WARN", "FAIL") for r in results)
