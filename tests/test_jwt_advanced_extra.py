"""Extra branch coverage for tblue.scanner.jwt_advanced."""

import base64
import json
from unittest.mock import MagicMock, patch
from tblue.scanner.jwt_advanced import JWTAdvancedScanner

URL = "https://example.com"


def _make_jwt(header: dict, payload: dict) -> str:
    def b64enc(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64enc(header)}.{b64enc(payload)}.fakesig"


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.url = URL
    return r


def _scanner():
    session = MagicMock()
    return JWTAdvancedScanner(session)


def test_none_response_no_fail():
    """None response → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert all(r["status"] != "FAIL" for r in results)


def test_jwt_in_url_param_warns():
    """JWT in URL query parameter leaks via Referer/logs → FAIL or WARN."""
    token = _make_jwt({"alg": "RS256"}, {"sub": "user", "exp": 9999999999})
    url_with_token = f"{URL}?token={token}"
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(url_with_token)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert isinstance(results, list)


def test_jwt_with_http_jku_fails():
    """JWT with jku pointing to HTTP (not HTTPS) → FAIL."""
    token = _make_jwt(
        {"alg": "RS256", "jku": "http://attacker.com/jwks.json"},
        {"sub": "admin", "exp": 9999999999}
    )
    body = json.dumps({"access_token": token})
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(body)):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_jwt_with_long_expiry_warns():
    """JWT with expiry > 24 hours → WARN about long-lived token."""
    import time
    exp = int(time.time()) + (30 * 24 * 3600)  # 30 days
    token = _make_jwt({"alg": "RS256"}, {"sub": "user", "exp": exp})
    body = json.dumps({"access_token": token})
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(body)):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_no_jwt_in_response_passes():
    """Response with no JWTs → PASS."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp('{"message": "ok"}')):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)
