"""Extra branch coverage for tblue.scanner.cors."""

from unittest.mock import MagicMock, patch
from tblue.scanner.cors import CORSScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return CORSScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def test_no_acao_header_returns_pass():
    """Covers the clean branch when server returns no CORS headers."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "", {})):
        results = s.scan(URL)
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


def test_reflected_evil_origin_with_credentials_fails():
    """Covers the critical CORS reflected origin + credentials branch."""
    s = _scanner()
    evil = "https://evil-tblue-probe.com"

    def fake_get(url, headers=None, **kw):
        origin = (headers or {}).get("Origin", "")
        if origin:
            return _resp(200, "", {
                "access-control-allow-origin": origin,
                "access-control-allow-credentials": "true",
            })
        return _resp(200, "", {})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_reflected_evil_origin_without_credentials_warns():
    """Covers the WARN branch for reflected origin without credentials."""
    s = _scanner()

    def fake_get(url, headers=None, **kw):
        origin = (headers or {}).get("Origin", "")
        if origin == "https://evil-tblue-probe.com":
            return _resp(200, "", {
                "access-control-allow-origin": origin,
                # no credentials header
            })
        return _resp(200, "", {})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_null_origin_accepted_warns():
    """Covers the null origin acceptance branch."""
    s = _scanner()

    def fake_get(url, headers=None, allow_redirects=True, **kw):
        origin = (headers or {}).get("Origin", "")
        if origin == "null":
            return _resp(200, "", {"access-control-allow-origin": "null"})
        return _resp(200, "", {})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert any(r["status"] in ("WARN", "FAIL") for r in results)


def test_wildcard_acao_warns():
    """Covers the wildcard ACAO detection branch."""
    s = _scanner()

    def fake_get(url, headers=None, allow_redirects=True, **kw):
        return _resp(200, "", {"access-control-allow-origin": "*"})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_exception_in_probe_does_not_propagate():
    """Covers the exception-handling branch in CORS probing."""
    s = _scanner()

    def fake_get(url, headers=None, allow_redirects=True, **kw):
        raise ConnectionError("network error")

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert isinstance(results, list)
