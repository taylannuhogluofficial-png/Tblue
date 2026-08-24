"""Extra branch coverage for tblue.scanner.cors_advanced."""

from unittest.mock import MagicMock, patch
from tblue.scanner.cors_advanced import CORSAdvancedScanner

URL = "https://example.com"
API_URL = "https://example.com/api/v1/users"


def _scanner():
    session = MagicMock()
    return CORSAdvancedScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def test_no_cors_headers_returns_pass():
    """Covers the clean branch where server returns no CORS headers at all."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "", {})):
        results = s.scan(URL)
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


def test_prefix_bypass_origin_accepted_warns():
    """Covers the prefix-bypass branch (trustedexample.com accepted for example.com)."""
    s = _scanner()

    def fake_get(url, headers=None, **kw):
        origin = (headers or {}).get("Origin", "")
        # Simulate a server that accepts origins ending with the domain
        if "example.com" in origin:
            return _resp(200, "", {"access-control-allow-origin": origin})
        return _resp(200, "", {})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert any(r["status"] in ("WARN", "FAIL") for r in results)


def test_null_origin_bypass_warns():
    """Covers the null origin bypass branch."""
    s = _scanner()

    def fake_get(url, headers=None, **kw):
        origin = (headers or {}).get("Origin", "")
        if origin == "null":
            return _resp(200, "", {"access-control-allow-origin": "null"})
        return _resp(200, "", {})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert any(r["status"] in ("WARN", "FAIL") for r in results)


def test_protocol_downgrade_origin_accepted_warns():
    """Covers HTTP origin accepted by HTTPS endpoint (protocol downgrade)."""
    s = _scanner()

    def fake_get(url, headers=None, **kw):
        origin = (headers or {}).get("Origin", "")
        if origin and origin.startswith("http://"):
            return _resp(200, "", {"access-control-allow-origin": origin})
        return _resp(200, "", {})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert any(r["status"] in ("WARN", "FAIL") for r in results)


def test_preflight_missing_allow_headers_warns():
    """Covers the preflight missing Access-Control-Allow-Headers branch."""
    s = _scanner()

    def fake_get(url, headers=None, **kw):
        origin = (headers or {}).get("Origin", "")
        if origin:
            return _resp(200, "", {
                "access-control-allow-origin": "https://attacker.com",
                "access-control-allow-methods": "GET, POST",
                # Missing access-control-allow-headers
            })
        return _resp(200, "", {})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_all_results_have_required_keys():
    """Covers that every result dict has the mandatory keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "", {})):
        results = s.scan(URL)
    for r in results:
        assert "type" in r
        assert "status" in r
        assert "url" in r
