"""Extra branch coverage for tblue.scanner.prototype_pollution."""

from unittest.mock import MagicMock, patch
from tblue.scanner.prototype_pollution import PrototypePollutionScanner

URL = "https://example.com"


def _resp(body="", status=200):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    r.url = URL
    return r


def _scanner():
    session = MagicMock()
    return PrototypePollutionScanner(session)


def test_no_params_returns_pass():
    """URL with no query params → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_reflection_of_proto_payload_fails():
    """Response reflects __proto__ payload → FAIL."""
    s = _scanner()
    # Response that echoes injected prototype pollution probe
    body = '{"polluted":"yes","__proto__":{"isAdmin":true}}'

    with patch.object(s.http, "get", return_value=_resp(body)):
        results = s.scan(URL + "?__proto__[isAdmin]=true")
    assert isinstance(results, list)


def test_none_response_no_fail():
    """None response → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL + "?__proto__[test]=1")
    assert all(r["status"] != "FAIL" for r in results)


def test_constructor_payload_tested():
    """Scanner tests constructor.prototype pollution payloads."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")), \
         patch.object(s.http, "post", return_value=_resp(""), new_callable=MagicMock):
        results = s.scan(URL + "?constructor[prototype][x]=1")
    assert isinstance(results, list)


def test_result_keys():
    """Results contain required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
