"""Extra branch coverage for tblue.scanner.host_header."""

from unittest.mock import MagicMock, patch
from tblue.scanner.host_header import HostHeaderScanner

URL = "https://example.com"
PROBE = "tblue-hostprobe.invalid"


def _scanner():
    session = MagicMock()
    return HostHeaderScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def test_probe_reflected_in_location_header():
    """Branch: probe value in Location response header → FAIL."""
    s = _scanner()
    s.http.get = MagicMock(return_value=_resp(
        302, "", {"Location": f"https://{PROBE}/redirect"}
    ))
    results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_probe_reflected_in_body():
    """Branch: probe value echoed in response body → FAIL."""
    s = _scanner()
    s.http.get = MagicMock(return_value=_resp(
        200, f"Welcome to {PROBE} portal"
    ))
    results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_no_reflection_returns_pass():
    """Branch: no reflection across any header → PASS result."""
    s = _scanner()
    s.http.get = MagicMock(return_value=_resp(200, "Safe page"))
    results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_exception_during_probe_skipped():
    """Branch: exception during GET probe is caught and probe skipped."""
    s = _scanner()
    s.http.get = MagicMock(side_effect=Exception("timeout"))
    results = s.scan(URL)
    # Should not raise; all probes failed, so PASS
    assert any(r["status"] == "PASS" for r in results)


def test_none_response_skipped():
    """Branch: None response for a header probe is skipped gracefully."""
    s = _scanner()
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_probe_reflected_in_refresh_header():
    """Branch: probe value in Refresh response header triggers FAIL."""
    s = _scanner()
    s.http.get = MagicMock(return_value=_resp(
        200, "", {"Refresh": f"0; url=https://{PROBE}/"}
    ))
    results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
