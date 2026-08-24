"""Extra branch coverage for tblue.scanner.sri_advanced."""

from unittest.mock import MagicMock, patch
from tblue.scanner.sri_advanced import SRIAdvancedScanner

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
    return SRIAdvancedScanner(session)


def test_external_script_with_integrity_passes():
    """External script with valid integrity attribute → PASS."""
    html = (
        '<html><head>'
        '<script src="https://cdn.example.com/lib.js" '
        'integrity="sha384-abc123" crossorigin="anonymous"></script>'
        '</head></html>'
    )
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_external_script_missing_integrity_fails():
    """External script missing integrity → FAIL."""
    html = '<html><head><script src="https://cdn.example.com/lib.js"></script></head></html>'
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert fails


def test_inline_scripts_not_flagged():
    """Inline scripts (no src) not flagged for missing SRI."""
    html = "<html><head><script>var x=1;</script></head></html>"
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not fails


def test_none_response_no_fail():
    """None response → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert all(r["status"] != "FAIL" for r in results)


def test_result_keys():
    """Results contain required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html></html>")):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
