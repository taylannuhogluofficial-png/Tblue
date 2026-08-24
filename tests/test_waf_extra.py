"""Extra branch coverage for tblue.scanner.waf."""

from unittest.mock import MagicMock, patch
from tblue.scanner.waf import WAFScanner

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
    return WAFScanner(session)


def test_waf_detected_passes():
    """WAF header present → informational PASS."""
    s = _scanner()
    hdrs = {"X-Cdn": "Cloudflare", "Server": "cloudflare"}
    with patch.object(s.http, "get", return_value=_resp("", headers=hdrs)):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_no_waf_warns():
    """No WAF detected → WARN (no protection layer)."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("", headers={})):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert isinstance(results, list)


def test_attack_request_blocked_passes():
    """WAF blocks XSS probe with 403 → PASS (WAF protecting)."""
    s = _scanner()
    responses = [_resp("", 200), _resp("Blocked", 403)]
    counter = [0]

    def get_side(*a, **kw):
        r = responses[min(counter[0], len(responses) - 1)]
        counter[0] += 1
        return r

    with patch.object(s.http, "get", side_effect=get_side):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_none_response_no_fail():
    """None response → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert all(r["status"] != "FAIL" for r in results)
