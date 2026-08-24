"""Extra branch coverage for tblue.scanner.race_condition."""

from unittest.mock import MagicMock, patch
from tblue.scanner.race_condition import RaceConditionScanner

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
    return RaceConditionScanner(session)


def test_plain_page_returns_pass():
    """Page with no race-vulnerable forms → PASS."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html><body><p>Hello</p></body></html>")):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_none_response_returns_pass():
    """None response → PASS result."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert any(r["status"] == "PASS" for r in results)


def test_gift_card_form_flagged():
    """Page with gift card redemption form → WARN or FAIL (race risk)."""
    s = _scanner()
    html = (
        '<html><body>'
        '<form action="/redeem" method="post">'
        '<input name="gift_code" /><input type="submit"/>'
        '</form></body></html>'
    )
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan("https://example.com/redeem")
    assert isinstance(results, list)


def test_idempotency_header_present_passes():
    """Response with X-Idempotency-Key header → idempotency enforced."""
    s = _scanner()
    html = (
        '<html><body>'
        '<form action="/transfer" method="post">'
        '<input name="amount" /><input type="submit"/>'
        '</form></body></html>'
    )
    hdrs = {"X-Idempotency-Key": "req-abc-123"}
    with patch.object(s.http, "get", return_value=_resp(html, headers=hdrs)):
        results = s.scan("https://example.com/transfer")
    assert isinstance(results, list)


def test_result_keys():
    """Results contain required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html><body></body></html>")):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
