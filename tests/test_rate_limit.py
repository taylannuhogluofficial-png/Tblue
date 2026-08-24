"""
Tests for the rate limiting detection scanner.
"""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.rate_limit import RateLimitScanner


def make_scanner(responses: list = None) -> RateLimitScanner:
    """
    responses: list of (status_code, headers, body) to return on successive calls.
    If shorter than probe count, last item repeats.
    """
    responses = responses or [(200, {}, "Login")]
    session   = MagicMock()
    call_idx  = [0]

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        idx  = min(call_idx[0], len(responses) - 1)
        code, hdrs, body = responses[idx]
        resp.status_code = code
        resp.headers     = hdrs
        resp.text        = body
        resp.url         = url
        call_idx[0]     += 1
        return resp

    session.request.side_effect = fake_request
    return RateLimitScanner(session, retries=1)


# ── Rate limiting detected ────────────────────────────────────────────────────

def test_429_response_passes(monkeypatch):
    monkeypatch.setattr("tblue.scanner.rate_limit.time.sleep", lambda _: None)
    # First request normal, then 429
    scanner = make_scanner([
        (200, {}, "Enter password"),
        (429, {"retry-after": "60"}, "Too Many Requests"),
    ])
    results = scanner.scan("https://example.com")
    assert any("enforced" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_ratelimit_header_passes(monkeypatch):
    monkeypatch.setattr("tblue.scanner.rate_limit.time.sleep", lambda _: None)
    scanner = make_scanner([
        (200, {"x-ratelimit-remaining": "4"}, "Enter password"),
    ])
    results = scanner.scan("https://example.com")
    assert any("enforced" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_retry_after_header_passes(monkeypatch):
    monkeypatch.setattr("tblue.scanner.rate_limit.time.sleep", lambda _: None)
    scanner = make_scanner([
        (200, {"retry-after": "30"}, "Enter password"),
    ])
    results = scanner.scan("https://example.com")
    assert any("enforced" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_lockout_message_in_body_passes(monkeypatch):
    monkeypatch.setattr("tblue.scanner.rate_limit.time.sleep", lambda _: None)
    scanner = make_scanner([
        (200, {}, "Enter password"),
        (200, {}, "Enter password"),
        (200, {}, "Too many attempts — please try again in 30 minutes"),
    ])
    results = scanner.scan("https://example.com")
    assert any("enforced" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ── No rate limiting ──────────────────────────────────────────────────────────

def test_no_rate_limiting_warns(monkeypatch):
    monkeypatch.setattr("tblue.scanner.rate_limit.time.sleep", lambda _: None)
    scanner = make_scanner([(200, {}, "Enter password")])
    results = scanner.scan("https://example.com")
    assert any("not detected" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Detail quality ────────────────────────────────────────────────────────────

def test_warn_result_has_fix_guidance(monkeypatch):
    monkeypatch.setattr("tblue.scanner.rate_limit.time.sleep", lambda _: None)
    scanner = make_scanner([(200, {}, "Login")])
    results = scanner.scan("https://example.com")
    warn    = next(r for r in results if r["status"] == "WARN")
    assert "fix" in warn["detail"].lower()
    assert "rate" in warn["detail"].lower()


# ── Error handling ────────────────────────────────────────────────────────────

def test_all_requests_fail_warns(monkeypatch):
    monkeypatch.setattr("tblue.scanner.rate_limit.time.sleep", lambda _: None)
    session = MagicMock()
    session.request.side_effect = Exception("Connection refused")
    scanner = RateLimitScanner(session, retries=1)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "WARN" for r in results)


def test_probe_get_raises_is_swallowed(monkeypatch):
    # Call _probe directly with http.get patched to raise — covers except pass branch
    from unittest.mock import patch
    monkeypatch.setattr("tblue.scanner.rate_limit.time.sleep", lambda _: None)
    scanner = make_scanner([(200, {}, "Login")])
    with patch.object(scanner.http, "get", side_effect=Exception("connection error")):
        result = scanner._probe("https://example.com/login", "GET")
    # All probes raised → no rate limiting detected → returns False
    assert result is False
