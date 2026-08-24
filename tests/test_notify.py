"""Tests for tblue.notify — notification webhook integration."""

import pytest
from unittest.mock import MagicMock, patch

from tblue.notify import (
    parse_target,
    send,
    _build_payload,
    _colour_for_score,
    _send_slack,
    _send_teams,
    _send_discord,
    _send_generic,
)


# ── parse_target ──────────────────────────────────────────────────────────────

def test_parse_slack():
    fmt, url = parse_target("slack:https://hooks.slack.com/services/T123/B456/xxx")
    assert fmt == "slack"
    assert url.startswith("https://")


def test_parse_teams():
    fmt, url = parse_target("teams:https://outlook.office.com/webhook/abc")
    assert fmt == "teams"
    assert "outlook" in url


def test_parse_discord():
    fmt, url = parse_target("discord:https://discord.com/api/webhooks/123/abc")
    assert fmt == "discord"


def test_parse_webhook():
    fmt, url = parse_target("webhook:https://soc.internal/hook")
    assert fmt == "webhook"


def test_parse_uppercase_format():
    fmt, url = parse_target("SLACK:https://hooks.slack.com/xxx")
    assert fmt == "slack"


def test_parse_missing_colon():
    with pytest.raises(ValueError, match="Expected 'format:URL'"):
        parse_target("noformat")


def test_parse_no_colon_at_all():
    with pytest.raises(ValueError):
        parse_target("noformat")


def test_parse_unknown_format():
    with pytest.raises(ValueError, match="Unknown notification format"):
        parse_target("pagerduty:https://events.pagerduty.com")


# ── _colour_for_score ─────────────────────────────────────────────────────────

def test_colour_high_score():
    assert _colour_for_score(90) == "#2ecc71"


def test_colour_medium_score():
    assert _colour_for_score(70) == "#f39c12"


def test_colour_low_score():
    assert _colour_for_score(40) == "#e74c3c"


def test_colour_boundary_80():
    assert _colour_for_score(80) == "#2ecc71"


def test_colour_boundary_60():
    assert _colour_for_score(60) == "#f39c12"


# ── _build_payload ────────────────────────────────────────────────────────────

def _make_score(score=75, grade="C"):
    s = MagicMock()
    s.score = score
    s.grade = grade
    return s


def test_build_payload_basic():
    all_results = {
        "headers": [
            {"status": "FAIL", "type": "CORS — wildcard", "url": "https://x.com"},
            {"status": "WARN", "type": "CSP — missing", "url": "https://x.com"},
            {"status": "PASS", "type": "X-Frame-Options", "url": "https://x.com"},
        ]
    }
    p = _build_payload("https://x.com", _make_score(), all_results, None)
    assert p["source"] == "tblue"
    assert p["target"] == "https://x.com"
    assert p["score"] == 75
    assert p["grade"] == "C"
    assert p["failed"] == 1
    assert p["warned"] == 1
    assert p["passed"] == 1
    assert "timestamp" in p
    assert "delta" not in p


def test_build_payload_no_score():
    p = _build_payload("https://x.com", None, {}, None)
    assert p["score"] == 0
    assert p["grade"] == "?"


def test_build_payload_with_diff():
    diff = MagicMock()
    diff.score_delta = -5
    diff.new_issues = [{"type": "X"}, {"type": "Y"}]
    diff.resolved_issues = [{"type": "Z"}]
    p = _build_payload("https://x.com", _make_score(), {}, diff)
    assert "delta" in p
    assert p["delta"]["score_delta"] == -5
    assert p["delta"]["new_issues"] == 2
    assert p["delta"]["resolved"] == 1


def test_build_payload_top_fails_limit():
    results = {"mod": [{"status": "FAIL", "type": f"issue-{i}", "url": "https://x.com"} for i in range(10)]}
    p = _build_payload("https://x.com", _make_score(), results, None)
    assert len(p["top_fails"]) == 5


def test_build_payload_empty_results():
    p = _build_payload("https://x.com", _make_score(), {"m1": [], "m2": []}, None)
    assert p["failed"] == 0
    assert p["warned"] == 0
    assert p["passed"] == 0


# ── _send_slack ───────────────────────────────────────────────────────────────

def _make_payload(score=75):
    return {
        "target": "https://example.com",
        "score": score,
        "grade": "C",
        "failed": 2,
        "warned": 3,
        "passed": 10,
        "critical": 1,
        "high": 1,
        "top_fails": ["XSS — reflected", "CORS — wildcard"],
        "timestamp": "2026-06-25T12:00:00Z",
    }


def test_send_slack_success():
    p = _make_payload()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("tblue.notify.req_lib.post", return_value=mock_resp):
        result = _send_slack("https://hooks.slack.com/test", p)
    assert result is True


def test_send_slack_failure():
    p = _make_payload()
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    with patch("tblue.notify.req_lib.post", return_value=mock_resp):
        result = _send_slack("https://hooks.slack.com/test", p)
    assert result is False


def test_send_slack_with_delta():
    p = _make_payload()
    p["delta"] = {"score_delta": 5, "new_issues": 1, "resolved": 2}
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("tblue.notify.req_lib.post", return_value=mock_resp):
        result = _send_slack("https://hooks.slack.com/test", p)
    assert result is True


def test_send_slack_with_score_drop():
    p = _make_payload()
    p["delta"] = {"score_delta": -10, "new_issues": 3, "resolved": 0}
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("tblue.notify.req_lib.post", return_value=mock_resp):
        result = _send_slack("https://hooks.slack.com/test", p)
    assert result is True


def test_send_slack_no_failures():
    p = _make_payload()
    p["top_fails"] = []
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("tblue.notify.req_lib.post", return_value=mock_resp):
        result = _send_slack("https://hooks.slack.com/test", p)
    assert result is True


# ── _send_teams ───────────────────────────────────────────────────────────────

def test_send_teams_success():
    p = _make_payload()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("tblue.notify.req_lib.post", return_value=mock_resp):
        result = _send_teams("https://outlook.office.com/webhook/test", p)
    assert result is True


def test_send_teams_grade_a():
    p = _make_payload(score=95)
    p["grade"] = "A"
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("tblue.notify.req_lib.post", return_value=mock_resp):
        result = _send_teams("https://outlook.office.com/webhook/test", p)
    assert result is True


def test_send_teams_failure():
    p = _make_payload()
    mock_resp = MagicMock()
    mock_resp.status_code = 400
    with patch("tblue.notify.req_lib.post", return_value=mock_resp):
        result = _send_teams("https://outlook.office.com/webhook/test", p)
    assert result is False


# ── _send_discord ─────────────────────────────────────────────────────────────

def test_send_discord_success():
    p = _make_payload(score=90)
    mock_resp = MagicMock()
    mock_resp.status_code = 204
    with patch("tblue.notify.req_lib.post", return_value=mock_resp):
        result = _send_discord("https://discord.com/api/webhooks/test", p)
    assert result is True


def test_send_discord_low_score():
    p = _make_payload(score=30)
    mock_resp = MagicMock()
    mock_resp.status_code = 204
    with patch("tblue.notify.req_lib.post", return_value=mock_resp):
        result = _send_discord("https://discord.com/api/webhooks/test", p)
    assert result is True


def test_send_discord_failure():
    p = _make_payload()
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    with patch("tblue.notify.req_lib.post", return_value=mock_resp):
        result = _send_discord("https://discord.com/api/webhooks/test", p)
    assert result is False


# ── _send_generic ─────────────────────────────────────────────────────────────

def test_send_generic_success():
    p = _make_payload()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("tblue.notify.req_lib.post", return_value=mock_resp):
        result = _send_generic("https://soc.internal/hook", p)
    assert result is True


def test_send_generic_failure():
    p = _make_payload()
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    with patch("tblue.notify.req_lib.post", return_value=mock_resp):
        result = _send_generic("https://soc.internal/hook", p)
    assert result is False


# ── send() dispatcher ─────────────────────────────────────────────────────────

def test_send_dispatches_slack():
    score = _make_score()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("tblue.notify.req_lib.post", return_value=mock_resp):
        result = send("slack:https://hooks.slack.com/test", "https://example.com", score, {})
    assert result is True


def test_send_dispatches_teams():
    score = _make_score()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("tblue.notify.req_lib.post", return_value=mock_resp):
        result = send("teams:https://outlook.office.com/webhook/test", "https://example.com", score, {})
    assert result is True


def test_send_dispatches_discord():
    score = _make_score()
    mock_resp = MagicMock()
    mock_resp.status_code = 204
    with patch("tblue.notify.req_lib.post", return_value=mock_resp):
        result = send("discord:https://discord.com/api/webhooks/test", "https://example.com", score, {})
    assert result is True


def test_send_dispatches_webhook():
    score = _make_score()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("tblue.notify.req_lib.post", return_value=mock_resp):
        result = send("webhook:https://soc.internal/hook", "https://example.com", score, {})
    assert result is True


def test_send_invalid_spec():
    result = send("invalid-spec", "https://example.com", _make_score(), {})
    assert result is False


def test_send_exception_in_sender():
    score = _make_score()
    with patch("tblue.notify.req_lib.post", side_effect=ConnectionError("timeout")):
        result = send("slack:https://hooks.slack.com/test", "https://example.com", score, {})
    assert result is False
