"""Extra branch coverage for tblue.notify."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.notify import parse_target, send


def test_parse_target_slack():
    """parse_target correctly parses a slack spec."""
    fmt, url = parse_target("slack:https://hooks.slack.com/services/T/B/xxx")
    assert fmt == "slack"
    assert url.startswith("https://")


def test_parse_target_discord():
    """parse_target correctly parses a discord spec."""
    fmt, url = parse_target("discord:https://discord.com/api/webhooks/123/abc")
    assert fmt == "discord"
    assert "discord.com" in url


def test_parse_target_invalid_format_raises():
    """Unknown format prefix raises ValueError."""
    with pytest.raises(ValueError, match="Unknown notification format"):
        parse_target("unknown:https://example.com/hook")


def test_parse_target_missing_colon_raises():
    """Missing colon separator raises ValueError."""
    with pytest.raises(ValueError, match="Invalid --notify spec"):
        parse_target("nocolonseparator")


def test_send_returns_false_on_bad_spec():
    """send() returns False when the spec is invalid."""
    result = send("badspec", "https://example.com", None, {})
    assert result is False


def test_send_slack_success():
    """send() returns True when the Slack webhook responds with 200."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("tblue.notify.req_lib.post", return_value=mock_resp):
        result = send(
            "slack:https://hooks.slack.com/services/T/B/xxx",
            "https://example.com",
            MagicMock(score=80, grade="B"),
            {"scanner": [{"status": "PASS", "check_type": "test"}]},
        )
    assert result is True
