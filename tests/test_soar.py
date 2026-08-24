"""Tests for tblue.soar — SOAR integration."""

import os
import pytest
from unittest.mock import MagicMock, patch
from tblue.soar import parse_target, send, _build_payload, _severity_for_score


# ── parse_target ──────────────────────────────────────────────────────────────

def test_parse_jira():
    fmt, url = parse_target("jira:https://company.atlassian.net/SEC")
    assert fmt == "jira"
    assert "atlassian" in url

def test_parse_pagerduty():
    fmt, url = parse_target("pagerduty:https://events.pagerduty.com/v2/enqueue")
    assert fmt == "pagerduty"

def test_parse_thehive():
    fmt, url = parse_target("thehive:https://hive.company.com")
    assert fmt == "thehive"

def test_parse_servicenow():
    fmt, url = parse_target("servicenow:https://company.service-now.com")
    assert fmt == "servicenow"

def test_parse_no_colon():
    with pytest.raises(ValueError, match="Expected"):
        parse_target("noformat")

def test_parse_unknown_format():
    with pytest.raises(ValueError, match="Unknown SOAR format"):
        parse_target("splunk:https://splunk.company.com")


# ── _severity_for_score ───────────────────────────────────────────────────────

def test_severity_critical():
    assert _severity_for_score(30) == "critical"

def test_severity_high():
    assert _severity_for_score(55) == "high"

def test_severity_medium():
    assert _severity_for_score(70) == "medium"

def test_severity_low():
    assert _severity_for_score(90) == "low"


# ── _build_payload ────────────────────────────────────────────────────────────

def _make_score(score=65, grade="D"):
    s = MagicMock()
    s.score = score
    s.grade = grade
    return s

def test_build_payload_counts():
    all_results = {"m": [
        {"status": "FAIL", "type": "XSS", "url": "https://x.com"},
        {"status": "WARN", "type": "CSP", "url": "https://x.com"},
        {"status": "PASS", "type": "SSL", "url": "https://x.com"},
    ]}
    p = _build_payload("https://x.com", _make_score(), all_results, None)
    assert p["failed"] == 1
    assert p["warned"] == 1
    assert p["passed"] == 1
    assert p["source"] == "tblue"

def test_build_payload_no_score():
    p = _build_payload("https://x.com", None, {}, None)
    assert p["score"] == 0


# ── send() dispatcher ─────────────────────────────────────────────────────────

def test_send_invalid_spec():
    result = send("bad-spec", "https://x.com", _make_score(), {})
    assert result is False

def test_send_jira_no_token():
    with patch.dict(os.environ, {}, clear=True):
        os.environ.pop("TBLUE_JIRA_TOKEN", None)
        result = send("jira:https://company.atlassian.net/SEC", "https://x.com", _make_score(), {})
    assert result is False

def test_send_pagerduty_no_key():
    env = {k: v for k, v in os.environ.items() if k != "TBLUE_PAGERDUTY_KEY"}
    with patch.dict(os.environ, env, clear=True):
        result = send("pagerduty:https://events.pagerduty.com/v2/enqueue", "https://x.com", _make_score(), {})
    assert result is False

def test_send_thehive_no_key():
    env = {k: v for k, v in os.environ.items() if k != "TBLUE_THEHIVE_KEY"}
    with patch.dict(os.environ, env, clear=True):
        result = send("thehive:https://hive.company.com", "https://x.com", _make_score(), {})
    assert result is False

def test_send_servicenow_no_creds():
    env = {k: v for k, v in os.environ.items()
           if k not in ("TBLUE_SERVICENOW_USER", "TBLUE_SERVICENOW_PASS")}
    with patch.dict(os.environ, env, clear=True):
        result = send("servicenow:https://company.service-now.com", "https://x.com", _make_score(), {})
    assert result is False

def test_send_jira_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {"key": "SEC-42"}
    with patch.dict(os.environ, {"TBLUE_JIRA_TOKEN": "tok123", "TBLUE_JIRA_USER": "user@co.com"}):
        with patch("tblue.soar.req_lib.post", return_value=mock_resp):
            result = send("jira:https://company.atlassian.net/SEC", "https://x.com", _make_score(), {})
    assert result is True

def test_send_pagerduty_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 202
    with patch.dict(os.environ, {"TBLUE_PAGERDUTY_KEY": "rkey123"}):
        with patch("tblue.soar.req_lib.post", return_value=mock_resp):
            result = send("pagerduty:https://events.pagerduty.com/v2/enqueue", "https://x.com", _make_score(), {})
    assert result is True

def test_send_thehive_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {"_id": "case-123"}
    with patch.dict(os.environ, {"TBLUE_THEHIVE_KEY": "apikey123"}):
        with patch("tblue.soar.req_lib.post", return_value=mock_resp):
            result = send("thehive:https://hive.company.com", "https://x.com", _make_score(), {})
    assert result is True

def test_send_servicenow_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {"result": {"sys_id": "inc001"}}
    with patch.dict(os.environ, {"TBLUE_SERVICENOW_USER": "admin", "TBLUE_SERVICENOW_PASS": "pass"}):
        with patch("tblue.soar.req_lib.post", return_value=mock_resp):
            result = send("servicenow:https://company.service-now.com", "https://x.com", _make_score(), {})
    assert result is True

def test_send_exception_returns_false():
    with patch.dict(os.environ, {"TBLUE_JIRA_TOKEN": "tok", "TBLUE_JIRA_USER": "u@c.com"}):
        with patch("tblue.soar.req_lib.post", side_effect=ConnectionError("timeout")):
            result = send("jira:https://company.atlassian.net/SEC", "https://x.com", _make_score(), {})
    assert result is False
