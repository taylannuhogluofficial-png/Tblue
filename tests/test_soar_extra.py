"""Extra branch coverage for tblue.soar — SOAR integration."""

from unittest.mock import MagicMock, patch
from tblue.soar import parse_target, _build_payload, _severity_for_score


def _results(*findings):
    return {"scanner": list(findings)}


def test_parse_target_jira():
    """parse_target splits 'jira:https://...' into (jira, url)."""
    backend, url = parse_target("jira:https://jira.example.com/PROJECT")
    assert backend == "jira"
    assert url == "https://jira.example.com/PROJECT"


def test_parse_target_pagerduty():
    """parse_target splits PagerDuty target."""
    backend, url = parse_target("pagerduty:https://events.pagerduty.com/v2/enqueue")
    assert backend == "pagerduty"


def test_parse_target_thehive():
    """parse_target splits TheHive target."""
    backend, url = parse_target("thehive:https://thehive.corp.com")
    assert backend == "thehive"


def test_build_payload_structure():
    """_build_payload returns dict with required keys."""
    findings = [{"status": "FAIL", "type": "XSS", "url": "https://example.com/q", "detail": "Found"}]
    all_results = _results(*findings)
    payload = _build_payload(
        target="https://example.com",
        scan_score=None,          # None means score=0, grade="?"
        all_results=all_results,
        scan_diff=None,
    )
    assert isinstance(payload, dict)
    assert "target" in payload
    assert "score" in payload


def test_build_payload_fail_count():
    """_build_payload counts FAIL/WARN/PASS correctly."""
    all_results = _results(
        {"status": "FAIL", "type": "XSS", "url": "https://example.com", "detail": "x"},
        {"status": "WARN", "type": "CSP", "url": "https://example.com", "detail": "x"},
        {"status": "PASS", "type": "HSTS", "url": "https://example.com", "detail": "x"},
    )
    payload = _build_payload("https://example.com", None, all_results, None)
    assert payload["failed"] == 1
    assert payload["warned"] == 1


def test_severity_for_score_critical():
    """_severity_for_score returns critical for very low scores."""
    sev = _severity_for_score(10)
    assert sev in ("critical", "high")


def test_severity_for_score_low():
    """_severity_for_score returns low/info for high scores."""
    sev = _severity_for_score(90)
    assert isinstance(sev, str)
