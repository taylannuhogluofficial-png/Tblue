"""
SOAR (Security Orchestration, Automation & Response) Integration.

Sends Tblue scan findings to incident management and ticketing systems:

  --soar jira:https://jira.company.com/PROJECT         Create Jira issue
  --soar pagerduty:https://events.pagerduty.com/...    PagerDuty event
  --soar thehive:https://thehive.company.com           TheHive case
  --soar servicenow:https://company.service-now.com    ServiceNow incident

Authentication via environment variables:
  TBLUE_JIRA_TOKEN        — Jira API token (user:token base64 or PAT)
  TBLUE_JIRA_USER         — Jira user email (needed with token)
  TBLUE_PAGERDUTY_KEY     — PagerDuty integration/routing key
  TBLUE_THEHIVE_KEY       — TheHive API key
  TBLUE_SERVICENOW_USER   — ServiceNow username
  TBLUE_SERVICENOW_PASS   — ServiceNow password

Payload schema for all backends:
  source, target, score, grade, failed, warned, critical, high, top_fails
"""

import os
import base64
import datetime
from typing import Any, Dict, List, Tuple

import requests as req_lib

from tblue.logger import get_logger

logger = get_logger(__name__)

_TIMEOUT = 15  # seconds

_VALID_FORMATS = ("jira", "pagerduty", "thehive", "servicenow")


def parse_target(soar_spec: str) -> Tuple[str, str]:
    """Parse 'format:https://...' → (fmt, url). Raises ValueError on bad format."""
    parts = soar_spec.split(":", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid --soar spec: {soar_spec!r}. Expected 'format:URL'.")
    fmt, rest = parts[0].lower().strip(), parts[1].strip()
    if fmt not in _VALID_FORMATS:
        raise ValueError(
            f"Unknown SOAR format {fmt!r}. Choose: {', '.join(_VALID_FORMATS)}"
        )
    url = rest if rest.startswith("http") else f"https:{rest}"
    return fmt, url


def send(soar_spec: str, target: str, scan_score, all_results: Dict[str, List],
         scan_diff=None) -> bool:
    """Dispatch scan to configured SOAR backend. Returns True on success."""
    try:
        fmt, backend_url = parse_target(soar_spec)
    except ValueError as e:
        logger.error(str(e))
        return False

    payload = _build_payload(target, scan_score, all_results, scan_diff)

    try:
        if fmt == "jira":
            return _send_jira(backend_url, payload)
        elif fmt == "pagerduty":
            return _send_pagerduty(backend_url, payload)
        elif fmt == "thehive":
            return _send_thehive(backend_url, payload)
        elif fmt == "servicenow":
            return _send_servicenow(backend_url, payload)
    except Exception as e:
        logger.error(f"SOAR dispatch failed ({fmt}): {e}")
    return False


def _build_payload(target, scan_score, all_results, scan_diff) -> Dict[str, Any]:
    from tblue.scoring import classify_severity

    fails, warns, passes = [], [], []
    critical, high = 0, 0

    for module_results in all_results.values():
        for r in module_results:
            s = r.get("status", "")
            if s == "FAIL":
                fails.append(r)
                sev = classify_severity(r.get("type", ""), "FAIL")
                if sev == "critical":
                    critical += 1
                elif sev == "high":
                    high += 1
            elif s == "WARN":
                warns.append(r)
            elif s == "PASS":
                passes.append(r)

    return {
        "source":    "tblue",
        "target":    target,
        "score":     scan_score.score if scan_score else 0,
        "grade":     scan_score.grade if scan_score else "?",
        "failed":    len(fails),
        "warned":    len(warns),
        "passed":    len(passes),
        "critical":  critical,
        "high":      high,
        "top_fails": [r.get("type", "") for r in fails[:10]],
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "score_delta": getattr(scan_diff, "score_delta", None) if scan_diff else None,
    }


def _severity_for_score(score: int) -> str:
    if score < 40:
        return "critical"
    elif score < 60:
        return "high"
    elif score < 80:
        return "medium"
    return "low"


# ── Jira ─────────────────────────────────────────────────────────────────────

def _send_jira(base_url: str, p: Dict[str, Any]) -> bool:
    """
    Create a Jira issue via REST API v3.
    URL format: https://jira.company.com/PROJECTKEY
    Environment: TBLUE_JIRA_TOKEN, TBLUE_JIRA_USER
    """
    # Extract project key from URL (last path component)
    parts = base_url.rstrip("/").rsplit("/", 1)
    if len(parts) == 2 and not parts[1].startswith("http"):
        jira_base, project_key = parts
    else:
        jira_base = base_url
        project_key = "SEC"

    token = os.environ.get("TBLUE_JIRA_TOKEN", "")
    user  = os.environ.get("TBLUE_JIRA_USER", "")

    if not token:
        logger.warning("TBLUE_JIRA_TOKEN not set — Jira integration requires authentication")
        return False

    if user:
        credentials = base64.b64encode(f"{user}:{token}".encode()).decode()
        auth_header = f"Basic {credentials}"
    else:
        auth_header = f"Bearer {token}"

    top_fails_text = "\n".join(f"* {f}" for f in p["top_fails"]) or "No failures"
    severity = _severity_for_score(p["score"])

    body = {
        "fields": {
            "project": {"key": project_key},
            "summary": f"[Tblue] Security scan: {p['target']} — Score {p['score']}/100 ({p['grade']})",
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": (
                            f"Tblue security scan results for {p['target']}.\n\n"
                            f"Score: {p['score']}/100 ({p['grade']})\n"
                            f"Failed: {p['failed']} | Warned: {p['warned']} | Passed: {p['passed']}\n"
                            f"Critical: {p['critical']} | High: {p['high']}\n\n"
                            f"Top issues:\n{top_fails_text}\n\n"
                            f"Scanned at: {p['timestamp']}"
                        )}]
                    }
                ]
            },
            "issuetype": {"name": "Bug"},
            "priority": {"name": severity.capitalize()},
            "labels": ["tblue", "security-scan", "automated"],
        }
    }

    r = req_lib.post(
        f"{jira_base.rstrip('/')}/rest/api/3/issue",
        json=body,
        headers={"Authorization": auth_header, "Content-Type": "application/json"},
        timeout=_TIMEOUT,
    )
    if r.status_code in (200, 201):
        issue_key = r.json().get("key", "?")
        logger.info(f"Jira issue created: {issue_key} for {p['target']}")
        return True
    logger.error(f"Jira issue creation failed: HTTP {r.status_code} — {r.text[:200]}")
    return False


# ── PagerDuty ─────────────────────────────────────────────────────────────────

def _send_pagerduty(events_url: str, p: Dict[str, Any]) -> bool:
    """
    Send PagerDuty event via Events API v2.
    Environment: TBLUE_PAGERDUTY_KEY (integration/routing key)
    """
    routing_key = os.environ.get("TBLUE_PAGERDUTY_KEY", "")
    if not routing_key:
        logger.warning("TBLUE_PAGERDUTY_KEY not set — PagerDuty requires routing key")
        return False

    severity = _severity_for_score(p["score"])
    action = "trigger" if p["failed"] > 0 else "resolve"

    body = {
        "routing_key": routing_key,
        "event_action": action,
        "dedup_key": f"tblue-{p['target'].replace('https://', '').replace('http://', '').rstrip('/')}",
        "payload": {
            "summary": f"Tblue: {p['target']} — {p['failed']} failures, score {p['score']}/100",
            "severity": severity,
            "source": p["target"],
            "component": "tblue-scanner",
            "group": "security",
            "class": "web-scan",
            "custom_details": {
                "score": p["score"],
                "grade": p["grade"],
                "failed": p["failed"],
                "warned": p["warned"],
                "critical": p["critical"],
                "high": p["high"],
                "top_issues": p["top_fails"][:5],
                "timestamp": p["timestamp"],
            },
        },
    }

    r = req_lib.post(events_url, json=body, timeout=_TIMEOUT)
    if r.status_code in (200, 202):
        logger.info(f"PagerDuty event sent ({action}) for {p['target']}")
        return True
    logger.error(f"PagerDuty event failed: HTTP {r.status_code}")
    return False


# ── TheHive ───────────────────────────────────────────────────────────────────

def _send_thehive(base_url: str, p: Dict[str, Any]) -> bool:
    """
    Create TheHive case via API v4/v5.
    Environment: TBLUE_THEHIVE_KEY (API key)
    """
    api_key = os.environ.get("TBLUE_THEHIVE_KEY", "")
    if not api_key:
        logger.warning("TBLUE_THEHIVE_KEY not set — TheHive requires API key")
        return False

    severity_map = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    sev_int = severity_map.get(_severity_for_score(p["score"]), 1)

    top_fails_md = "\n".join(f"- {f}" for f in p["top_fails"]) or "No failures"

    case_body = {
        "title": f"Tblue Security Scan: {p['target']}",
        "description": (
            f"## Tblue Scan Results\n\n"
            f"**Target:** {p['target']}\n"
            f"**Score:** {p['score']}/100 ({p['grade']})\n"
            f"**Failed:** {p['failed']} | **Warned:** {p['warned']} | **Passed:** {p['passed']}\n"
            f"**Critical:** {p['critical']} | **High:** {p['high']}\n\n"
            f"### Top Issues\n{top_fails_md}\n\n"
            f"*Scanned at {p['timestamp']}*"
        ),
        "severity": sev_int,
        "tags": ["tblue", "web-security", "automated-scan"],
        "tlp": 2,  # AMBER
        "pap": 2,  # AMBER
    }

    r = req_lib.post(
        f"{base_url.rstrip('/')}/api/v1/case",
        json=case_body,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        timeout=_TIMEOUT,
    )
    if r.status_code in (200, 201):
        case_id = r.json().get("_id", "?")
        logger.info(f"TheHive case created: {case_id} for {p['target']}")
        return True
    logger.error(f"TheHive case creation failed: HTTP {r.status_code}")
    return False


# ── ServiceNow ────────────────────────────────────────────────────────────────

def _send_servicenow(base_url: str, p: Dict[str, Any]) -> bool:
    """
    Create ServiceNow security incident via Table API.
    Environment: TBLUE_SERVICENOW_USER, TBLUE_SERVICENOW_PASS
    """
    user = os.environ.get("TBLUE_SERVICENOW_USER", "")
    pwd  = os.environ.get("TBLUE_SERVICENOW_PASS", "")

    if not user or not pwd:
        logger.warning("TBLUE_SERVICENOW_USER/PASS not set — ServiceNow requires credentials")
        return False

    # ServiceNow urgency: 1=high, 2=medium, 3=low
    urgency_map = {"critical": 1, "high": 1, "medium": 2, "low": 3}
    urgency = urgency_map.get(_severity_for_score(p["score"]), 2)

    top_fails_text = "\n".join(f"- {f}" for f in p["top_fails"]) or "None"

    incident_body = {
        "short_description": f"Tblue Security Scan: {p['target']} — Score {p['score']}/100",
        "description": (
            f"Tblue automated security scan results.\n\n"
            f"Target: {p['target']}\n"
            f"Score: {p['score']}/100 (Grade: {p['grade']})\n"
            f"Critical: {p['critical']} | High: {p['high']}\n"
            f"Failed: {p['failed']} | Warned: {p['warned']}\n\n"
            f"Top issues:\n{top_fails_text}\n\n"
            f"Scan timestamp: {p['timestamp']}"
        ),
        "category": "Security",
        "subcategory": "Web Application",
        "urgency": str(urgency),
        "impact": str(urgency),
        "assignment_group": "Security Operations",
        "caller_id": user,
    }

    r = req_lib.post(
        f"{base_url.rstrip('/')}/api/now/table/incident",
        json=incident_body,
        auth=(user, pwd),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        timeout=_TIMEOUT,
    )
    if r.status_code in (200, 201):
        sys_id = r.json().get("result", {}).get("sys_id", "?")
        logger.info(f"ServiceNow incident created: {sys_id} for {p['target']}")
        return True
    logger.error(f"ServiceNow incident creation failed: HTTP {r.status_code}")
    return False
