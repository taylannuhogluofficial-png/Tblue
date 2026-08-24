"""
Notification webhook integration for Tblue.

Supports:
  slack:https://hooks.slack.com/...  — Slack Incoming Webhook
  teams:https://...                  — Microsoft Teams Incoming Webhook
  webhook:https://...                — Generic HTTP POST (JSON payload)
  discord:https://discord.com/...    — Discord Webhook

Usage (CLI):
  --notify slack:https://hooks.slack.com/services/T.../B.../xxxx
  --notify teams:https://outlook.office.com/webhook/...
  --notify webhook:https://your-soc.internal/tblue-hook

Payload sent to generic/discord webhooks follows the Tblue summary schema:
  {
    "source": "tblue",
    "target": "https://example.com",
    "score": 78,
    "grade": "C",
    "passed": 42,
    "warned": 12,
    "failed": 5,
    "critical": 2,
    "high": 3,
    "top_fails": ["XSS — reflected...", "..."],
    "timestamp": "2026-06-28T..."
  }
"""

import json
import datetime
from typing import Any, Dict, List, Tuple

import requests as req_lib

from tblue.logger import get_logger

logger = get_logger(__name__)

_TIMEOUT = 10  # seconds


def parse_target(notify_spec: str) -> Tuple[str, str]:
    """Parse 'format:https://...' → (fmt, url). Raises ValueError on bad format."""
    parts = notify_spec.split(":", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid --notify spec: {notify_spec!r}. Expected 'format:URL'.")
    fmt, rest = parts[0].lower().strip(), parts[1].strip()
    if fmt not in ("slack", "teams", "webhook", "discord"):
        raise ValueError(f"Unknown notification format {fmt!r}. Choose: slack, teams, webhook, discord")
    # Re-add the https: that was split off
    url = rest if rest.startswith("http") else f"https:{rest}"
    return fmt, url


def send(
    notify_spec: str,
    target: str,
    scan_score,
    all_results: Dict[str, List],
    scan_diff=None,
) -> bool:
    """
    Send scan summary to a notification webhook.
    Returns True on success, False on failure.
    """
    try:
        fmt, webhook_url = parse_target(notify_spec)
    except ValueError as e:
        logger.error(str(e))
        return False

    payload = _build_payload(target, scan_score, all_results, scan_diff)

    try:
        if fmt == "slack":
            return _send_slack(webhook_url, payload)
        elif fmt == "teams":
            return _send_teams(webhook_url, payload)
        elif fmt == "discord":
            return _send_discord(webhook_url, payload)
        else:
            return _send_generic(webhook_url, payload)
    except Exception as e:
        logger.error(f"Notification failed ({fmt}): {e}")
        return False


def _build_payload(target, scan_score, all_results, scan_diff) -> Dict[str, Any]:
    """Build the common summary payload."""
    from tblue.scoring import classify_severity

    fails, warns, passes = [], [], []
    critical_count = high_count = 0

    for module_results in all_results.values():
        for r in module_results:
            status = r.get("status", "")
            if status == "FAIL":
                fails.append(r)
                sev = classify_severity(r.get("type", ""), "FAIL")
                if sev == "critical":
                    critical_count += 1
                elif sev == "high":
                    high_count += 1
            elif status == "WARN":
                warns.append(r)
            elif status == "PASS":
                passes.append(r)

    top_fails = [r.get("type", "Unknown") for r in fails[:5]]

    payload: Dict[str, Any] = {
        "source":    "tblue",
        "target":    target,
        "score":     scan_score.score if scan_score else 0,
        "grade":     scan_score.grade if scan_score else "?",
        "passed":    len(passes),
        "warned":    len(warns),
        "failed":    len(fails),
        "critical":  critical_count,
        "high":      high_count,
        "top_fails": top_fails,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }

    if scan_diff:
        payload["delta"] = {
            "score_delta":    getattr(scan_diff, "score_delta", 0),
            "new_issues":     len(getattr(scan_diff, "new_issues", [])),
            "resolved":       len(getattr(scan_diff, "resolved_issues", [])),
        }

    return payload


def _colour_for_score(score: int) -> str:
    if score >= 80:
        return "#2ecc71"   # green
    elif score >= 60:
        return "#f39c12"   # orange
    else:
        return "#e74c3c"   # red


def _send_slack(webhook_url: str, p: Dict[str, Any]) -> bool:
    """Format as Slack Block Kit message."""
    colour  = _colour_for_score(p["score"])
    fails_text = "\n".join(f"• {f}" for f in p["top_fails"]) or "None"

    delta_text = ""
    if "delta" in p:
        d = p["delta"]
        arrow = "▲" if d["score_delta"] > 0 else "▼" if d["score_delta"] < 0 else "→"
        delta_text = (
            f"\n*Trend:* {arrow} {abs(d['score_delta']):.1f} pts | "
            f"+{d['new_issues']} new issues, {d['resolved']} resolved"
        )

    body = {
        "attachments": [{
            "color": colour,
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"Tblue Scan — {p['target']}"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Score:* {p['score']}/100 ({p['grade']})"},
                        {"type": "mrkdwn", "text": f"*Critical:* {p['critical']} | *High:* {p['high']}"},
                        {"type": "mrkdwn", "text": f"*Failed:* {p['failed']} | *Warned:* {p['warned']} | *Passed:* {p['passed']}"},
                        {"type": "mrkdwn", "text": f"*Time:* {p['timestamp'][:19].replace('T', ' ')} UTC"},
                    ],
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Top issues:*\n{fails_text}{delta_text}"},
                },
            ],
        }]
    }

    r = req_lib.post(webhook_url, json=body, timeout=_TIMEOUT)
    success = r.status_code in (200, 204)
    if success:
        logger.info(f"Slack notification sent: {p['target']} score={p['score']}")
    else:
        logger.error(f"Slack notification failed: HTTP {r.status_code}")
    return success


def _send_teams(webhook_url: str, p: Dict[str, Any]) -> bool:
    """Format as Microsoft Teams Adaptive Card (Connector message)."""
    colour_map = {"A": "Good", "B": "Good", "C": "Warning", "D": "Attention", "F": "Attention"}
    colour = colour_map.get(p["grade"], "Warning")
    fails_text = "<br/>".join(f"• {f}" for f in p["top_fails"]) or "None"

    body = {
        "@type":       "MessageCard",
        "@context":    "https://schema.org/extensions",
        "themeColor":  "0076D7",
        "summary":     f"Tblue scan: {p['target']} — {p['score']}/100",
        "sections": [
            {
                "activityTitle": "Tblue Security Scan",
                "activitySubtitle": p["target"],
                "facts": [
                    {"name": "Score",    "value": f"{p['score']}/100 ({p['grade']})"},
                    {"name": "Critical", "value": str(p["critical"])},
                    {"name": "High",     "value": str(p["high"])},
                    {"name": "Failed",   "value": str(p["failed"])},
                    {"name": "Warned",   "value": str(p["warned"])},
                    {"name": "Passed",   "value": str(p["passed"])},
                    {"name": "Time",     "value": p["timestamp"][:19].replace("T", " ") + " UTC"},
                ],
                "text": f"**Top issues:**<br/>{fails_text}",
                "markdown": True,
            }
        ],
    }

    r = req_lib.post(webhook_url, json=body, timeout=_TIMEOUT)
    success = r.status_code in (200, 204)
    if success:
        logger.info(f"Teams notification sent: {p['target']} score={p['score']}")
    else:
        logger.error(f"Teams notification failed: HTTP {r.status_code}")
    return success


def _send_discord(webhook_url: str, p: Dict[str, Any]) -> bool:
    """Format as Discord embed."""
    colour_int = 0x2ecc71 if p["score"] >= 80 else 0xf39c12 if p["score"] >= 60 else 0xe74c3c
    fails_text = "\n".join(f"• {f}" for f in p["top_fails"]) or "None"

    body = {
        "embeds": [{
            "title":       f"Tblue: {p['target']}",
            "color":       colour_int,
            "description": f"Security score: **{p['score']}/100 ({p['grade']})**",
            "fields": [
                {"name": "Critical / High", "value": f"{p['critical']} / {p['high']}", "inline": True},
                {"name": "Failed / Warned", "value": f"{p['failed']} / {p['warned']}", "inline": True},
                {"name": "Passed",          "value": str(p["passed"]),                  "inline": True},
                {"name": "Top issues",      "value": fails_text,                        "inline": False},
            ],
            "footer": {"text": f"Tblue • {p['timestamp'][:19].replace('T', ' ')} UTC"},
        }]
    }

    r = req_lib.post(webhook_url, json=body, timeout=_TIMEOUT)
    success = r.status_code in (200, 204)
    if success:
        logger.info(f"Discord notification sent: {p['target']} score={p['score']}")
    else:
        logger.error(f"Discord notification failed: HTTP {r.status_code}")
    return success


def _send_generic(webhook_url: str, p: Dict[str, Any]) -> bool:
    """Generic JSON POST."""
    r = req_lib.post(
        webhook_url,
        data=json.dumps(p),
        headers={"Content-Type": "application/json"},
        timeout=_TIMEOUT,
    )
    success = r.status_code < 400
    if success:
        logger.info(f"Webhook notification sent: {p['target']} score={p['score']}")
    else:
        logger.error(f"Webhook notification failed: HTTP {r.status_code}")
    return success
