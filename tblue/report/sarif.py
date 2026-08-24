"""
SARIF 2.1.0 report generator.

SARIF (Static Analysis Results Interchange Format) is the GitHub-standard
output format for security tools. When uploaded as a GitHub Actions artifact
(upload-sarif), findings appear inline on PRs and in the Security tab.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json
from datetime import datetime, timezone
from typing import Dict, List

from tblue import __version__
from tblue.scoring import classify_severity

_SCHEMA  = "https://json.schemastore.org/sarif-2.1.0.json"
_TOOL_URI = "https://github.com/taylannuhogluofficial-png/Tblue"

# Map our severity levels to SARIF levels
_SARIF_LEVEL = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "none",
}

# Map our severity to SARIF security-severity score (for GitHub)
_SARIF_SEC_SCORE = {
    "critical": "9.8",
    "high":     "7.5",
    "medium":   "5.0",
    "low":      "3.0",
    "info":     "0.0",
}


def generate(target: str, all_results: Dict[str, List], output_path: str,
             scan_score=None) -> None:
    """Write a SARIF 2.1.0 file from scan results."""

    rules: Dict[str, dict] = {}
    results: List[dict]    = []

    for module, module_results in all_results.items():
        for r in module_results:
            status  = r.get("status", "PASS")
            rtype   = r.get("type", "unknown")
            detail  = r.get("detail", "")
            url     = r.get("url", target)
            sev     = classify_severity(rtype, status)

            rule_id = _make_rule_id(rtype)

            # Register rule if new
            if rule_id not in rules:
                rules[rule_id] = _make_rule(rule_id, rtype, detail, sev)

            # Only emit FAIL/WARN as findings; PASS = no finding
            if status not in ("FAIL", "WARN"):
                continue

            results.append(_make_result(rule_id, rtype, detail, url, status, sev))

    sarif = {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name":             "Tblue",
                    "version":          __version__,
                    "informationUri":   _TOOL_URI,
                    "rules":            list(rules.values()),
                }
            },
            "invocations": [{
                "executionSuccessful": True,
                "commandLine":         f"tblue -u {target}",
                "endTimeUtc":          datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }],
            "results": results,
            "properties": {
                "score":  scan_score.score if scan_score else None,
                "grade":  scan_score.grade if scan_score else None,
                "target": target,
            },
        }]
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)


def _make_rule_id(rtype: str) -> str:
    """Convert a result type string to a stable rule ID slug."""
    slug = rtype.lower()
    for ch in " /—–-.,()[]{}":
        slug = slug.replace(ch, "_")
    slug = "TB_" + slug.strip("_").upper()
    # Truncate to keep IDs readable
    return slug[:60]


def _make_rule(rule_id: str, rtype: str, detail: str, severity: str) -> dict:
    sec_score = _SARIF_SEC_SCORE.get(severity, "0.0")
    return {
        "id":   rule_id,
        "name": _pascal(rtype),
        "shortDescription": {"text": rtype},
        "fullDescription":  {"text": detail[:500] if detail else rtype},
        "helpUri": _TOOL_URI,
        "properties": {
            "tags":              ["security", severity],
            "security-severity": sec_score,
        },
        "defaultConfiguration": {
            "level": _SARIF_LEVEL.get(severity, "warning"),
        },
    }


def _make_result(rule_id: str, rtype: str, detail: str, url: str,
                 status: str, severity: str) -> dict:
    level = _SARIF_LEVEL.get(severity, "warning")
    if status == "WARN" and level == "error":
        level = "warning"

    return {
        "ruleId":  rule_id,
        "level":   level,
        "message": {"text": detail or rtype},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri":      url,
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {"startLine": 1},
            }
        }],
        "properties": {
            "security-severity": _SARIF_SEC_SCORE.get(severity, "0.0"),
            "status":  status,
            "module":  rule_id,
        },
    }


def _pascal(s: str) -> str:
    """Convert 'foo — bar baz' to 'FooBarBaz'."""
    return "".join(w.capitalize() for w in s.replace("—", " ").replace("-", " ").split())
