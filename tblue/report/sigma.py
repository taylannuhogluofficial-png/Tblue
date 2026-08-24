"""
Sigma Rules Export for Tblue Findings.

Exports scan findings as Sigma detection rules (YAML) for SIEM ingestion:
  - Splunk, Elastic SIEM, Microsoft Sentinel, QRadar, etc.

Each FAIL/WARN finding becomes a Sigma rule with:
  - detection logic based on finding type
  - logsource (web, application)
  - tags (MITRE ATT&CK, OWASP)

Reference: https://github.com/SigmaHQ/sigma
"""

import re
import yaml
import hashlib
import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


# Sigma logsource mapping per finding type
_LOGSOURCE_MAP = {
    r"xss|dom|csp|content.security": {
        "category": "webserver", "product": "any"
    },
    r"sql|nosql|injection": {
        "category": "application", "product": "any"
    },
    r"ssl|tls|certificate": {
        "category": "network", "product": "any"
    },
    r"auth|login|session|jwt|oauth|saml": {
        "category": "authentication", "product": "any"
    },
    r"header|response|cors|mixed|csp": {
        "category": "webserver", "product": "any"
    },
    r"cloud|metadata|ssrf|k8s|kubernetes": {
        "category": "cloud", "product": "aws"
    },
    r"scim|grpc|api|graphql": {
        "category": "application", "product": "any"
    },
    r"dns|subdomain": {
        "category": "dns", "product": "any"
    },
}

_DEFAULT_LOGSOURCE = {"category": "webserver", "product": "any"}

# OWASP tag mapping
_OWASP_TAGS = {
    "A01": "OWASP/A01:2021-Broken-Access-Control",
    "A02": "OWASP/A02:2021-Cryptographic-Failures",
    "A03": "OWASP/A03:2021-Injection",
    "A04": "OWASP/A04:2021-Insecure-Design",
    "A05": "OWASP/A05:2021-Security-Misconfiguration",
    "A06": "OWASP/A06:2021-Vulnerable-and-Outdated-Components",
    "A07": "OWASP/A07:2021-Identification-and-Authentication-Failures",
    "A08": "OWASP/A08:2021-Software-and-Data-Integrity-Failures",
    "A09": "OWASP/A09:2021-Security-Logging-and-Monitoring-Failures",
    "A10": "OWASP/A10:2021-SSRF",
}


def _logsource_for(finding_type: str) -> Dict[str, str]:
    needle = finding_type.lower()
    for pattern, ls in _LOGSOURCE_MAP.items():
        if re.search(pattern, needle):
            return ls
    return _DEFAULT_LOGSOURCE


def _severity_for_status(status: str) -> str:
    return {"FAIL": "high", "WARN": "medium"}.get(status, "informational")


def _rule_id(finding_type: str, url: str) -> str:
    raw = f"{finding_type}:{url}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    parts = [h[:4], h[4:8], "0000", "0000", h]
    return "-".join(parts[:5])[:36]


def _sanitize_title(finding_type: str) -> str:
    title = re.sub(r"\s+", " ", finding_type).strip()
    if len(title) > 100:
        title = title[:97] + "..."
    return title


def _finding_to_rule(finding: Dict[str, Any], target: str) -> Optional[Dict[str, Any]]:
    """Convert a single finding to a Sigma rule dict."""
    status = finding.get("status", "")
    if status not in ("FAIL", "WARN"):
        return None

    finding_type = finding.get("type", "Unknown finding")
    url = finding.get("url", target)
    detail = finding.get("detail", "")

    # Build detection — use URL path and finding type keyword as indicators
    from urllib.parse import urlparse
    parsed = urlparse(url)
    path = parsed.path or "/"

    # Extract keywords from finding type for detection
    keywords = [w for w in re.split(r"[^\w]+", finding_type.lower()) if len(w) > 3][:5]

    detection_keywords = list(set(keywords))

    # Build tags from finding metadata
    tags = []
    compliance = finding.get("compliance", {})
    for owasp_id in compliance.get("owasp", []):
        if owasp_id in _OWASP_TAGS:
            tags.append(_OWASP_TAGS[owasp_id])
    for tech in finding.get("mitre_techniques", []):
        tid = tech.get("id", "")
        if tid:
            tags.append(f"attack.{tid.lower().replace('.', '_')}")

    logsource = _logsource_for(finding_type)

    rule = {
        "title": f"Tblue: {_sanitize_title(finding_type)}",
        "id": _rule_id(finding_type, url),
        "status": "experimental",
        "description": detail[:500] if detail else f"{finding_type} detected by Tblue",
        "references": [f"https://owasp.org/Top10/"],
        "author": "Tblue (auto-generated)",
        "date": datetime.date.today().isoformat(),
        "modified": datetime.date.today().isoformat(),
        "tags": tags if tags else ["attack.t1190"],
        "logsource": logsource,
        "detection": {
            "keywords": detection_keywords if detection_keywords else ["error"],
            "condition": "keywords",
        },
        "fields": ["cs-uri-stem", "c-ip", "cs-method", "sc-status"],
        "falsepositives": ["Legitimate security scanning"],
        "level": _severity_for_status(status),
        "custom": {
            "tblue_status": status,
            "tblue_target": target,
            "tblue_url": url,
        },
    }

    return rule


def generate(target: str, all_results: Dict[str, List], output_path: str,
             scan_score=None) -> None:
    """Generate a Sigma rules bundle (.yaml) from scan findings."""
    rules = []
    seen_ids = set()

    for module_name, findings in all_results.items():
        for finding in findings:
            rule = _finding_to_rule(finding, target)
            if not rule:
                continue
            rule_id = rule["id"]
            if rule_id in seen_ids:
                continue
            seen_ids.add(rule_id)
            rules.append(rule)

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w") as f:
        for i, rule in enumerate(rules):
            if i > 0:
                f.write("---\n")
            yaml.dump(rule, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
