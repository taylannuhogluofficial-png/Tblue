"""
KQL (Kusto Query Language) Export for Microsoft Sentinel.

Generates Microsoft Sentinel / Azure Monitor KQL analytics rules from
Tblue findings. Each FAIL/WARN finding becomes a Sentinel Scheduled
Analytics Rule expressed in KQL.

Output format: JSON with KQL rule definitions suitable for Sentinel ARM template.
"""

import re
import json
import datetime
import hashlib
from pathlib import Path
from typing import Dict, List

_KQL_TEMPLATES: List[tuple] = [
    (r"xss|cross.site.script", (
        "W3CIISLog\n"
        "| where csUriStem contains \"<script\" or csUriStem contains \"javascript:\"\n"
        "| summarize Count=count() by cIP, csUriStem, _TimeRange\n"
        "| where Count > 5"
    )),
    (r"nosql|mongodb", (
        "AppServiceHTTPLogs\n"
        "| where Result contains \"MongoError\" or Result contains \"MongooseError\"\n"
        "| summarize Count=count() by CIp, ScStatus, TimeGenerated\n"
        "| where Count > 1"
    )),
    (r"ssrf|metadata|169\.254", (
        "W3CIISLog\n"
        "| where csUriStem contains \"169.254.169.254\" or csUriStem contains \"metadata.google\"\n"
        "| project TimeGenerated, cIP, csUriStem, scStatus"
    )),
    (r"jwt.*none|jwt.*algorithm", (
        "AppServiceHTTPLogs\n"
        "| where Message contains \"alg\":\"none\" or Message contains \"invalid token\"\n"
        "| summarize Count=count() by CIp, TimeGenerated\n"
        "| where Count > 3"
    )),
    (r"path.*traversal|lfi", (
        "W3CIISLog\n"
        "| where csUriStem contains \"../\" or csUriStem contains \"%2e%2e%2f\"\n"
        "| summarize Count=count() by cIP, csUriStem\n"
        "| where Count > 2"
    )),
    (r"brute.force|auth.*fail|login.*fail", (
        "SigninLogs\n"
        "| where ResultType != 0\n"
        "| summarize FailureCount=count() by IPAddress, UserPrincipalName, bin(TimeGenerated, 5m)\n"
        "| where FailureCount > 10"
    )),
    (r"information.*disclosure|stack.*trace|debug", (
        "AppServiceHTTPLogs\n"
        "| where Result contains \"Exception\" or Result contains \"stack trace\"\n"
        "| project TimeGenerated, CIp, ScStatus, CsUriStem"
    )),
    (r"cors.*wildcard|cors.*origin", (
        "W3CIISLog\n"
        "| where csReferrer != \"\" and scStatus in (200, 201)\n"
        "| where csUriStem matches regex @\"api|graphql|rest\"\n"
        "| summarize Count=count() by cIP, csReferrer\n"
        "| where Count > 5"
    )),
    (r"cloud.*metadata|k8s|kubernetes", (
        "AzureActivity\n"
        "| where OperationName contains \"secret\" or OperationName contains \"key\"\n"
        "| where ActivityStatus == \"Success\"\n"
        "| project TimeGenerated, Caller, OperationName, ResourceGroup"
    )),
    (r"admin.*exposed|actuator.*exposed|management", (
        "W3CIISLog\n"
        "| where csUriStem contains \"/admin\" or csUriStem contains \"/actuator\"\n"
        "| where scStatus == 200\n"
        "| summarize Count=count() by cIP, csUriStem"
    )),
]

_DEFAULT_KQL = (
    "W3CIISLog\n"
    "| where csUriStem contains \"{path}\"\n"
    "| summarize Count=count() by cIP, csUriStem\n"
    "| where Count > 5"
)


def _kql_for_finding(finding_type: str, url: str) -> str:
    needle = finding_type.lower()
    from urllib.parse import urlparse
    path = urlparse(url).path or "/"

    for pattern, kql in _KQL_TEMPLATES:
        if re.search(pattern, needle, re.I):
            return kql

    return _DEFAULT_KQL.replace("{path}", path[:40])


def _rule_id(finding_type: str) -> str:
    h = hashlib.sha256(finding_type.encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def generate(target: str, all_results: Dict[str, List], output_path: str,
             scan_score=None) -> None:
    """Generate Microsoft Sentinel KQL analytics rules from scan findings."""
    rules = []
    seen: set = set()

    for module_name, findings in all_results.items():
        for finding in findings:
            status = finding.get("status", "")
            if status not in ("FAIL", "WARN"):
                continue

            finding_type = finding.get("type", "")
            if finding_type in seen:
                continue
            seen.add(finding_type)

            kql = _kql_for_finding(finding_type, finding.get("url", target))

            severity_map = {"FAIL": "High", "WARN": "Medium"}

            rule = {
                "id": _rule_id(finding_type),
                "name": f"Tblue: {finding_type[:100]}",
                "description": finding.get("detail", finding_type)[:500],
                "severity": severity_map.get(status, "Medium"),
                "enabled": True,
                "query": kql,
                "queryFrequency": "PT1H",
                "queryPeriod": "PT1H",
                "triggerOperator": "GreaterThan",
                "triggerThreshold": 0,
                "suppressionDuration": "PT5H",
                "suppressionEnabled": False,
                "tactics": ["InitialAccess", "Discovery"],
                "kind": "Scheduled",
                "metadata": {
                    "tblue_target": target,
                    "tblue_module": module_name,
                    "tblue_status": status,
                    "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                }
            }
            rules.append(rule)

    output_data = {
        "schema": "tblue-sentinel-rules-v1",
        "target": target,
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "score": scan_score.score if scan_score else None,
        "rule_count": len(rules),
        "rules": rules,
    }

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(output_data, indent=2))
