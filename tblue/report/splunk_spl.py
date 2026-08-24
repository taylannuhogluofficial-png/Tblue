"""
Splunk SPL (Search Processing Language) Correlation Rules Export.

Generates Splunk SPL search queries from Tblue findings for use in:
  - Splunk Security Essentials
  - Splunk SOAR playbooks
  - Scheduled alert searches

Each FAIL/WARN finding becomes a correlation search that detects
patterns associated with the vulnerability being exploited.
"""

import re
import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Splunk search components per finding category
_SPL_TEMPLATES: List[tuple] = [
    (r"xss|cross.site.script", (
        'index=web_logs OR index=access_logs '
        '(uri="*<script*" OR uri="*javascript:*" OR uri="*onerror=*" OR uri="*onload=*") '
        '| eval risk="XSS" '
        '| stats count by src_ip, uri, http_method '
        '| where count > 5'
    )),
    # Must be before sql.injection since "NoSQL" contains "sql"
    (r"nosql|mongodb|couchdb", (
        'index=app_logs '
        '(message="MongoError*" OR message="MongoServerError*" OR message="E11000*") '
        '| eval risk="NoSQL" '
        '| stats count by host, source '
        '| where count > 1'
    )),
    (r"sql.injection|sqli", (
        'index=web_logs OR index=db_logs '
        "(uri=\"*' OR '1'='1*\" OR uri=\"*UNION SELECT*\" OR uri=\"*DROP TABLE*\") "
        '| eval risk="SQLi" '
        '| stats count by src_ip, uri '
        '| where count > 3'
    )),
    (r"nosql|mongodb|couchdb", (
        'index=app_logs '
        '(message="MongoError*" OR message="MongoServerError*" OR message="E11000*") '
        '| eval risk="NoSQL" '
        '| stats count by host, source '
        '| where count > 1'
    )),
    (r"auth.bypass|unauthorized|403|401", (
        'index=web_logs status IN (401, 403) '
        '| bucket _time span=5m '
        '| stats count by src_ip, _time '
        '| where count > 20 '
        '| eval risk="Auth_Bypass_Attempt"'
    )),
    (r"jwt.*none|jwt.*algorithm", (
        'index=app_logs '
        '(message="*alg*none*" OR message="*invalid token*" OR message="*jwt*") '
        '| eval risk="JWT_Attack" '
        '| stats count by src_ip, user '
        '| where count > 5'
    )),
    (r"ssrf|server.side.request.forgery|metadata", (
        'index=web_logs '
        '(uri="*169.254.169.254*" OR uri="*metadata.google*" OR uri="*/latest/meta-data/*") '
        '| eval risk="SSRF" '
        '| stats count by src_ip, uri '
        '| where count > 1'
    )),
    (r"directory.*listing|exposed.*directory", (
        'index=web_logs '
        '(uri="*Index of /*" OR uri="*Parent Directory*") '
        '| eval risk="Directory_Listing" '
        '| stats count by src_ip, uri'
    )),
    (r"path.*traversal|lfi|local.*file.*inclusion", (
        'index=web_logs '
        '(uri="*../*" OR uri="*..\\\\*" OR uri="*%2e%2e%2f*" OR uri="*/etc/passwd*") '
        '| eval risk="Path_Traversal" '
        '| stats count by src_ip, uri '
        '| where count > 2'
    )),
    (r"cors.*advanced|cors.*wildcard|cors.*origin", (
        'index=web_logs '
        'http_response_headers="*Access-Control-Allow-Origin: \\**" '
        '| eval risk="CORS_Wildcard" '
        '| stats count by uri, src_ip'
    )),
    (r"information.*disclosure|sensitive.*info|stack.*trace", (
        'index=web_logs '
        '(body="*Exception*" OR body="*stack trace*" OR body="*at com.*" OR body="*NullPointerException*") '
        '| eval risk="Info_Disclosure" '
        '| stats count by uri, src_ip'
    )),
]

_DEFAULT_SPL = (
    'index=web_logs OR index=access_logs '
    '| search uri="{path}" '
    '| stats count by src_ip, uri, status '
    '| where count > 10'
)


def _spl_for_finding(finding_type: str, url: str) -> str:
    """Return the most appropriate SPL query for this finding type."""
    needle = finding_type.lower()
    from urllib.parse import urlparse
    path = urlparse(url).path or "/"

    for pattern, spl in _SPL_TEMPLATES:
        if re.search(pattern, needle, re.I):
            return spl

    # Generic fallback
    return _DEFAULT_SPL.replace("{path}", path[:50])


def generate(target: str, all_results: Dict[str, List], output_path: str,
             scan_score=None) -> None:
    """Generate Splunk SPL correlation searches from scan findings."""
    lines = [
        f"# Tblue Splunk SPL Correlation Rules",
        f"# Target: {target}",
        f"# Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}",
        f"# Score: {scan_score.score if scan_score else 'N/A'}",
        f"",
        f"# ====================================================================",
        f"# INSTRUCTIONS: Import into Splunk > Settings > Searches, Reports, Alerts",
        f"# ====================================================================",
        f"",
    ]

    seen: set = set()
    rule_num = 0

    for module_name, findings in all_results.items():
        for finding in findings:
            status = finding.get("status", "")
            if status not in ("FAIL", "WARN"):
                continue

            finding_type = finding.get("type", "")
            spl_key = re.sub(r"[^a-z0-9]", "_", finding_type.lower())[:40]

            if spl_key in seen:
                continue
            seen.add(spl_key)
            rule_num += 1

            spl = _spl_for_finding(finding_type, finding.get("url", target))

            lines.append(f"# ── Rule {rule_num}: {finding_type[:80]} ──")
            lines.append(f"# Status: {status} | Module: {module_name}")
            lines.append(f"# SPL Search:")
            lines.append(spl)
            lines.append("")

    if rule_num == 0:
        lines.append("# No FAIL/WARN findings — no correlation rules generated")

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines))
