"""
Proof-of-Concept (PoC) report generator.

For each FAIL/WARN finding, generates a safe, read-only curl command or
test snippet that a defender can run to confirm the issue is real and
verify it after remediation. No attack payloads — all requests are
equivalent to what a browser normally sends.
"""

import json
import shlex
from datetime import datetime, timezone
from typing import Dict, List, Any
from urllib.parse import urlparse

from tblue import __version__

# (finding_type_prefix, curl_template, description)
# {url} = finding URL, {host} = hostname
_POC_TEMPLATES: List[tuple] = [
    # TLS / HTTPS
    ("pci_4_2_1_no_tls",
     "curl -v --max-time 5 http://{host}/",
     "Confirm page is reachable over plain HTTP (should redirect to HTTPS)."),

    ("nist_pr_aa02_no_tls",
     "curl -v --max-time 5 http://{host}/",
     "Confirm HTTP is reachable — should return 301/302 to HTTPS."),

    # HSTS
    ("pci_8_2_no_hsts",
     "curl -sI https://{host}/ | grep -i strict",
     "Confirm Strict-Transport-Security header is absent."),

    ("hipaa_312_e2i_no_hsts",
     "curl -sI https://{host}/ | grep -i strict",
     "Confirm HSTS header absent on HTTPS page."),

    # CSP
    ("pci_6_4_1_no_csp",
     "curl -sI https://{host}/ | grep -i content-security-policy",
     "Confirm Content-Security-Policy header is absent."),

    # Clickjacking
    ("pci_6_3_2_no_frame_protection",
     "curl -sI {url} | grep -iE 'x-frame-options|content-security-policy'",
     "Confirm no clickjacking protection header present."),

    # XFO
    ("soc2_cc6_6_no_frame_protection",
     "curl -sI {url} | grep -iE 'x-frame-options|frame-ancestors'",
     "Confirm no frame protection on page."),

    # CORS
    ("cors_origin_reflection",
     "curl -sI -H 'Origin: https://evil.example.com' {url} | grep -i access-control",
     "Check if server reflects arbitrary Origin in Access-Control-Allow-Origin."),

    ("cors_wildcard_api",
     "curl -sI -H 'Origin: https://evil.example.com' {url} | grep -i 'access-control-allow-origin'",
     "Confirm wildcard CORS on API endpoint."),

    ("cors_null_origin",
     "curl -sI -H 'Origin: null' {url} | grep -i access-control",
     "Check if server accepts null Origin (sandbox iframe bypass)."),

    # Security headers
    ("nist_pr_ps01_no_xcto",
     "curl -sI {url} | grep -i x-content-type-options",
     "Confirm X-Content-Type-Options: nosniff is absent."),

    # Host header injection
    ("host_header_injection",
     "curl -sI -H 'Host: evil.example.com' -H 'X-Forwarded-Host: evil.example.com' {url}",
     "Check if injected Host/X-Forwarded-Host is reflected in response."),

    # Open redirect
    ("open_redirect",
     "curl -sI {url_redirect} | grep -i location",
     "Confirm redirect parameter forwards to external URL."),

    ("open_redirect_deep",
     "curl -sI {url_next} | grep -i location",
     "Confirm protocol-relative redirect not validated."),

    # Sensitive data
    ("nist_pr_ir01_credential_exposure",
     "curl -s {url} | grep -oE 'AKIA[0-9A-Z]{16}'",
     "Confirm AWS key pattern in response body."),

    ("hardcoded_credentials",
     "curl -s {url} | grep -iE '(api_key|secret|password)\\s*[:=]'",
     "Check for hardcoded credential patterns in page source."),

    # Error disclosure
    ("soc2_cc7_1_error_disclosure",
     "curl -s {url} | grep -iE '(Traceback|stack trace|ORA-[0-9]{{5}}|SQLSTATE)'",
     "Confirm error/stack trace visible in response."),

    ("debug_endpoint_exposure",
     "curl -sI {url}/debug | grep -i 'content-type\\|x-debug'",
     "Probe debug endpoint for HTTP 200 response."),

    # Version disclosure
    ("soc2_cc8_1_version_disclosure",
     "curl -sI {url} | grep -iE '^(server|x-powered-by):'",
     "Confirm version string in Server or X-Powered-By header."),

    # Directory listing
    ("directory_listing",
     "curl -s {url}/ | grep -iE '(index of|parent directory|\\[dir\\])'",
     "Check if directory listing is enabled (Index Of pattern)."),

    # GraphQL introspection
    ("graphql_info_disclosure",
     "curl -s -X POST -H 'Content-Type: application/json' "
     "-d '{\"query\":\"{__schema{types{name}}}\"}' {url}/graphql",
     "Confirm GraphQL introspection is enabled without auth."),

    ("introspection_disclosure",
     "curl -sI {url}/actuator | grep -i 'content-type'",
     "Check Actuator endpoint accessibility."),

    # JWT
    ("jwt_algorithm_confusion",
     "curl -s {url} | grep -oE 'eyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+'",
     "Extract JWT from page to inspect algorithm header."),

    # Source maps
    ("sourcemap_exposure",
     "curl -sI {url}/main.js.map | grep 'HTTP/'",
     "Check if JS source map file is publicly accessible."),

    # SSRF params
    ("ssrf_params",
     "curl -s {url_ssrf} | head -5",
     "Probe SSRF-prone URL parameter with cloud metadata URL."),

    # File upload
    ("file_upload_security",
     "curl -sI -X OPTIONS {url} | grep -i allow",
     "Check allowed HTTP methods on file upload endpoint."),

    # Subdomain takeover
    ("subdomain_takeover",
     "curl -sI {url} | head -5",
     "Confirm unclaimed page fingerprint in response."),

    # Admin exposure
    ("admin_exposure",
     "curl -sI {url}/admin | grep 'HTTP/'",
     "Check HTTP status of admin panel path."),

    # Sensitive endpoints
    ("health_endpoint_exposure",
     "curl -s {url}/actuator/health | python3 -m json.tool 2>/dev/null | head -20",
     "Confirm health endpoint returns internal status without auth."),

    ("actuator_endpoint_exposure",
     "curl -s {url}/actuator | python3 -m json.tool 2>/dev/null | head -20",
     "Confirm Spring Boot Actuator _links exposed without auth."),

    # Cloud storage
    ("open_s3_bucket",
     "curl -s 'https://{host}.s3.amazonaws.com/?list-type=2' | grep -i Key",
     "Confirm S3 bucket is publicly listable."),

    # Docker/K8s
    ("docker_exposure",
     "curl -s {url}:2375/version | python3 -m json.tool 2>/dev/null",
     "Probe Docker daemon API for unauthenticated access."),

    ("k8s_exposure",
     "curl -sk https://{host}:6443/api/v1/namespaces | python3 -m json.tool 2>/dev/null | head -5",
     "Probe Kubernetes API server for unauthenticated namespace listing."),

    # Polyfill supply chain
    ("polyfill_sc_cdn_polyfill_io",
     "curl -s {url} | grep -o 'cdn\\.polyfill\\.io[^\"]*'",
     "Confirm reference to compromised cdn.polyfill.io domain in page source."),

    # SBOM
    ("sbom_manifest_exposed",
     "curl -s {url}/package.json | python3 -m json.tool 2>/dev/null | head -20",
     "Confirm package.json is publicly readable."),

    # Session
    ("session_entropy_passive",
     "curl -sI {url} | grep -i set-cookie",
     "Inspect session cookie length and format."),

    # Compliance
    ("pci_3_3_1_card_number_exposed",
     "curl -s {url} | grep -oE '[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}'",
     "Confirm PAN (card number) visible in page response."),

    ("hipaa_312_a2iv_ssn_exposed",
     "curl -s {url} | grep -oE '[0-9]{3}-[0-9]{2}-[0-9]{4}'",
     "Confirm SSN pattern visible in page response."),
]


def _find_template(finding_type: str) -> tuple:
    for prefix, template, desc in _POC_TEMPLATES:
        if finding_type == prefix or finding_type.startswith(prefix.split("_")[0]):
            return template, desc
    return (
        "curl -sI {url}",
        "Generic connectivity check — examine response headers and body for the flagged condition."
    )


def generate(target: str, all_results: Dict[str, List[Any]], output_path: str,
             scan_score: Any = None) -> None:
    """Generate PoC curl commands for all FAIL/WARN findings."""

    parsed  = urlparse(target)
    host    = parsed.netloc.split(":")[0]
    pocs    = []
    seen    = set()

    flat = [r for findings in all_results.values() for r in findings
            if r.get("status", "PASS").upper() in ("FAIL", "WARN")]

    for finding in flat:
        ftype    = finding.get("type", "unknown")
        severity = finding.get("status", "WARN")
        url      = finding.get("url", target)
        detail   = finding.get("detail", "")

        if ftype in seen:
            continue
        seen.add(ftype)

        template, description = _find_template(ftype)
        # Findings carry attacker-influenceable URLs (redirects, crawled links).
        # Shell-quote every substituted value so a copy-pasted PoC cannot inject
        # shell metacharacters into the user's terminal.
        command = template.format(
            url          = shlex.quote(url),
            host         = shlex.quote(host),
            url_redirect = shlex.quote(f"{url}?redirect=https://evil.example.com"),
            url_next     = shlex.quote(f"{url}?next=//evil.example.com"),
            url_ssrf     = shlex.quote(f"{url}?url=http://169.254.169.254/latest/meta-data/"),
        )

        pocs.append({
            "finding_type": ftype,
            "severity":     severity,
            "url":          url,
            "description":  description,
            "poc_command":  command,
            "detail_excerpt": detail[:150],
        })

    output = {
        "schema":    "Tblue Proof-of-Concept Report",
        "tool":      f"Tblue {__version__}",
        "target":    target,
        "generated": datetime.now(timezone.utc).isoformat(),
        "score":     scan_score,
        "poc_count": len(pocs),
        "pocs":      sorted(pocs, key=lambda x: {"FAIL": 0, "WARN": 1}.get(x["severity"], 2)),
    }

    json_path = output_path if output_path.endswith(".json") else output_path + ".json"
    md_path   = json_path.replace(".json", ".md")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# Tblue — Proof of Concept Commands\n\n")
        f.write(f"**Target:** {target}  \n")
        f.write(f"**Generated:** {output['generated']}  \n")
        f.write(f"**Findings with PoC:** {len(pocs)}  \n\n")
        f.write("> All commands are read-only. No attack payloads.\n\n---\n\n")

        for poc in output["pocs"]:
            f.write(f"### `{poc['finding_type']}` — {poc['severity']}\n\n")
            f.write(f"{poc['description']}\n\n")
            if poc["detail_excerpt"]:
                f.write(f"> {poc['detail_excerpt']}\n\n")
            f.write(f"```bash\n{poc['poc_command']}\n```\n\n")
