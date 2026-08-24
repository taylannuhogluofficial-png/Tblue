"""
STRIDE Threat Model report generator.

Consumes scan findings and produces a structured STRIDE threat model:
  Spoofing, Tampering, Repudiation, Information Disclosure,
  Denial of Service, Elevation of Privilege

Output formats: JSON (machine) and Markdown (human).
"""

import json
from datetime import datetime, timezone
from typing import Dict, List, Any

from tblue import __version__

# Maps finding types to STRIDE categories
_STRIDE_MAP: Dict[str, List[str]] = {
    # Spoofing — attacker impersonates a user or system
    "S": [
        "xss", "csrf", "cors", "host_header", "host_header_injection",
        "open_redirect", "open_redirect_deep", "client_side_redirect",
        "session_fixation", "session_fixation_passive", "saml", "saml_passive",
        "oauth", "oauth_advanced", "oauth_implicit_flow", "oauth_pkce",
        "social_login_security", "jwt", "jwt_advanced", "jwt_algorithm_confusion",
        "phishing", "subdomain_takeover", "subdomain_takeover_passive",
        "typosquatting", "dns_rebinding", "dns_rebinding_passive",
        "tabnabbing", "tabnapping_passive", "form_action_hijacking",
        "link_injection_passive", "magic_link_security",
    ],
    # Tampering — attacker modifies data or code
    "T": [
        "sql_error_passive", "command_injection", "xxe_injection", "xxe_passive",
        "xml_xxe", "ssti", "csti", "el_injection", "ldap_injection",
        "ldap_injection_passive", "nosql_injection", "nosql_injection_advanced",
        "path_traversal", "path_traversal_deep", "file_inclusion",
        "deserialization", "deserialization_gadget_passive",
        "insecure_deserialization_passive", "prototype_pollution",
        "javascript_prototype_pollution_deep", "javascript_prototype_chain",
        "parameter_pollution", "parameter_pollution_passive",
        "http_parameter_pollution", "path_parameter_pollution",
        "zip_slip_passive", "mass_assignment", "mass_assignment_security",
        "content_injection", "css_injection", "css_injection_passive",
        "srcdoc_injection", "mutation_xss", "trojan_source",
        "import_map_security", "importmap_security", "polyfill_supply_chain",
        "supply_chain", "supply_chain_lockfile", "js_supply_chain_integrity",
        "dependency_confusion", "dependency_hijacking",
    ],
    # Repudiation — attacker denies an action occurred
    "R": [
        "log_injection", "log_injection_passive", "audit_log",
        "security_txt", "security_txt_deep", "nel_reporting",
        "reporting_api_security",
    ],
    # Information Disclosure — attacker reads unauthorized data
    "I": [
        "info", "error_pages", "secret_in_error_page", "html_comments",
        "exposure", "hardcoded_credentials", "credential_exposure",
        "js_secrets", "api_key_in_js", "api_key_rotation",
        "jwt_token_exposure", "token_exposure_passive", "session_token_exposure",
        "sensitive_params", "sensitive_data_exposure", "insecure_data_exposure",
        "phi_exposure", "pii", "gdpr", "gdpr_privacy",
        "server_timing", "server_timing_disclosure", "server_info_deep",
        "etag_fingerprinting", "canvas_fingerprinting",
        "source_map", "source_map_exposure", "sourcemap_exposure",
        "dev_artifact", "exposed_backup_files", "robots_txt",
        "directory_listing", "dir_listing", "apache_status_exposure",
        "actuator_endpoint_exposure", "spring_actuator", "health_endpoint_exposure",
        "debug_mode_detection", "debug_endpoint_exposure", "introspection_disclosure",
        "graphql_info_disclosure", "graphql_field_suggestion",
        "sbom", "sca", "version_cve", "live_cve", "cms",
        "cloud_metadata", "cloud_storage", "open_s3_bucket",
        "k8s_exposure", "docker_exposure", "cicd_exposure", "serverless_exposure",
        "open_graph_exposure", "link_preview_exposure", "webrtc_exposure",
        "cors_origin_reflection", "cors_deep_analysis",
        "certificate_transparency", "crt_sh", "exif_metadata_exposure",
        "xsleak", "timing_oracle", "timing_attack_passive",
        "compression_oracle", "xssi", "jsonp_endpoint",
        "local_storage_sensitive", "client_storage", "browser_storage",
        "hipaa_compliance", "pci_dss_compliance",
    ],
    # Denial of Service — attacker disrupts availability
    "D": [
        "rate_limit", "rate_limiting", "rate_limiting_detection", "api_rate_limit_deep",
        "graphql_depth", "graphql_batching", "graphql_batch_abuse", "graphql_batch_attack",
        "http2_rapid_reset", "http2_security", "redos_passive",
        "integer_overflow_passive", "race_condition", "race_condition_passive",
        "web_locks_security", "scheduler_api_security",
        "vibration_api_security", "screen_wake_lock_security",
    ],
    # Elevation of Privilege — attacker gains elevated access
    "E": [
        "access_control", "admin_exposure", "idor_detection",
        "broken_object_level_auth", "insecure_direct_object_reference",
        "mass_assignment", "business_logic", "business_logic_exposure",
        "file_upload", "file_upload_security",
        "ssrf_params", "ssrf_advanced", "ssrf_passive", "ssrf_detection",
        "path_normalization_security", "nginx_alias_traversal",
        "http_method_override", "http_method_tampering", "http_verb_tampering",
        "privilege_escalation", "cors_credential_security",
        "session_security", "session_entropy_passive",
        "mfa_detection", "account_lockout", "account_recovery",
        "password_policy", "password_reset",
        "scim", "webauthn_security",
        "soc2_compliance", "nist_csf_compliance", "iso27001_compliance",
    ],
}

_STRIDE_LABELS = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}

_STRIDE_DESCRIPTIONS = {
    "S": "Attacker impersonates a user, service, or process.",
    "T": "Attacker modifies data, code, or configuration.",
    "R": "Attacker performs an action that cannot be traced back to them.",
    "I": "Attacker reads data they should not have access to.",
    "D": "Attacker disrupts availability of the service.",
    "E": "Attacker gains capabilities beyond their authorization level.",
}


def _classify(finding_type: str) -> List[str]:
    categories = []
    for cat, patterns in _STRIDE_MAP.items():
        if any(finding_type == p or finding_type.startswith(p) for p in patterns):
            categories.append(cat)
    return categories or ["I"]  # default: information disclosure


def _severity_rank(severity: str) -> int:
    return {"FAIL": 0, "WARN": 1, "PASS": 2, "INFO": 3}.get(severity.upper(), 9)


def generate(target: str, all_results: Dict[str, List[Any]], output_path: str,
             scan_score: Any = None) -> None:
    """Generate STRIDE threat model JSON and Markdown from scan results."""

    threats: Dict[str, List[Dict]] = {c: [] for c in "STRIDE"}
    flat = [r for findings in all_results.values() for r in findings
            if r.get("severity", "PASS").upper() in ("FAIL", "WARN")]

    for finding in flat:
        ftype    = finding.get("type", "unknown")
        severity = finding.get("severity", "WARN")
        detail   = finding.get("detail", "")
        url      = finding.get("url", target)
        cats     = _classify(ftype)
        for cat in cats:
            threats[cat].append({
                "finding_type": ftype,
                "severity":     severity,
                "url":          url,
                "detail":       detail[:200],
            })

    # Deduplicate per category by finding_type
    for cat in threats:
        seen = set()
        deduped = []
        for t in threats[cat]:
            if t["finding_type"] not in seen:
                seen.add(t["finding_type"])
                deduped.append(t)
        threats[cat] = sorted(deduped, key=lambda x: _severity_rank(x["severity"]))

    model = {
        "schema":    "STRIDE Threat Model",
        "tool":      f"Tblue {__version__}",
        "target":    target,
        "generated": datetime.now(timezone.utc).isoformat(),
        "score":     scan_score,
        "threats": {
            _STRIDE_LABELS[c]: {
                "description": _STRIDE_DESCRIPTIONS[c],
                "count":       len(threats[c]),
                "findings":    threats[c],
            }
            for c in "STRIDE"
        },
    }

    json_path  = output_path if output_path.endswith(".json") else output_path + ".json"
    md_path    = json_path.replace(".json", ".md")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(model, f, indent=2)

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# STRIDE Threat Model\n\n")
        f.write(f"**Target:** {target}  \n")
        f.write(f"**Tool:** Tblue {__version__}  \n")
        f.write(f"**Generated:** {model['generated']}  \n")
        if scan_score is not None:
            f.write(f"**Security Score:** {scan_score}  \n")
        f.write("\n---\n\n")

        for cat_code in "STRIDE":
            label = _STRIDE_LABELS[cat_code]
            desc  = _STRIDE_DESCRIPTIONS[cat_code]
            items = threats[cat_code]
            f.write(f"## {label} ({cat_code})\n\n")
            f.write(f"_{desc}_\n\n")
            if not items:
                f.write("No findings in this category.\n\n")
                continue
            f.write(f"**{len(items)} unique finding type(s):**\n\n")
            f.write("| Severity | Finding Type | Detail |\n")
            f.write("|---|---|---|\n")
            for item in items:
                sev    = item["severity"]
                ftype  = item["finding_type"]
                detail = item["detail"].replace("|", "\\|").replace("\n", " ")[:120]
                f.write(f"| {sev} | `{ftype}` | {detail} |\n")
            f.write("\n")
