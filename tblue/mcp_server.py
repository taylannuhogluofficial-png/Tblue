"""
Tblue MCP Server

Exposes Tblue's 614 blue-team scanners as AI-callable tools via the
Model Context Protocol. Works with Claude Desktop, Claude Code, and any
MCP-compatible AI client.

Usage:
    tblue-mcp              # stdio transport (default, for Claude Desktop / Claude Code)

Tools exposed:
    scan          - Run scanners against a URL and return structured findings
    list_modules  - List available scanner modules with descriptions
    explain_module - Get a detailed explanation of what a specific module checks
"""

import asyncio
import json
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

import requests

os.environ.setdefault("TBLUE_NO_BANNER", "1")

from mcp.server.mcpserver.context import Context
from mcp.server.mcpserver.server import MCPServer

from tblue.cli import _SCANNER_REGISTRY, ALL_MODULES

# Build lookup tables once at startup
_REGISTRY_BY_KEY = {mod: (cls, msg) for mod, cls, msg in _SCANNER_REGISTRY}

# Category mapping derived from the scanner descriptions
_CATEGORY_MAP = {
    "injection":      ["xss", "ssti", "xml_xxe", "xxe_injection", "command_injection",
                       "sql_error_passive", "el_injection", "ldap_injection", "nosql_injection",
                       "nosql_injection_advanced", "log_injection", "json_injection",
                       "csv_injection", "crlf_injection", "http_response_splitting",
                       "latex_injection_passive", "xpath_injection_passive", "xpath_injection_security"],
    "authentication": ["jwt", "jwt_advanced", "jwt_claim_analysis", "jwt_algorithm_confusion",
                       "jwks_exposure", "jwt_token_exposure", "jwt_advanced_security",
                       "session_security", "session_fixation", "session_fixation_passive",
                       "session_fixation_security", "session_entropy_passive", "session_token_exposure",
                       "mfa_detection", "login_security", "password_policy", "password_reset",
                       "account_lockout", "account_enumeration", "account_recovery",
                       "magic_link_security", "webauthn_security", "credential_exposure",
                       "credential_management_security", "auth_bypass_pattern_security"],
    "authorization":  ["idor_detection", "access_control", "mass_assignment",
                       "mass_assignment_security", "broken_object_level_auth",
                       "insecure_direct_object_reference", "path_traversal",
                       "path_traversal_deep", "file_inclusion", "file_inclusion_security",
                       "directory_listing", "admin_exposure"],
    "headers":        ["headers", "response_headers", "http_security_baseline",
                       "http_security_headers_deep", "http_security_consistency",
                       "permissions_policy", "permissions_policy_deep",
                       "referrer_policy", "referrer_policy_deep",
                       "feature_policy_security", "nel_reporting", "reporting_api_security"],
    "cors":           ["cors", "cors_advanced", "cors_deep_analysis", "cors_misconfiguration_deep",
                       "cors_preflight_deep", "cors_wildcard_api", "cors_null_origin",
                       "cors_expose_headers", "cors_max_age_deep", "cors_origin_reflection",
                       "cors_credential_security", "cors_policy_advanced"],
    "csp":            ["csp", "csp_advanced", "csp_nonce", "csp_nonce_reuse",
                       "csp_reporting", "csp_violation_report", "trusted_types_csp",
                       "trusted_types_policy", "trusted_types_security"],
    "cookies":        ["cookies", "cookie_advanced", "cookie_prefix_security",
                       "cookie_samesite_deep", "cookies_partitioned_security",
                       "same_site_cookie_security"],
    "tls":            ["ssl", "tls_deep", "tls_protocol_version", "tls_certificate_deep",
                       "tls_downgrade_passive", "hsts_preload", "hsts_deep_analysis",
                       "http_strict_transport_upgrade", "weak_crypto", "compression_oracle"],
    "oauth":          ["oauth", "oauth_advanced", "oauth_token_leak", "oauth_pkce",
                       "oauth_redirect_uri_validation", "oauth_implicit_flow",
                       "oauth_device_flow", "oauth_misconfiguration_passive",
                       "saml", "saml_passive", "saml_security_passive",
                       "social_login_security", "federated_identity_security", "fedcm_security"],
    "ssrf":           ["ssrf_params", "ssrf_advanced", "ssrf_detection", "ssrf_passive",
                       "cloud_metadata", "dns_rebinding", "dns_rebinding_passive",
                       "link_preview_exposure", "open_redirect", "open_redirect_deep"],
    "secrets":        ["js_secrets", "hardcoded_credentials", "credential_exposure",
                       "api_key_in_js", "secret_in_error_page", "token_exposure_passive",
                       "dev_artifact", "exposed_backup_files", "package_manifest_exposure",
                       "html_comments", "source_map", "sourcemap_exposure", "source_map_exposure"],
    "api":            ["api_surface", "api_auth_security", "api_security_headers",
                       "api_versioning", "api_versioning_security", "api_error_disclosure",
                       "api_documentation_exposure", "api_schema_exposure", "api_collection",
                       "api_rate_limit_deep", "api_rate_limit_headers", "api_pagination_security",
                       "api_pagination_abuse", "api_key_rotation", "api_gateway_security",
                       "api_authentication_exposure", "open_api_exposure"],
    "graphql":        ["graphql", "graphql_advanced", "graphql_depth", "graphql_batching",
                       "graphql_batch_abuse", "graphql_batch_attack", "graphql_field_suggestion",
                       "graphql_subscription", "graphql_persisted_queries",
                       "graphql_info_disclosure", "graphql_csrf", "graphql_authorization",
                       "graphql_introspection_security", "introspection_disclosure"],
    "supply_chain":   ["supply_chain", "supply_chain_lockfile", "sca", "dependency_confusion",
                       "dependency_hijacking", "typosquatting", "sri_advanced",
                       "subresource_integrity_deep", "js_supply_chain_integrity",
                       "importmap_security", "polyfill_supply_chain", "sbom_scanner"],
    "cloud":          ["cloud_storage", "cloud_metadata", "open_s3_bucket", "k8s_exposure",
                       "docker_exposure", "cicd_exposure", "elasticsearch_exposure",
                       "redis_exposure", "mongodb_exposure", "serverless_exposure",
                       "spring_actuator", "actuator_endpoint_exposure", "health_endpoint_exposure"],
    "dns":            ["dns", "dns_advanced", "dns_caa", "dns_rebinding",
                       "subdomain_takeover", "subdomain_takeover_passive",
                       "subdomain_enum_passive", "certificate_transparency", "crt_sh"],
    "csrf":           ["csrf_token_strength", "csrf_double_submit", "form_security",
                       "form_action_security", "form_action_hijacking"],
}

# Reverse map: module key -> category name
_MODULE_CATEGORY: dict[str, str] = {}
for _cat, _mods in _CATEGORY_MAP.items():
    for _mod in _mods:
        _MODULE_CATEGORY.setdefault(_mod, _cat)

_DEFAULT_USER_AGENT = "Tblue/1.0 MCP (blue-team scanner)"


def _build_auth_session(
    auth_cookie: Optional[str] = None,
    auth_bearer: Optional[str] = None,
    auth_header: Optional[list] = None,
    auth_basic: Optional[str] = None,
) -> requests.Session:
    """Create a requests.Session with optional auth credentials applied."""
    session = requests.Session()
    session.headers["User-Agent"] = _DEFAULT_USER_AGENT

    if auth_cookie:
        for part in auth_cookie.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                session.cookies.set(name.strip(), value.strip())

    if auth_bearer:
        session.headers["Authorization"] = f"Bearer {auth_bearer}"

    for h in (auth_header or []):
        if ":" in h:
            name, _, value = h.partition(":")
            session.headers[name.strip()] = value.strip()

    if auth_basic and ":" in auth_basic:
        user, _, pwd = auth_basic.partition(":")
        session.auth = (user, pwd)

    return session


def _run_one_scanner(key: str, url: str, session: requests.Session) -> list[dict]:
    """Run a single scanner module. Called from a thread pool."""
    entry = _REGISTRY_BY_KEY.get(key)
    if not entry:
        return []
    cls, _ = entry
    try:
        return cls(session).scan(url) or []
    except Exception as exc:
        return [{"module": key, "status": "ERROR", "detail": str(exc)}]


# Compliance framework prefixes — findings from these scanners are tagged and deduplicated
_COMPLIANCE_PREFIXES = ("soc2_", "pci_", "hipaa_", "iso27001_", "nist_", "gdpr_", "fedramp_", "cis_")
_COMPLIANCE_FRAMEWORK_NAMES = {
    "soc2_":       "SOC 2",
    "pci_":        "PCI-DSS",
    "hipaa_":      "HIPAA",
    "iso27001_":   "ISO 27001",
    "nist_":       "NIST CSF",
    "gdpr_":       "GDPR",
    "fedramp_":    "FedRAMP",
    "cis_":        "CIS Controls",
}
# Known root-issue keywords that appear in compliance finding type names
_ROOT_KEYWORDS = [
    "hsts", "spf", "dmarc", "dkim", "tls", "cors", "csp", "xcto",
    "sri", "csrf", "xss", "sql", "injection", "clickjack",
    "rate_limit", "auth", "mfa", "session", "cookie", "header",
    "redirect", "secrets", "api_key", "debug",
]


def _compliance_root(check_type: str) -> Optional[str]:
    """Return a root-issue keyword for compliance findings, else None."""
    for prefix in _COMPLIANCE_PREFIXES:
        if check_type.startswith(prefix):
            for kw in _ROOT_KEYWORDS:
                if kw in check_type:
                    return kw
            return check_type  # fallback: treat full type as root
    return None


def _normalize_module_name(check_type: str) -> str:
    """Convert internal snake_case module keys to a human-readable name."""
    # Already human-readable if it contains spaces or dashes
    if " " in check_type or "—" in check_type:
        return check_type
    # Convert snake_case to Title Case words
    return check_type.replace("_", " ").title()


def _dedup_findings(issues: list[dict]) -> list[dict]:
    """
    Deduplicate findings:
    1. Exact same (module, url, detail-prefix) — keep one.
    2. Compliance findings about the same root issue — collapse into one with
       a 'compliance_frameworks' list.
    """
    # Step 1: exact-key dedup (same type + url + first 100 chars of detail)
    seen: dict[str, dict] = {}
    deduped: list[dict] = []
    for f in issues:
        key = f"{f.get('module','')}|{f.get('url','')}|{(f.get('detail') or '')[:100]}"
        if key not in seen:
            seen[key] = f
            deduped.append(f)

    # Step 2: compliance grouping — group compliance findings by root keyword
    compliance_groups: dict[str, list[dict]] = {}  # root → list of findings
    non_compliance: list[dict] = []

    for f in deduped:
        root = _compliance_root(f.get("module", ""))
        if root is not None:
            compliance_groups.setdefault(root, []).append(f)
        else:
            non_compliance.append(f)

    # For each compliance group, emit one representative finding with framework tags
    collapsed_compliance: list[dict] = []
    for root, group in compliance_groups.items():
        # Pick the most detailed finding as representative
        rep = max(group, key=lambda f: len(f.get("detail", "")))

        # Collect framework names
        frameworks = []
        for f in group:
            mod = f.get("module", "")
            for prefix, name in _COMPLIANCE_FRAMEWORK_NAMES.items():
                if mod.startswith(prefix):
                    frameworks.append(name)
                    break

        if len(group) > 1:
            rep = dict(rep)  # copy so we don't mutate
            rep["compliance_frameworks"] = sorted(set(frameworks))
            # Append framework context to detail if not already present
            fw_str = ", ".join(sorted(set(frameworks)))
            rep["detail"] = rep.get("detail", "") + f" [Compliance implications: {fw_str}]"

        collapsed_compliance.append(rep)

    return non_compliance + collapsed_compliance


def _summarise(findings: list[dict], modules_run: int) -> dict:
    """Turn raw scanner findings into a structured summary."""
    severity_order = {"FAIL": 0, "CRITICAL": 0, "HIGH": 1, "WARN": 2, "MEDIUM": 2, "LOW": 3, "INFO": 4, "PASS": 5, "ERROR": 6}

    pass_count = sum(1 for f in findings if f.get("status") == "PASS")
    issues_raw = [f for f in findings if f.get("status") not in ("PASS", None)]

    # Build structured records — keep original module key for dedup/compliance detection
    structured = [
        {
            "module":      f.get("type") or f.get("module") or "unknown",  # raw key, normalized after dedup
            "severity":    (f.get("severity") or f.get("status") or "INFO").upper(),
            "url":         f.get("url", ""),
            "detail":      f.get("detail") or f.get("description") or "",
            "remediation": f.get("remediation") or "",
        }
        for f in issues_raw
    ]

    deduplicated = _dedup_findings(structured)

    # Normalize module names for display only after dedup (so compliance prefix matching worked)
    for f in deduplicated:
        frameworks = f.get("compliance_frameworks")
        if frameworks:
            # Build a clean display name: "Compliance: <Root Issue> (<Frameworks>)"
            root = _compliance_root(f["module"]) or f["module"]
            root_label = root.replace("_", " ").title()
            fw_label = ", ".join(frameworks)
            f["module"] = f"Compliance: {root_label} ({fw_label})"
        else:
            f["module"] = _normalize_module_name(f["module"])

    counts: dict[str, int] = {"PASS": pass_count}
    for f in deduplicated:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    # Compute a letter grade based on FAIL/WARN ratio
    total_checks = len(deduplicated) + pass_count
    fail_count = counts.get("FAIL", 0) + counts.get("CRITICAL", 0)
    warn_count = counts.get("WARN", 0)
    if total_checks == 0:
        grade = "N/A"
    elif fail_count == 0 and warn_count == 0:
        grade = "A+"
    elif fail_count == 0 and warn_count <= 3:
        grade = "A"
    elif fail_count == 0 and warn_count <= 10:
        grade = "B"
    elif fail_count <= 3 and warn_count <= 10:
        grade = "C"
    elif fail_count <= 10:
        grade = "D"
    else:
        grade = "F"

    sorted_issues = sorted(
        deduplicated,
        key=lambda f: severity_order.get(f.get("severity", "INFO").upper(), 99),
    )

    return {
        "modules_run":    modules_run,
        "total_findings": len(deduplicated),
        "pass_count":     pass_count,
        "grade":          grade,
        "severity_counts": counts,
        "findings":       sorted_issues,
    }


# ── Scan history ──────────────────────────────────────────────────────────────

import hashlib
from datetime import datetime, timezone
from pathlib import Path

_HISTORY_DIR = Path.home() / ".tblue" / "scans"


def _url_slug(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:16]


def _save_scan_history(url: str, summary: dict) -> None:
    try:
        slug = _url_slug(url)
        scan_dir = _HISTORY_DIR / slug
        scan_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        record = {"url": url, "timestamp": ts, "summary": summary}
        (scan_dir / f"{ts}.json").write_text(json.dumps(record, indent=2))
        # Keep only the 10 most recent scans to limit disk use
        scans = sorted(scan_dir.glob("*.json"))
        for old in scans[:-10]:
            old.unlink(missing_ok=True)
    except Exception:
        pass


def _load_previous_scan(url: str) -> Optional[dict]:
    try:
        slug = _url_slug(url)
        scan_dir = _HISTORY_DIR / slug
        scans = sorted(scan_dir.glob("*.json"))
        if not scans:
            return None
        # The most recent file IS the previous scan — current has not been saved yet
        return json.loads(scans[-1].read_text())
    except Exception:
        return None


def _diff_summaries(prev: dict, curr: dict) -> dict:
    """Compare two scan summaries and return new, fixed, and persistent findings."""
    def _key(f: dict) -> str:
        return f"{f.get('module', '')}|{f.get('url', '')}|{f.get('detail', '')[:120]}"

    prev_findings = prev.get("summary", prev).get("findings", [])
    curr_findings = curr.get("findings", [])

    prev_keys = {_key(f): f for f in prev_findings}
    curr_keys = {_key(f): f for f in curr_findings}

    new_keys       = set(curr_keys) - set(prev_keys)
    fixed_keys     = set(prev_keys) - set(curr_keys)
    persistent_keys = set(curr_keys) & set(prev_keys)

    return {
        "new_count":        len(new_keys),
        "fixed_count":      len(fixed_keys),
        "persistent_count": len(persistent_keys),
        "new":              [curr_keys[k] for k in new_keys],
        "fixed":            [prev_keys[k] for k in fixed_keys],
        "persistent":       [curr_keys[k] for k in persistent_keys],
        "previous_scan_timestamp": prev.get("timestamp"),
    }


# ── MCP Server ────────────────────────────────────────────────────────────────

mcp = MCPServer(
    name="tblue",
    instructions=(
        "Tblue is a passive blue-team security scanner. "
        "Use it to audit the security of websites the user owns. "
        "Start with `list_modules` to understand what is available, "
        "then call `scan` with the relevant modules for the user's concern. "
        "Use `explain_module` when the user wants to understand a specific finding. "
        "Pass auth credentials (auth_bearer, auth_cookie, etc.) when scanning "
        "pages that require authentication."
    ),
)


@mcp.tool(
    description=(
        "Run Tblue security scanners against a URL and return structured findings. "
        "By default runs all 614 passive modules. You can narrow the scan by passing a "
        "list of module keys (e.g. ['jwt', 'cors', 'session_security']) or a category "
        "name (e.g. 'authentication', 'cors', 'injection', 'secrets', 'tls', 'oauth', "
        "'headers', 'cookies', 'ssrf', 'api', 'graphql', 'supply_chain', 'cloud', "
        "'dns', 'csrf', 'authorization'). "
        "For authenticated scans, pass credentials via auth_bearer, auth_cookie, "
        "auth_header, or auth_basic. "
        "Returns severity-sorted findings. If this URL was scanned before, also returns "
        "a diff showing what is new, what was fixed, and what persists."
    )
)
async def scan(
    url: str,
    modules: Optional[list] = None,
    category: Optional[str] = None,
    workers: int = 20,
    auth_cookie: Optional[str] = None,
    auth_bearer: Optional[str] = None,
    auth_header: Optional[list] = None,
    auth_basic: Optional[str] = None,
    ctx: Context = None,
) -> str:
    """
    Scan a URL with Tblue's passive security scanners.

    Parameters
    ----------
    url         : The target URL (must be a site you own or have permission to scan).
    modules     : Optional list of specific module keys to run. If omitted, runs all or category.
    category    : Optional category shortcut. One of: authentication, authorization, cors,
                  csp, cookies, headers, tls, oauth, ssrf, secrets, api, graphql,
                  supply_chain, cloud, dns, injection, csrf.
    workers     : Number of parallel threads (default 20, max 50).
    auth_cookie : Session cookies as a string: "name=value; name2=value2".
    auth_bearer : Bearer token (sets Authorization: Bearer <token>).
    auth_header : List of extra headers: ["X-API-Key: secret", "X-Tenant: acme"].
    auth_basic  : HTTP Basic auth credentials as "username:password".
    """
    workers = min(max(workers, 1), 50)

    warnings: list[str] = []
    if modules:
        keys = [m for m in modules if m in _REGISTRY_BY_KEY]
        unknown = [m for m in modules if m not in _REGISTRY_BY_KEY]
        if unknown:
            warnings.append(f"Unknown module keys skipped: {unknown}. Use list_modules to see valid keys.")
        if not keys:
            return json.dumps({"error": f"No valid module keys provided. Unknown: {unknown}. Use list_modules to see valid keys."})
    elif category:
        cat = category.lower()
        keys = _CATEGORY_MAP.get(cat)
        if not keys:
            valid = sorted(_CATEGORY_MAP.keys())
            return json.dumps({"error": f"Unknown category '{cat}'. Valid categories: {valid}"})
        keys = [k for k in keys if k in _REGISTRY_BY_KEY]
    else:
        keys = [k for k in ALL_MODULES if k in _REGISTRY_BY_KEY]

    if not keys:
        return json.dumps({"error": "No valid modules to run."})

    session = _build_auth_session(auth_cookie, auth_bearer, auth_header, auth_basic)
    total = len(keys)
    completed = 0
    all_findings: list[dict] = []

    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=min(workers, total)) as pool:
        async_futures = [
            loop.run_in_executor(pool, _run_one_scanner, key, url, session)
            for key in keys
        ]

        for coro in asyncio.as_completed(async_futures):
            findings = await coro
            all_findings.extend(findings)
            completed += 1

            if ctx is not None:
                try:
                    await ctx.report_progress(completed, total)
                except Exception:
                    pass

    summary = _summarise(all_findings, modules_run=total)

    # Load previous scan for diff (must happen before saving current)
    previous = _load_previous_scan(url)
    _save_scan_history(url, summary)

    result: dict = {"scan": summary}
    if warnings:
        result["warnings"] = warnings
    if previous is not None:
        result["diff_vs_previous"] = _diff_summaries(previous, summary)

    return json.dumps(result, indent=2)


@mcp.tool(
    description=(
        "List all available Tblue scanner modules with their names, descriptions, "
        "and categories. Use this to find the right modules before calling scan. "
        "Optionally filter by a search term or category name."
    )
)
def list_modules(
    search: Optional[str] = None,
    category: Optional[str] = None,
) -> str:
    """
    List available scanner modules.

    Parameters
    ----------
    search   : Optional keyword to filter by module name or description.
    category : Optional category name to filter by.
    """
    results = []
    for mod, cls, description in _SCANNER_REGISTRY:
        cat = _MODULE_CATEGORY.get(mod, "general")

        if category and cat != category.lower():
            continue

        if search:
            term = search.lower()
            if term not in mod.lower() and term not in description.lower() and term not in cat.lower():
                continue

        results.append({
            "key":         mod,
            "category":    cat,
            "description": description.rstrip("."),
        })

    return json.dumps({
        "total":   len(results),
        "modules": results,
    }, indent=2)


@mcp.tool(
    description=(
        "Get a detailed explanation of what a specific Tblue scanner module checks, "
        "why the issue it detects is dangerous, and how to fix it. "
        "Use this to help a user understand a finding from the scan tool."
    )
)
def explain_module(module_key: str) -> str:
    """
    Explain what a scanner module checks and how to remediate findings.

    Parameters
    ----------
    module_key : The module key (e.g. 'jwt', 'cors', 'csp_nonce'). Use list_modules to find keys.
    """
    entry = _REGISTRY_BY_KEY.get(module_key)
    if not entry:
        close = [k for k in _REGISTRY_BY_KEY if module_key in k]
        suggestion = f" Did you mean one of: {close[:5]}?" if close else ""
        return json.dumps({"error": f"Unknown module '{module_key}'.{suggestion}"})

    cls, description = entry
    category = _MODULE_CATEGORY.get(module_key, "general")
    doc = (cls.__doc__ or "").strip()

    return json.dumps({
        "key":         module_key,
        "category":    category,
        "description": description.rstrip("."),
        "detail":      doc or "See the Tblue SCANNERS.md reference for full details.",
        "how_to_run":  f"tblue -u https://yoursite.com --only {module_key}",
    }, indent=2)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
