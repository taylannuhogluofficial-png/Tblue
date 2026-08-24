#!/usr/bin/env python3
"""
Tblue Live Scan Server.

Two modes:
  • Single-URL scan   POST /api/scan           {"url": "https://example.com"}
  • Subdomain scan    POST /api/subdomain-scan  {"domain": "example.com"}
                      GET  /api/subdomain-scan/status/<job_id>
                      GET  /api/subdomain-scan/results/<job_id>

Usage:
    python scan_server.py              # http://localhost:8080
    python scan_server.py --port 9090
    python scan_server.py --no-browser
"""

import argparse
import importlib
import json
import socket
import threading
import time
import uuid
import warnings
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Scanner registry ──────────────────────────────────────────────────────────
SCANNERS = [
    # Network / Transport
    ("tblue.scanner.ssl",                    "SSLScanner",                    "TLS/SSL Configuration",        "network"),
    ("tblue.scanner.tls_deep",               "TLSDeepScanner",                "TLS Deep Analysis",            "network"),
    ("tblue.scanner.dns_security",           "DNSSecurityScanner",            "DNS / Email Security",         "network"),
    ("tblue.scanner.dns_advanced",           "DNSAdvancedScanner",            "DNSSEC & CAA",                 "network"),
    ("tblue.scanner.hsts_preload",           "HSTSPreloadScanner",            "HSTS Preload",                 "network"),
    ("tblue.scanner.redirect_chain",         "RedirectChainScanner",          "Redirect Chain",               "network"),
    ("tblue.scanner.waf",                    "WAFScanner",                    "WAF Detection",                "network"),

    # HTTP Headers
    ("tblue.scanner.headers",                "HeaderScanner",                 "Security Headers",             "headers"),
    ("tblue.scanner.response_headers",       "ResponseHeadersScanner",        "Response Headers",             "headers"),
    ("tblue.scanner.permissions_policy",     "PermissionsPolicyScanner",      "Permissions Policy",           "headers"),
    ("tblue.scanner.referrer_policy",        "ReferrerPolicyScanner",         "Referrer Policy",              "headers"),
    ("tblue.scanner.csp",                    "CSPScanner",                    "Content Security Policy",      "headers"),
    ("tblue.scanner.csp_advanced",           "CSPAdvancedScanner",            "CSP Advanced Analysis",        "headers"),
    ("tblue.scanner.mixed_content",          "MixedContentScanner",           "Mixed Content",                "headers"),

    # CORS
    ("tblue.scanner.cors",                   "CORSScanner",                   "CORS Policy",                  "cors"),
    ("tblue.scanner.cors_advanced",          "CORSAdvancedScanner",           "CORS Advanced",                "cors"),
    ("tblue.scanner.fetch_metadata",         "FetchMetadataScanner",          "Fetch Metadata Isolation",     "cors"),
    ("tblue.scanner.crossdomain_policy",     "CrossDomainPolicyScanner",      "Crossdomain Policy",           "cors"),

    # Authentication / Session
    ("tblue.scanner.cookies",                "CookieScanner",                 "Cookie Security",              "auth"),
    ("tblue.scanner.cookie_advanced",        "CookieAdvancedScanner",         "Cookie Advanced",              "auth"),
    ("tblue.scanner.session_security",       "SessionSecurityScanner",        "Session Management",           "auth"),
    ("tblue.scanner.clickjacking",           "ClickjackingScanner",           "Clickjacking",                 "auth"),
    ("tblue.scanner.webauthn_security",      "WebAuthnSecurityScanner",       "WebAuthn / MFA",               "auth"),
    ("tblue.scanner.oauth_token_leak",       "OAuthTokenLeakScanner",         "OAuth Token Leak",             "auth"),

    # Information Disclosure
    ("tblue.scanner.info_disclosure",        "InfoDisclosureScanner",         "Information Disclosure",       "disclosure"),
    ("tblue.scanner.html_comments",          "HTMLCommentsScanner",           "HTML Comment Leakage",         "disclosure"),
    ("tblue.scanner.error_pages",            "ErrorPageScanner",              "Verbose Error Pages",          "disclosure"),
    ("tblue.scanner.server_timing",          "ServerTimingScanner",           "Server Timing Header",         "disclosure"),
    ("tblue.scanner.source_map",             "SourceMapScanner",              "Source Map Exposure",          "disclosure"),
    ("tblue.scanner.robots_txt",             "RobotsSecurityScanner",         "Robots.txt Analysis",          "disclosure"),
    ("tblue.scanner.security_txt",           "SecurityTxtScanner",            "Security.txt",                 "disclosure"),
    ("tblue.scanner.version_cve",            "VersionCVEScanner",             "Version / CVE Disclosure",     "disclosure"),

    # Exposed Resources
    ("tblue.scanner.dev_artifact",           "DevArtifactScanner",            "Dev Artifacts (.git/.env)",    "exposure"),
    ("tblue.scanner.admin_exposure",         "AdminExposureScanner",          "Admin Panel Exposure",         "exposure"),
    ("tblue.scanner.directory_listing",      "DirectoryListingScanner",       "Directory Listing",            "exposure"),
    ("tblue.scanner.exposure",               "ExposureScanner",               "Swagger / API Docs Exposure",  "exposure"),
    ("tblue.scanner.open_api_exposure",      "OpenAPIExposureScanner",        "OpenAPI Spec Exposure",        "exposure"),
    ("tblue.scanner.spring_actuator",        "SpringActuatorScanner",         "Spring Actuator Endpoints",    "exposure"),
    ("tblue.scanner.cicd_exposure",          "CICDExposureScanner",           "CI/CD File Exposure",          "exposure"),
    ("tblue.scanner.k8s_exposure",           "K8sExposureScanner",            "Kubernetes Exposure",          "exposure"),
    ("tblue.scanner.framework_config",       "FrameworkConfigScanner",        "Framework Config Exposure",    "exposure"),

    # Cloud
    ("tblue.scanner.cloud_storage",          "CloudStorageScanner",           "Cloud Storage Buckets",        "cloud"),
    ("tblue.scanner.cloud_metadata",         "CloudMetadataScanner",          "Cloud Metadata SSRF",          "cloud"),
    ("tblue.scanner.subdomain_takeover",     "SubdomainTakeoverScanner",      "Subdomain Takeover",           "cloud"),

    # API Security
    ("tblue.scanner.graphql",                "GraphQLScanner",                "GraphQL Introspection",        "api"),
    ("tblue.scanner.graphql_advanced",       "GraphQLAdvancedScanner",        "GraphQL Advanced",             "api"),
    ("tblue.scanner.graphql_depth",          "GraphQLDepthScanner",           "GraphQL Depth / DoS",          "api"),
    ("tblue.scanner.graphql_batching",       "GraphQLBatchingScanner",        "GraphQL Batching Abuse",       "api"),
    ("tblue.scanner.api_versioning",         "APIVersioningScanner",          "API Version Exposure",         "api"),
    ("tblue.scanner.api_security_headers",   "APISecurityHeadersScanner",     "API Security Headers",         "api"),
    ("tblue.scanner.api_auth_security",      "APIAuthSecurityScanner",        "API Authentication",           "api"),

    # Injection / Vulnerability
    ("tblue.scanner.xss",                    "XSSScanner",                    "XSS Detection",                "vuln"),
    ("tblue.scanner.css_injection",          "CSSInjectionScanner",           "CSS Injection",                "vuln"),
    ("tblue.scanner.prssi",                  "PRSSIScanner",                  "PRSSI / Path-Relative CSS",    "vuln"),
    ("tblue.scanner.dom_clobbering",         "DOMClobberingScanner",          "DOM Clobbering",               "vuln"),
    ("tblue.scanner.sri_advanced",           "SRIAdvancedScanner",            "Subresource Integrity (SRI)",  "vuln"),
    ("tblue.scanner.dependency_confusion",   "DependencyConfusionScanner",    "Dependency Confusion",         "vuln"),
    ("tblue.scanner.supply_chain",           "SupplyChainScanner",            "Supply Chain Risk",            "vuln"),
    ("tblue.scanner.weak_crypto",            "WeakCryptoScanner",             "Weak Cryptography",            "vuln"),
    ("tblue.scanner.open_redirect",          "OpenRedirectScanner",           "Open Redirect",                "vuln"),
    ("tblue.scanner.web_cache_deception",    "WebCacheDeceptionScanner",      "Web Cache Deception",          "vuln"),
    ("tblue.scanner.form_security",          "FormSecurityScanner",           "Form Security / CSRF",         "vuln"),
    ("tblue.scanner.path_traversal",         "PathTraversalScanner",          "Path Traversal",               "vuln"),
    ("tblue.scanner.cms_detection",          "CMSDetectionScanner",           "CMS Detection",                "vuln"),
    ("tblue.scanner.sensitive_data_exposure","SensitiveDataExposureScanner",  "Sensitive Data Exposure",      "vuln"),
    ("tblue.scanner.js_file_analysis",       "JSFileAnalysisScanner",         "JS File Analysis",             "vuln"),
    ("tblue.scanner.xsleak",                 "XSLeakScanner",                 "Cross-Site Leaks",             "vuln"),
    ("tblue.scanner.xssi",                   "XSSIScanner",                   "XSSI",                        "vuln"),
]

CATEGORY_LABELS = {
    "network":    "Network & Transport",
    "headers":    "HTTP Security Headers",
    "cors":       "CORS & Origin Policy",
    "auth":       "Authentication & Sessions",
    "disclosure": "Information Disclosure",
    "exposure":   "Exposed Resources",
    "cloud":      "Cloud & Infrastructure",
    "api":        "API Security",
    "vuln":       "Vulnerabilities & Injections",
}

# ── Subdomain discovery wordlist ──────────────────────────────────────────────
_SUBDOMAIN_WORDLIST = [
    "www", "api", "admin", "dev", "staging", "app", "test", "beta",
    "mail", "smtp", "webmail", "mx", "ns", "ns1", "ns2",
    "portal", "login", "secure", "auth", "oauth", "sso", "id",
    "cdn", "static", "assets", "media", "files", "img", "images",
    "dashboard", "console", "panel", "manage", "management", "control",
    "blog", "shop", "store", "forum", "wiki", "docs", "help", "support",
    "demo", "sandbox", "uat", "qa", "preview", "canary",
    "v1", "v2", "api2", "backend", "frontend", "service",
    "mobile", "m", "wap", "app2",
    "status", "monitor", "health", "ping",
    "internal", "intranet", "corp", "vpn",
    "git", "svn", "code", "repo",
    "jira", "confluence", "jenkins", "ci", "cicd", "gitlab",
    "grafana", "prometheus", "kibana", "elastic", "sentry",
    "db", "database", "redis", "cache",
    "ftp", "sftp", "ssh",
    "cpanel", "plesk", "whm",
    "old", "new", "legacy", "archive",
    "pay", "payment", "checkout", "billing",
    "crm", "erp", "hr",
    "search", "analytics", "tracking",
    "upload", "download", "dl",
]

# Maximum subdomains to scan in one job
_MAX_SUBDOMAINS = 50

# Concurrent targets when scanning (each spawns its own scanner thread pool)
_TARGET_CONCURRENCY = 3

# ── In-memory job store ───────────────────────────────────────────────────────
_JOBS: dict = {}
_JOBS_LOCK = threading.Lock()


# ── Scanner execution ─────────────────────────────────────────────────────────

def _run_one(module_path, class_name, label, category, url, session):
    t0 = time.time()
    try:
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        findings = cls(session).scan(url)
        return {
            "scanner":  label,
            "category": category,
            "findings": findings,
            "duration": round(time.time() - t0, 2),
            "error":    None,
        }
    except Exception as exc:
        return {
            "scanner":  label,
            "category": category,
            "findings": [],
            "duration": round(time.time() - t0, 2),
            "error":    str(exc)[:200],
        }


def scan_url(url: str) -> dict:
    """Run all scanners against one URL in parallel. Returns aggregated dict."""
    t0 = time.time()

    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
    if not urlparse(url).netloc:
        return {"error": f"Invalid URL: {url}"}

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Tblue/2.0 Blue-Team-Scanner (passive analysis only)",
    })
    session.verify = False

    results = []
    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = {
            pool.submit(_run_one, mod, cls, label, cat, url, session): label
            for mod, cls, label, cat in SCANNERS
        }
        for fut in as_completed(futures):
            results.append(fut.result())

    def _sort_key(r):
        sev = 0
        for f in r.get("findings", []):
            s = f.get("status", "")
            if s == "FAIL":   sev = max(sev, 3)
            elif s == "WARN": sev = max(sev, 2)
            elif s == "PASS": sev = max(sev, 1)
        return -sev

    results.sort(key=_sort_key)

    fail   = sum(1 for r in results for f in r["findings"] if f.get("status") == "FAIL")
    warn   = sum(1 for r in results for f in r["findings"] if f.get("status") == "WARN")
    passed = sum(1 for r in results for f in r["findings"] if f.get("status") == "PASS")

    return {
        "url":      url,
        "duration": round(time.time() - t0, 2),
        "summary":  {"fail": fail, "warn": warn, "pass": passed,
                     "total": fail + warn + passed},
        "scanners": results,
    }


# ── Subdomain discovery ───────────────────────────────────────────────────────

def _crtsh_subdomains(domain: str) -> set:
    """Query crt.sh Certificate Transparency logs for known subdomains."""
    found = set()
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=25,
            headers={"User-Agent": "Tblue/2.0"},
        )
        if r.status_code == 200:
            for entry in r.json():
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        found.add(name)
    except Exception:
        pass
    return found


def _wordlist_subdomains(domain: str) -> set:
    return {f"{w}.{domain}" for w in _SUBDOMAIN_WORDLIST} | {domain}


def _resolve(subdomain: str) -> bool:
    """Return True if the subdomain has a DNS A/AAAA record."""
    try:
        socket.getaddrinfo(subdomain, None, proto=socket.IPPROTO_TCP)
        return True
    except Exception:
        return False


def _probe_live(subdomain: str) -> str | None:
    """
    Return the first live URL (https:// preferred) for this subdomain,
    or None if the subdomain doesn't respond.
    """
    session = requests.Session()
    session.headers.update({"User-Agent": "Tblue/2.0"})
    session.max_redirects = 5

    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            resp = session.get(url, timeout=8, verify=False, allow_redirects=True)
            if resp.status_code < 500:
                return url
        except Exception:
            continue
    return None


def discover_live_targets(domain: str, job_id: str) -> list[str]:
    """
    Enumerate subdomains via crt.sh + wordlist, resolve DNS, probe HTTP.
    Updates job progress. Returns list of live URLs (capped at _MAX_SUBDOMAINS).
    """
    domain = domain.lower().strip().lstrip("https://").lstrip("http://").split("/")[0]

    _job_update(job_id, phase="discovering", detail=f"Querying crt.sh for {domain}…")
    ct_subs = _crtsh_subdomains(domain)

    _job_update(job_id, phase="discovering",
                detail=f"Found {len(ct_subs)} subdomains in CT logs. Merging wordlist…")
    all_candidates = ct_subs | _wordlist_subdomains(domain)

    _job_update(job_id, phase="resolving",
                detail=f"Resolving DNS for {len(all_candidates)} candidates…")

    # Parallel DNS resolution (fast, 50 threads)
    resolves = set()
    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(_resolve, sub): sub for sub in all_candidates}
        for fut in as_completed(futures):
            sub = futures[fut]
            if fut.result():
                resolves.add(sub)

    _job_update(job_id, phase="probing",
                detail=f"{len(resolves)} subdomains resolve. Probing HTTP…")

    # Parallel HTTP live-check (moderate concurrency — we're making real requests)
    live = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(_probe_live, sub): sub for sub in resolves}
        for fut in as_completed(futures):
            url = fut.result()
            if url:
                live.append(url)

    # Deduplicate by netloc (prefer https over http)
    seen_hosts = set()
    deduped = []
    for url in sorted(live, key=lambda u: (0 if u.startswith("https") else 1)):
        host = urlparse(url).netloc
        if host not in seen_hosts:
            seen_hosts.add(host)
            deduped.append(url)

    # Sort: apex domain first, then alphabetically
    deduped.sort(key=lambda u: (0 if urlparse(u).netloc == domain else 1, u))
    return deduped[:_MAX_SUBDOMAINS]


# ── Job management ────────────────────────────────────────────────────────────

def _job_update(job_id: str, **kwargs):
    with _JOBS_LOCK:
        if job_id in _JOBS:
            _JOBS[job_id].update(kwargs)


def _new_job(domain: str) -> str:
    job_id = str(uuid.uuid4())
    with _JOBS_LOCK:
        _JOBS[job_id] = {
            "job_id":     job_id,
            "domain":     domain,
            "status":     "queued",
            "phase":      "queued",
            "detail":     "Job queued",
            "started_at": time.time(),
            "targets":    [],       # live URLs discovered
            "scanned":    0,        # targets fully scanned so far
            "total":      0,        # total live targets
            "results":    [],       # per-target scan results (appended as they finish)
        }
    return job_id


def _run_subdomain_job(job_id: str, domain: str):
    """Background thread: discover → scan each live target."""
    try:
        _job_update(job_id, status="running")

        # Phase 1 — Discovery
        live_targets = discover_live_targets(domain, job_id)

        if not live_targets:
            _job_update(job_id,
                        status="done",
                        phase="done",
                        detail="No live subdomains found.",
                        targets=[],
                        total=0)
            return

        _job_update(job_id,
                    phase="scanning",
                    detail=f"Scanning {len(live_targets)} live targets…",
                    targets=live_targets,
                    total=len(live_targets),
                    scanned=0)

        print(f"[subdomain-scan:{job_id[:8]}] {domain} → {len(live_targets)} targets", flush=True)

        # Phase 2 — Scan each target (bounded concurrency: _TARGET_CONCURRENCY at once)
        with ThreadPoolExecutor(max_workers=_TARGET_CONCURRENCY) as pool:
            futures = {pool.submit(scan_url, url): url for url in live_targets}
            for fut in as_completed(futures):
                result = fut.result()
                with _JOBS_LOCK:
                    _JOBS[job_id]["results"].append(result)
                    _JOBS[job_id]["scanned"] += 1
                    done = _JOBS[job_id]["scanned"]
                    tot  = _JOBS[job_id]["total"]
                url = futures[fut]
                print(f"[subdomain-scan:{job_id[:8]}] scanned {done}/{tot}: {url}", flush=True)

        _job_update(job_id,
                    status="done",
                    phase="done",
                    detail=f"Completed — {len(live_targets)} targets scanned.")

    except Exception as exc:
        _job_update(job_id,
                    status="error",
                    phase="error",
                    detail=str(exc)[:400])
        print(f"[subdomain-scan:{job_id[:8]}] ERROR: {exc}", flush=True)


# ── Embedded dashboard HTML ───────────────────────────────────────────────────

_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tblue Scanner</title>
<style>
  :root {
    --bg: #0f1117; --card: #1a1d27; --border: #2a2d3a;
    --accent: #6366f1; --accent2: #818cf8;
    --fail: #ef4444; --warn: #f59e0b; --pass: #22c55e;
    --text: #e2e8f0; --muted: #64748b; --font: 'Inter', system-ui, sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font);
         min-height: 100vh; padding: 2rem 1rem; }
  h1 { font-size: 1.6rem; font-weight: 700; color: #fff;
       display: flex; align-items: center; gap: .6rem; }
  h1 span.sub { font-size: .9rem; font-weight: 400; color: var(--muted); }
  .card { background: var(--card); border: 1px solid var(--border);
          border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }
  .tabs { display: flex; gap: .5rem; margin-bottom: 1.5rem; }
  .tab { padding: .5rem 1.2rem; border-radius: 8px; cursor: pointer;
         background: var(--border); color: var(--muted); border: none;
         font-size: .9rem; font-family: inherit; transition: all .15s; }
  .tab.active { background: var(--accent); color: #fff; }
  .tab:hover:not(.active) { background: #2a2d3a; color: var(--text); }
  label { display: block; font-size: .85rem; color: var(--muted);
          margin-bottom: .4rem; font-weight: 500; }
  input[type=text] {
    width: 100%; padding: .7rem 1rem; border-radius: 8px;
    background: var(--bg); border: 1px solid var(--border);
    color: var(--text); font-size: 1rem; font-family: inherit;
    outline: none; transition: border .15s;
  }
  input[type=text]:focus { border-color: var(--accent); }
  .btn {
    display: inline-flex; align-items: center; gap: .4rem;
    padding: .7rem 1.5rem; border-radius: 8px; border: none;
    background: var(--accent); color: #fff; font-size: .95rem;
    font-family: inherit; font-weight: 600; cursor: pointer;
    transition: opacity .15s; margin-top: .8rem;
  }
  .btn:hover { opacity: .85; }
  .btn:disabled { opacity: .4; cursor: not-allowed; }
  .row { display: flex; gap: 1rem; align-items: flex-end; flex-wrap: wrap; }
  .row > * { flex: 1; min-width: 200px; }
  .row .btn { flex: 0; white-space: nowrap; }

  /* Progress */
  .progress-wrap { display: none; margin-top: 1rem; }
  .progress-wrap.show { display: block; }
  .phase-label { font-size: .85rem; color: var(--accent2); margin-bottom: .5rem; font-weight: 600; }
  .detail-label { font-size: .82rem; color: var(--muted); margin-bottom: .8rem; }
  .progress-bar-bg { background: var(--border); border-radius: 99px; height: 8px; }
  .progress-bar { height: 8px; border-radius: 99px; background: var(--accent);
                  width: 0%; transition: width .3s; }
  .targets-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
                  gap: .5rem; margin-top: 1rem; }
  .target-chip {
    padding: .4rem .8rem; border-radius: 6px; font-size: .8rem;
    background: var(--border); border-left: 3px solid var(--muted);
    display: flex; align-items: center; justify-content: space-between;
    word-break: break-all;
  }
  .target-chip.scanning { border-left-color: var(--accent); }
  .target-chip.done-fail { border-left-color: var(--fail); }
  .target-chip.done-warn { border-left-color: var(--warn); }
  .target-chip.done-pass { border-left-color: var(--pass); }
  .chip-badge { font-size: .75rem; padding: .15rem .4rem; border-radius: 4px;
                background: var(--bg); white-space: nowrap; margin-left: .4rem; }

  /* Results */
  #results { display: none; }
  #results.show { display: block; }
  .summary-row { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
  .stat { background: var(--bg); border: 1px solid var(--border); border-radius: 10px;
          padding: .8rem 1.2rem; text-align: center; flex: 1; min-width: 100px; }
  .stat .num { font-size: 1.8rem; font-weight: 700; }
  .stat .lbl { font-size: .75rem; color: var(--muted); margin-top: .2rem; }
  .num.fail { color: var(--fail); }
  .num.warn { color: var(--warn); }
  .num.pass { color: var(--pass); }

  .target-section { margin-bottom: 2rem; }
  .target-header { display: flex; align-items: center; gap: .8rem;
                   cursor: pointer; padding: .6rem 0; }
  .target-url { font-size: 1rem; font-weight: 600; color: var(--accent2); }
  .target-badges { display: flex; gap: .4rem; margin-left: auto; }
  .badge { font-size: .75rem; font-weight: 700; padding: .2rem .6rem;
           border-radius: 6px; }
  .badge.fail { background: #7f1d1d; color: var(--fail); }
  .badge.warn { background: #78350f; color: var(--warn); }
  .badge.pass { background: #14532d; color: var(--pass); }
  .scanner-list { display: none; }
  .scanner-list.open { display: block; }
  .finding { padding: .6rem .8rem; border-left: 3px solid var(--border);
             margin: .3rem 0; border-radius: 0 6px 6px 0; font-size: .82rem;
             background: var(--bg); }
  .finding.FAIL { border-left-color: var(--fail); }
  .finding.WARN { border-left-color: var(--warn); }
  .finding.PASS { border-left-color: var(--pass); opacity: .5; }
  .finding-type { font-weight: 600; }
  .finding-detail { color: var(--muted); margin-top: .2rem;
                    white-space: pre-wrap; font-size: .78rem; }
  .scanner-name { font-size: .85rem; font-weight: 600; color: var(--text);
                  padding: .5rem 0 .2rem; margin-top: .4rem; }
  .error-chip { color: var(--fail); font-size: .78rem; font-style: italic; }

  .section-toggle::before { content: "▶ "; font-size: .8rem; color: var(--muted); }
  .section-toggle.open::before { content: "▼ "; }
  .spinner { display: inline-block; width: 14px; height: 14px;
             border: 2px solid var(--border); border-top-color: var(--accent);
             border-radius: 50%; animation: spin .7s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .hidden { display: none !important; }
</style>
</head>
<body>
<div style="max-width:960px;margin:0 auto;">

<h1>
  🛡️ Tblue
  <span class="sub">Blue-Team Security Scanner</span>
</h1>
<p style="color:var(--muted);font-size:.85rem;margin:.4rem 0 1.5rem;">
  Passive, non-destructive — scans headers, configs, subdomains, exposed surfaces.
</p>

<div class="tabs">
  <button class="tab active" id="tab-single" onclick="switchTab('single')">Single URL</button>
  <button class="tab" id="tab-subdomain" onclick="switchTab('subdomain')">Subdomain Scan</button>
</div>

<!-- Single URL mode -->
<div id="panel-single" class="card">
  <label for="url-input">Target URL</label>
  <div class="row">
    <div>
      <input type="text" id="url-input" placeholder="https://example.com"
             onkeydown="if(event.key==='Enter')startSingle()">
    </div>
    <button class="btn" id="btn-single" onclick="startSingle()">▶ Scan</button>
  </div>
  <div class="progress-wrap" id="single-progress">
    <div class="phase-label" id="single-phase">Scanning…</div>
    <div class="detail-label">Running all scanners in parallel</div>
    <div class="progress-bar-bg"><div class="progress-bar" id="single-bar" style="width:100%;animation:pulse 1.5s ease infinite"></div></div>
    <style>@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}</style>
  </div>
</div>

<!-- Subdomain mode -->
<div id="panel-subdomain" class="card hidden">
  <label for="domain-input">Root Domain</label>
  <div class="row">
    <div>
      <input type="text" id="domain-input" placeholder="example.com"
             onkeydown="if(event.key==='Enter')startSubdomain()">
    </div>
    <button class="btn" id="btn-subdomain" onclick="startSubdomain()">🌐 Discover &amp; Scan</button>
  </div>
  <p style="font-size:.8rem;color:var(--muted);margin-top:.6rem;">
    Queries Certificate Transparency logs + DNS wordlist to find all accessible subdomains,
    then runs the full scanner suite on each one.
  </p>

  <div class="progress-wrap" id="sub-progress">
    <div class="phase-label" id="sub-phase">Starting…</div>
    <div class="detail-label" id="sub-detail"></div>
    <div class="progress-bar-bg" style="margin-bottom:.8rem;">
      <div class="progress-bar" id="sub-bar"></div>
    </div>
    <div style="font-size:.82rem;color:var(--muted);" id="sub-counter"></div>
    <div class="targets-grid" id="targets-grid"></div>
  </div>
</div>

<!-- Results panel -->
<div id="results">
  <div class="summary-row" id="summary-row"></div>
  <div id="results-body"></div>
</div>

</div><!-- /max-width -->

<script>
// ── Tab switching ─────────────────────────────────────────────────────────────
let currentTab = 'single';
function switchTab(t) {
  currentTab = t;
  document.getElementById('tab-single').classList.toggle('active', t === 'single');
  document.getElementById('tab-subdomain').classList.toggle('active', t === 'subdomain');
  document.getElementById('panel-single').classList.toggle('hidden', t !== 'single');
  document.getElementById('panel-subdomain').classList.toggle('hidden', t !== 'subdomain');
  document.getElementById('results').classList.remove('show');
  document.getElementById('results-body').innerHTML = '';
  document.getElementById('summary-row').innerHTML = '';
}

// ── Single URL scan ───────────────────────────────────────────────────────────
async function startSingle() {
  const url = document.getElementById('url-input').value.trim();
  if (!url) return;
  const btn = document.getElementById('btn-single');
  btn.disabled = true;
  document.getElementById('single-progress').classList.add('show');
  document.getElementById('single-phase').textContent = `Scanning ${url}…`;
  document.getElementById('results').classList.remove('show');

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url})
    });
    const data = await res.json();
    if (data.error) { alert(data.error); return; }
    renderResults([data]);
  } catch(e) {
    alert('Scan failed: ' + e.message);
  } finally {
    btn.disabled = false;
    document.getElementById('single-progress').classList.remove('show');
  }
}

// ── Subdomain scan ────────────────────────────────────────────────────────────
let _pollTimer = null;

async function startSubdomain() {
  let domain = document.getElementById('domain-input').value.trim()
    .replace(/^https?:\/\//i, '').split('/')[0];
  if (!domain) return;

  const btn = document.getElementById('btn-subdomain');
  btn.disabled = true;
  clearInterval(_pollTimer);

  document.getElementById('sub-progress').classList.add('show');
  document.getElementById('sub-phase').textContent = 'Starting…';
  document.getElementById('sub-detail').textContent = '';
  document.getElementById('sub-counter').textContent = '';
  document.getElementById('sub-bar').style.width = '0%';
  document.getElementById('targets-grid').innerHTML = '';
  document.getElementById('results').classList.remove('show');
  document.getElementById('results-body').innerHTML = '';
  document.getElementById('summary-row').innerHTML = '';

  let jobId;
  try {
    const res = await fetch('/api/subdomain-scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({domain})
    });
    const data = await res.json();
    if (data.error) { alert(data.error); btn.disabled = false; return; }
    jobId = data.job_id;
  } catch(e) {
    alert('Failed to start: ' + e.message);
    btn.disabled = false;
    return;
  }

  // Poll for status every 2 seconds
  const chipState = {};
  _pollTimer = setInterval(async () => {
    try {
      const res = await fetch(`/api/subdomain-scan/status/${jobId}`);
      const st  = await res.json();
      updateSubProgress(st, chipState);

      if (st.status === 'done' || st.status === 'error') {
        clearInterval(_pollTimer);
        btn.disabled = false;
        if (st.status === 'done') {
          // Fetch final full results
          const r2 = await fetch(`/api/subdomain-scan/results/${jobId}`);
          const data = await r2.json();
          renderResults(data.results || []);
        } else {
          alert('Scan error: ' + st.detail);
        }
      }
    } catch(e) { /* ignore transient */ }
  }, 2000);
}

function updateSubProgress(st, chipState) {
  const PHASE_LABELS = {
    queued:      '⏳ Queued',
    discovering: '🔍 Discovering via Certificate Transparency…',
    resolving:   '📡 Resolving DNS…',
    probing:     '🌐 Probing live targets…',
    scanning:    '🔬 Scanning targets…',
    done:        '✅ Complete',
    error:       '❌ Error',
  };
  document.getElementById('sub-phase').textContent =
    PHASE_LABELS[st.phase] || st.phase;
  document.getElementById('sub-detail').textContent = st.detail || '';

  const scanned = st.scanned || 0;
  const total   = st.total   || 0;
  const pct = total > 0 ? Math.round(scanned / total * 100) : (st.phase === 'scanning' ? 5 : 0);
  document.getElementById('sub-bar').style.width = pct + '%';
  document.getElementById('sub-counter').textContent =
    total > 0 ? `${scanned} / ${total} targets scanned` : '';

  // Render target chips
  const grid = document.getElementById('targets-grid');
  const targets = st.targets || [];
  const results = st.results || [];
  const scannedUrls = new Set(results.map(r => r.url));

  targets.forEach(url => {
    let chip = document.getElementById('chip-' + btoa(url).replace(/=/g,''));
    if (!chip) {
      chip = document.createElement('div');
      chip.className = 'target-chip';
      chip.id = 'chip-' + btoa(url).replace(/=/g,'');
      chip.innerHTML = `<span>${url}</span><span class="chip-badge" id="badge-${btoa(url).replace(/=/g,'')}"></span>`;
      grid.appendChild(chip);
    }

    const result = results.find(r => r.url === url);
    const badge = document.getElementById('badge-' + btoa(url).replace(/=/g,''));

    if (result) {
      const s = result.summary || {};
      if (s.fail > 0) {
        chip.className = 'target-chip done-fail';
        if (badge) badge.textContent = `${s.fail} FAIL`;
      } else if (s.warn > 0) {
        chip.className = 'target-chip done-warn';
        if (badge) badge.textContent = `${s.warn} WARN`;
      } else {
        chip.className = 'target-chip done-pass';
        if (badge) badge.textContent = 'PASS';
      }
    } else {
      chip.className = 'target-chip scanning';
      if (badge) badge.innerHTML = '<span class="spinner"></span>';
    }
  });
}

// ── Result rendering ──────────────────────────────────────────────────────────
function renderResults(allResults) {
  const panel = document.getElementById('results');
  const body  = document.getElementById('results-body');
  const sumRow = document.getElementById('summary-row');

  panel.classList.add('show');
  body.innerHTML = '';

  // Aggregate totals
  let totFail = 0, totWarn = 0, totPass = 0;
  allResults.forEach(r => {
    const s = r.summary || {};
    totFail += s.fail  || 0;
    totWarn += s.warn  || 0;
    totPass += s.pass  || 0;
  });

  sumRow.innerHTML = `
    <div class="stat"><div class="num fail">${totFail}</div><div class="lbl">FAIL</div></div>
    <div class="stat"><div class="num warn">${totWarn}</div><div class="lbl">WARN</div></div>
    <div class="stat"><div class="num pass">${totPass}</div><div class="lbl">PASS</div></div>
    <div class="stat"><div class="num" style="color:var(--accent2)">${allResults.length}</div>
      <div class="lbl">Target${allResults.length !== 1 ? 's' : ''}</div></div>
  `;

  // Sort targets: most failures first
  const sorted = [...allResults].sort((a, b) =>
    (b.summary?.fail || 0) - (a.summary?.fail || 0) ||
    (b.summary?.warn || 0) - (a.summary?.warn || 0)
  );

  sorted.forEach((target, ti) => {
    const s = target.summary || {};
    const sec = document.createElement('div');
    sec.className = 'target-section card';

    const header = document.createElement('div');
    header.className = 'target-header';
    const togId = `tgl-${ti}`;
    header.innerHTML = `
      <span class="section-toggle" id="${togId}"></span>
      <span class="target-url">${target.url}</span>
      <span style="color:var(--muted);font-size:.8rem;">${target.duration || 0}s</span>
      <span class="target-badges">
        ${s.fail  ? `<span class="badge fail">${s.fail} FAIL</span>`  : ''}
        ${s.warn  ? `<span class="badge warn">${s.warn} WARN</span>`  : ''}
        ${s.pass  ? `<span class="badge pass">${s.pass} PASS</span>`  : ''}
      </span>
    `;
    header.onclick = () => {
      const list = document.getElementById('list-' + ti);
      const tog  = document.getElementById(togId);
      list.classList.toggle('open');
      tog.classList.toggle('open');
    };

    const list = document.createElement('div');
    list.className = 'scanner-list';
    list.id = 'list-' + ti;

    (target.scanners || []).forEach(sc => {
      if (!sc.findings || sc.findings.length === 0) return;
      const nonPass = sc.findings.filter(f => f.status !== 'PASS');
      if (nonPass.length === 0 && sc.findings.every(f => f.status === 'PASS')) return;

      const scDiv = document.createElement('div');
      scDiv.innerHTML = `<div class="scanner-name">${sc.scanner}</div>`;
      if (sc.error) {
        scDiv.innerHTML += `<div class="error-chip">⚠ ${sc.error}</div>`;
      }
      sc.findings.forEach(f => {
        if (f.status === 'PASS') return; // collapse passing findings
        const fDiv = document.createElement('div');
        fDiv.className = `finding ${f.status}`;
        fDiv.innerHTML = `
          <div class="finding-type">${f.type || f.check_type || ''}</div>
          ${f.detail ? `<div class="finding-detail">${f.detail}</div>` : ''}
        `;
        scDiv.appendChild(fDiv);
      });
      list.appendChild(scDiv);
    });

    // If nothing to show, show summary
    if (!list.children.length) {
      list.innerHTML = `<p style="color:var(--pass);font-size:.85rem;padding:.5rem 0">
        ✅ All ${s.pass} checks passed — no issues detected.
      </p>`;
    }

    sec.appendChild(header);
    sec.appendChild(list);

    // Auto-expand if target has failures
    if (s.fail > 0) {
      list.classList.add('open');
      document.getElementById(togId)?.classList.add('open');
    }

    body.appendChild(sec);
  });

  panel.scrollIntoView({ behavior: 'smooth' });
}
</script>
</body>
</html>"""


# ── HTTP server ───────────────────────────────────────────────────────────────

class _Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        p = self.path.split("?")[0]

        if p in ("/", "/index.html"):
            self._serve_ui()
        elif p == "/api/status":
            self._json(200, {"status": "ok", "scanners": len(SCANNERS)})
        elif p.startswith("/api/subdomain-scan/status/"):
            job_id = p.split("/")[-1]
            self._handle_job_status(job_id)
        elif p.startswith("/api/subdomain-scan/results/"):
            job_id = p.split("/")[-1]
            self._handle_job_results(job_id)
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        p = self.path.split("?")[0]
        if p == "/api/scan":
            self._handle_single_scan()
        elif p == "/api/subdomain-scan":
            self._handle_subdomain_scan_start()
        else:
            self._json(404, {"error": "not found"})

    # ── handlers ────────────────────────────────────────────────────────────

    def _serve_ui(self):
        # Prefer the generated dashboard file if it exists, else serve embedded UI
        dash = Path(__file__).parent / "tblue_dashboard.html"
        if dash.exists():
            body = dash.read_bytes()
        else:
            body = _DASHBOARD_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _handle_single_scan(self):
        payload = self._read_json()
        if payload is None:
            return
        url = payload.get("url", "").strip()
        if not url:
            self._json(400, {"error": "url is required"})
            return
        print(f"[scan] {url}", flush=True)
        self._json(200, scan_url(url))

    def _handle_subdomain_scan_start(self):
        payload = self._read_json()
        if payload is None:
            return
        domain = payload.get("domain", "").strip()
        if not domain:
            self._json(400, {"error": "domain is required"})
            return
        # Normalise: strip scheme/path
        domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
        if not domain or "." not in domain:
            self._json(400, {"error": f"Invalid domain: {domain}"})
            return

        job_id = _new_job(domain)
        t = threading.Thread(target=_run_subdomain_job, args=(job_id, domain), daemon=True)
        t.start()
        print(f"[subdomain-scan] started job {job_id[:8]} for {domain}", flush=True)
        self._json(202, {"job_id": job_id, "domain": domain, "status": "queued"})

    def _handle_job_status(self, job_id: str):
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
        if job is None:
            self._json(404, {"error": "Job not found"})
            return
        # Return lightweight status (no full scan results — use /results for that)
        self._json(200, {
            "job_id":  job["job_id"],
            "domain":  job["domain"],
            "status":  job["status"],
            "phase":   job["phase"],
            "detail":  job["detail"],
            "targets": job["targets"],
            "scanned": job["scanned"],
            "total":   job["total"],
            # Include partial results so the UI can update chips
            "results": [
                {"url": r["url"], "summary": r.get("summary", {})}
                for r in job["results"]
            ],
        })

    def _handle_job_results(self, job_id: str):
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
        if job is None:
            self._json(404, {"error": "Job not found"})
            return
        if job["status"] not in ("done", "error"):
            self._json(202, {"status": job["status"], "message": "Job not yet complete"})
            return
        self._json(200, {
            "job_id":  job["job_id"],
            "domain":  job["domain"],
            "status":  job["status"],
            "targets": job["targets"],
            "results": job["results"],
        })

    # ── helpers ──────────────────────────────────────────────────────────────

    def _read_json(self):
        try:
            cl = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(cl)
            return json.loads(body)
        except Exception as exc:
            self._json(400, {"error": str(exc)})
            return None

    def _json(self, status: int, data):
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Tblue Scanner Server")
    parser.add_argument("--port",       type=int, default=8080)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), _Handler)
    base   = f"http://127.0.0.1:{args.port}"

    print(f"\n  Tblue Scanner Server")
    print(f"  ────────────────────────────────────────")
    print(f"  Dashboard          → {base}/")
    print(f"  Single scan API    → POST {base}/api/scan")
    print(f"  Subdomain scan API → POST {base}/api/subdomain-scan")
    print(f"  Scanners loaded    → {len(SCANNERS)}")
    print(f"\n  Press Ctrl+C to stop.\n")

    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(base)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
        server.shutdown()


if __name__ == "__main__":
    main()
