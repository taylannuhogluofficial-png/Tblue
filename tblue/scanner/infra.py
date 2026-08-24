"""
Infrastructure hardening scanner.

Checks:
- Directory listing on common paths
- Source map exposure (.js.map, .css.map)
- .git/ directory exposure
- IDE/editor artifact exposure (.vscode, .idea, .DS_Store)
- .well-known/openid-configuration exposure (OAuth discovery)
- Referrer-Policy: unsafe-url detection
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_DIR_LISTING_SIGNATURES = re.compile(
    r'Index of /|Directory listing for|<title>Directory listing|'
    r'Parent Directory</a>|<a href="\.\./"|ListBucketResult',
    re.I
)

# Paths to probe for directory listing
_DIR_PROBE_PATHS = [
    "/uploads/", "/images/", "/static/", "/assets/",
    "/media/", "/files/", "/backup/", "/backups/",
    "/logs/", "/data/", "/tmp/", "/temp/",
    "/js/", "/css/", "/fonts/", "/vendor/",
]

# Source map and artifact probes
_ARTIFACT_PROBES = [
    ("/js/app.js.map",          "Source map",   "WARN",
     "Source map exposes original JavaScript source code, potentially revealing "
     "business logic, API endpoints, and code structure. Fix: exclude .map files "
     "from production deployments or serve them only to authenticated developers."),
    ("/js/main.js.map",         "Source map",   "WARN", ""),
    ("/css/app.css.map",        "Source map",   "WARN", ""),
    ("/.git/config",            ".git directory exposed", "FAIL",
     ".git/config is accessible — attackers can download your entire source code "
     "history including secrets committed in the past. Fix: block access to .git/ "
     "in your web server config (Nginx: location ~ /\\.git { deny all; })."),
    ("/.git/HEAD",              ".git directory exposed", "FAIL", ""),
    ("/.vscode/settings.json",  "IDE artifacts exposed", "WARN",
     ".vscode/settings.json reveals editor configuration, potentially including "
     "workspace paths, plugin settings, and linting rules. Fix: exclude .vscode/ "
     "from deployments."),
    ("/.idea/workspace.xml",    "IDE artifacts exposed", "WARN",
     ".idea/ JetBrains IDE files can expose project structure and paths. "
     "Fix: exclude .idea/ from deployments."),
    ("/.DS_Store",              "IDE artifacts exposed", "WARN",
     ".DS_Store files are macOS metadata files that list directory contents. "
     "Attackers use them to enumerate files without directory listing. "
     "Fix: add to .gitignore and deny access in web server config."),
    ("/.env.example",           "Environment template exposed", "WARN",
     ".env.example reveals expected environment variable names and structure — "
     "useful to attackers for targeted secret scanning."),
]


class InfraScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        self._check_directory_listing(url)
        self._check_artifacts(url)
        self._check_openid_config(url)
        self._check_referrer_policy(url)
        return self.results

    # ── Directory listing ─────────────────────────────────────────────────────

    def _check_directory_listing(self, url: str) -> None:
        parsed  = urlparse(url)
        base    = f"{parsed.scheme}://{parsed.netloc}"
        found   = []

        for path in _DIR_PROBE_PATHS:
            try:
                resp = self.http.get(base + path)
                if resp and resp.status_code == 200:
                    if _DIR_LISTING_SIGNATURES.search(resp.text[:4096]):
                        found.append(path)
                        log_fail(logger, f"Directory listing enabled: {path}")
            except Exception:
                continue

        if found:
            paths = ", ".join(found[:5])
            more  = f" (+ {len(found) - 5} more)" if len(found) > 5 else ""
            self.results.append(self._result(url,
                "Directory listing enabled",
                "FAIL",
                detail=(
                    f"Directory listing is enabled on: {paths}{more}. "
                    "Attackers can enumerate all files in these directories, "
                    "finding backups, uploaded files, configuration, and sensitive data. "
                    "Fix: disable directory listing in your web server. "
                    "Nginx: remove 'autoindex on'. Apache: set 'Options -Indexes'."
                )))
        else:
            self.results.append(self._result(url,
                "Directory listing — not detected",
                "PASS",
                detail=f"Directory listing not detected on {len(_DIR_PROBE_PATHS)} common paths."))

    # ── Source maps and IDE artifacts ─────────────────────────────────────────

    def _check_artifacts(self, url: str) -> None:
        parsed    = urlparse(url)
        base      = f"{parsed.scheme}://{parsed.netloc}"
        seen_types: set = set()

        for path, label, status, detail in _ARTIFACT_PROBES:
            if label in seen_types:
                continue
            try:
                resp = self.http.get(base + path)
                if resp and resp.status_code == 200 and len(resp.text) > 10:
                    body = resp.text[:200]
                    if body.strip().startswith("<") and "html" in body.lower():
                        continue  # HTML false positive
                    seen_types.add(label)
                    use_detail = detail or (
                        f"{label} found at {base + path}. "
                        "Remove from production deployments."
                    )
                    log_fail(logger, f"{label} accessible: {path}")
                    self.results.append(self._result(
                        base + path, label, status, detail=use_detail
                    ))
            except Exception:
                continue

    # ── OpenID Connect discovery ───────────────────────────────────────────────

    def _check_openid_config(self, url: str) -> None:
        parsed   = urlparse(url)
        base     = f"{parsed.scheme}://{parsed.netloc}"
        oidc_url = f"{base}/.well-known/openid-configuration"
        try:
            resp = self.http.get(oidc_url)
            if resp and resp.status_code == 200:
                body = resp.text
                if '"issuer"' in body or '"authorization_endpoint"' in body:
                    log_warn(logger, "OpenID Connect discovery endpoint exposed")
                    self.results.append(self._result(url,
                        "OpenID Connect discovery endpoint exposed",
                        "WARN",
                        detail=(
                            f"/.well-known/openid-configuration is publicly accessible at {oidc_url}. "
                            "This reveals your OAuth/OIDC infrastructure: authorization endpoint, "
                            "token endpoint, JWKS URI, and supported scopes. "
                            "If this is intentional (public OIDC provider), this is informational. "
                            "If this is unexpected, restrict access — it maps out your auth architecture."
                        )))
        except Exception:
            pass

    # ── Referrer-Policy ───────────────────────────────────────────────────────

    def _check_referrer_policy(self, url: str) -> None:
        try:
            resp   = self.http.get(url)
            if not resp:
                return
            policy = resp.headers.get("Referrer-Policy", "").lower()
            if not policy:
                return  # base headers scanner already flags missing Referrer-Policy
            if "unsafe-url" in policy:
                log_warn(logger, "Referrer-Policy: unsafe-url leaks full URLs to third parties")
                self.results.append(self._result(url,
                    "Referrer-Policy: unsafe-url — full URL sent to third parties",
                    "WARN",
                    detail=(
                        "Referrer-Policy is set to 'unsafe-url', which sends the full URL "
                        "(including query parameters and path) to every third-party resource your "
                        "page loads. If URLs contain tokens, session IDs, or user data "
                        "(e.g. /reset?token=abc123), those leak to every analytics, CDN, "
                        "and tracker your site loads. "
                        "Fix: use 'strict-origin-when-cross-origin' or 'no-referrer'."
                    )))
            elif "no-referrer-when-downgrade" in policy:
                self.results.append(self._result(url,
                    "Referrer-Policy: no-referrer-when-downgrade (permissive)",
                    "WARN",
                    detail=(
                        "Referrer-Policy 'no-referrer-when-downgrade' sends the full URL to "
                        "all HTTPS third parties. Prefer 'strict-origin-when-cross-origin'."
                    )))
        except Exception:
            pass
