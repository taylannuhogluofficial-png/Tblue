"""
Cross-Domain Policy & Mobile App Link Security Scanner.

Covers four families of cross-origin trust configuration files:

1. crossdomain.xml (Adobe Flash cross-domain policy)
   - Still exploitable via PDF readers with Flash support, Unity WebGL,
     and enterprise applications using legacy Flash embeds.
   - Permissive `<allow-access-from domain="*"/>` lets any origin read
     authenticated responses, bypassing the Same-Origin Policy.
   - CWE-183, CWE-284. Checked by Acunetix, Invicti, Detectify.

2. clientaccesspolicy.xml (Microsoft Silverlight cross-domain policy)
   - Silverlight is EOL but policy files still exist and some tooling
     respects them. `<domain uri="*"/>` is the dangerous pattern.
   - CWE-284. Checked by Acunetix, OWASP WSTG-CONF-08.

3. Apple App Site Association / AASA (iOS Universal Links)
   - iOS Universal Links are configured via /.well-known/apple-app-site-association.
   - Misconfiguration risks:
     a) File missing → any app could claim the URL scheme (only via older URL schemes,
        not Universal Links, but the absence prevents legitimate deep-link protection).
     b) Wildcard path "paths": ["*"] → all paths claimable by the configured app.
     c) Overly short app prefix (fingerprints the iOS app team ID + bundle ID).
   - CWE-284. Checked by Detectify, PortSwigger research.

4. Android Asset Links (assetlinks.json)
   - Android App Links are configured via /.well-known/assetlinks.json.
   - Misconfiguration risks:
     a) Wrong or missing SHA-256 fingerprint → any app with the right package name
        could claim the links.
     b) `"relation": ["delegate_permission/common.handle_all_urls"]` with wrong
        package name → link hijacking.
   - CWE-284. Checked by Detectify.

OWASP Testing Guide: WSTG-CONF-08 (Test HTTP Methods / Cross-Domain Policies).
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# ── crossdomain.xml patterns ─────────────────────────────────────────────────

_CROSSDOMAIN_VALID_RE = re.compile(
    r'<\s*cross-domain-policy\b|<\s*allow-access-from\b|<\s*site-control\b',
    re.I,
)

# Wildcard domain — allows any origin (exact * only, not *.subdomain)
_CROSSDOMAIN_WILDCARD_RE = re.compile(
    r"""<\s*allow-access-from\s[^>]*domain\s*=\s*(?:['"]\*['"]|\*(?:\s|/|>))""",
    re.I,
)

# Wildcard on headers — allows any origin to send any header
_CROSSDOMAIN_HEADER_WILDCARD_RE = re.compile(
    r'<\s*allow-http-request-headers-from\s[^>]*domain\s*=\s*["\']?\s*\*\s*["\']?',
    re.I,
)

# Allows all subdomains (*.example.com pattern)
_CROSSDOMAIN_SUBDOMAIN_RE = re.compile(
    r'<\s*allow-access-from\s[^>]*domain\s*=\s*["\']?\s*\*\.',
    re.I,
)

# secure="false" — allows HTTPS-hosted Flash to read HTTP resources
_CROSSDOMAIN_INSECURE_RE = re.compile(
    r'<\s*allow-access-from\s[^>]*secure\s*=\s*["\']?false["\']?',
    re.I,
)

# ── clientaccesspolicy.xml patterns ──────────────────────────────────────────

_CLIENTACCESS_VALID_RE = re.compile(
    r'<\s*access-policy\b|<\s*cross-domain-access\b|<\s*policy\b',
    re.I,
)

_CLIENTACCESS_WILDCARD_RE = re.compile(
    r'<\s*domain\s[^>]*uri\s*=\s*["\']?\s*\*\s*["\']?',
    re.I,
)

_CLIENTACCESS_ALL_PATHS_RE = re.compile(
    r'<\s*resource\s[^>]*path\s*=\s*["\']?\s*/\s*["\']?[^>]*include-subpaths\s*=\s*["\']?true',
    re.I,
)

# ── Apple App Site Association patterns ──────────────────────────────────────

_AASA_VALID_RE = re.compile(r'"applinks"\s*:', re.I)
_AASA_DETAILS_RE = re.compile(r'"details"\s*:', re.I)
_AASA_APP_ID_RE = re.compile(r'"appID"\s*:\s*"([^"]+)"', re.I)
_AASA_APPS_RE = re.compile(r'"apps"\s*:\s*\[([^\]]*)\]', re.I)
_AASA_WEBCREDENTIALS_RE = re.compile(r'"webcredentials"\s*:', re.I)

# ── Android Asset Links patterns ─────────────────────────────────────────────

_ASSETLINKS_VALID_RE = re.compile(r'"relation"\s*:', re.I)
_ASSETLINKS_HANDLE_URLS_RE = re.compile(
    r'delegate_permission/common\.handle_all_urls',
    re.I,
)
_ASSETLINKS_PACKAGE_RE = re.compile(r'"package_name"\s*:\s*"([^"]+)"', re.I)
_ASSETLINKS_FINGERPRINT_RE = re.compile(
    r'"sha256_cert_fingerprints"\s*:\s*\[([^\]]*)\]',
    re.I,
)


class CrossDomainPolicyScanner(BaseScanner):
    """Detect misconfigured cross-domain policy files and mobile app link security files."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Cross-domain policy — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        self._check_crossdomain(base)
        self._check_clientaccess(base)
        self._check_aasa(base)
        self._check_assetlinks(base)

        if not any(r["status"] in ("FAIL", "WARN") for r in self.results):
            log_pass(logger, f"Cross-domain policy — no policy misconfigurations found on {base}")
            self.results.append(self._result(
                url,
                "Cross-domain policy — no permissive cross-domain policy files found",
                "PASS",
                detail=(
                    "Checked for: crossdomain.xml (Flash), clientaccesspolicy.xml (Silverlight), "
                    "apple-app-site-association (iOS Universal Links), and assetlinks.json "
                    "(Android App Links). No permissive wildcard policies found."
                )
            ))

        return self.results

    def _check_crossdomain(self, base: str) -> None:
        for path in ["/crossdomain.xml", "/flash/crossdomain.xml", "/static/crossdomain.xml"]:
            url = base + path
            try:
                r = self.http.get(url)
                if r is None or r.status_code != 200:
                    continue
                body = r.text or ""
                if not _CROSSDOMAIN_VALID_RE.search(body):
                    continue

                # File exists with valid Flash policy structure
                if _CROSSDOMAIN_WILDCARD_RE.search(body):
                    log_fail(logger, f"crossdomain.xml allows all origins at {url}")
                    self.results.append(self._result(
                        url,
                        "Cross-domain policy — crossdomain.xml allows all origins (*)",
                        "FAIL",
                        detail=(
                            f"crossdomain.xml at {url} contains "
                            "'<allow-access-from domain=\"*\"/>'. "
                            "This permits any origin to make authenticated cross-origin requests "
                            "via Flash/PDF embeds, reading session data and bypassing SOP. "
                            "Fix: remove the file, or restrict to specific trusted domains. "
                            "CWE-183, CWE-284. OWASP WSTG-CONF-08."
                        ),
                    ))
                elif _CROSSDOMAIN_HEADER_WILDCARD_RE.search(body):
                    log_fail(logger, f"crossdomain.xml allows all header origins at {url}")
                    self.results.append(self._result(
                        url,
                        "Cross-domain policy — crossdomain.xml allows headers from all origins",
                        "FAIL",
                        detail=(
                            f"crossdomain.xml at {url} contains "
                            "'<allow-http-request-headers-from domain=\"*\"/>'. "
                            "This permits any origin to send arbitrary request headers cross-origin. "
                            "Fix: restrict to specific trusted domains. CWE-284."
                        ),
                    ))
                elif _CROSSDOMAIN_INSECURE_RE.search(body):
                    log_warn(logger, f"crossdomain.xml has secure=false at {url}")
                    self.results.append(self._result(
                        url,
                        "Cross-domain policy — crossdomain.xml allows HTTP from HTTPS context",
                        "WARN",
                        detail=(
                            f"crossdomain.xml at {url} contains 'secure=\"false\"', "
                            "allowing HTTPS-hosted applications to load resources over HTTP. "
                            "Fix: remove 'secure=\"false\"' or restrict to trusted HTTPS origins. "
                            "CWE-311."
                        ),
                    ))
                elif _CROSSDOMAIN_SUBDOMAIN_RE.search(body):
                    log_warn(logger, f"crossdomain.xml allows wildcard subdomains at {url}")
                    self.results.append(self._result(
                        url,
                        "Cross-domain policy — crossdomain.xml uses wildcard subdomain",
                        "WARN",
                        detail=(
                            f"crossdomain.xml at {url} allows '*.domain.com', "
                            "which trusts all subdomains including potentially compromised ones. "
                            "Fix: enumerate specific trusted subdomains rather than using wildcards. "
                            "CWE-183."
                        ),
                    ))
                else:
                    log_warn(logger, f"crossdomain.xml present at {url} — review manually")
                    self.results.append(self._result(
                        url,
                        "Cross-domain policy — crossdomain.xml present (review allowed domains)",
                        "WARN",
                        detail=(
                            f"crossdomain.xml exists at {url}. "
                            "Review the allowed domains to ensure no overly broad trust. "
                            "If Flash/Silverlight is not used, remove the file entirely. "
                            "CWE-284. OWASP WSTG-CONF-08."
                        ),
                    ))
            except Exception:
                continue

    def _check_clientaccess(self, base: str) -> None:
        url = base + "/clientaccesspolicy.xml"
        try:
            r = self.http.get(url)
            if r is None or r.status_code != 200:
                return
            body = r.text or ""
            if not _CLIENTACCESS_VALID_RE.search(body):
                return

            if _CLIENTACCESS_WILDCARD_RE.search(body):
                log_fail(logger, f"clientaccesspolicy.xml allows all origins at {url}")
                self.results.append(self._result(
                    url,
                    "Cross-domain policy — clientaccesspolicy.xml allows all origins (*)",
                    "FAIL",
                    detail=(
                        f"clientaccesspolicy.xml at {url} contains '<domain uri=\"*\"/>'. "
                        "Any origin can make cross-domain Silverlight requests. "
                        "Fix: remove or restrict to specific trusted domains. CWE-284."
                    ),
                ))
            elif _CLIENTACCESS_ALL_PATHS_RE.search(body):
                log_warn(logger, f"clientaccesspolicy.xml exposes all paths at {url}")
                self.results.append(self._result(
                    url,
                    "Cross-domain policy — clientaccesspolicy.xml exposes all paths",
                    "WARN",
                    detail=(
                        f"clientaccesspolicy.xml at {url} includes the root path '/' with "
                        "include-subpaths='true', exposing all application resources. "
                        "Fix: restrict to specific paths. CWE-284."
                    ),
                ))
            else:
                log_warn(logger, f"clientaccesspolicy.xml present at {url} — review manually")
                self.results.append(self._result(
                    url,
                    "Cross-domain policy — clientaccesspolicy.xml present (review)",
                    "WARN",
                    detail=(
                        f"clientaccesspolicy.xml exists at {url}. "
                        "Silverlight is EOL — if not needed, remove the file. "
                        "CWE-284."
                    ),
                ))
        except Exception:
            pass

    def _check_aasa(self, base: str) -> None:
        for path in ["/.well-known/apple-app-site-association", "/apple-app-site-association"]:
            url = base + path
            try:
                r = self.http.get(url)
                if r is None or r.status_code != 200:
                    continue
                body = r.text or ""
                if not _AASA_VALID_RE.search(body) and not _AASA_WEBCREDENTIALS_RE.search(body):
                    continue

                # File exists — check for app ID disclosure
                app_ids = _AASA_APP_ID_RE.findall(body)

                if app_ids:
                    log_warn(logger, f"AASA file discloses iOS app IDs at {url}")
                    ids_preview = ", ".join(app_ids[:3])
                    self.results.append(self._result(
                        url,
                        "Mobile deep link — apple-app-site-association discloses iOS app identifiers",
                        "WARN",
                        detail=(
                            f"apple-app-site-association at {url} reveals iOS Team ID and "
                            f"Bundle ID(s): {ids_preview}. "
                            "These identifiers can be used to fingerprint the application and "
                            "may assist in targeted attacks against the iOS app. "
                            "This is expected behavior for Universal Links but should be reviewed "
                            "to ensure only the correct apps are listed. CWE-200."
                        ),
                    ))
                else:
                    log_warn(logger, f"AASA file present at {url}")
                    self.results.append(self._result(
                        url,
                        "Mobile deep link — apple-app-site-association present (review app IDs)",
                        "WARN",
                        detail=(
                            f"apple-app-site-association exists at {url}. "
                            "Review to ensure only authorized iOS apps are listed. CWE-284."
                        ),
                    ))
                return  # Only report once (first path found)
            except Exception:
                continue

    def _check_assetlinks(self, base: str) -> None:
        url = base + "/.well-known/assetlinks.json"
        try:
            r = self.http.get(url)
            if r is None or r.status_code != 200:
                return
            body = r.text or ""
            if not _ASSETLINKS_VALID_RE.search(body):
                return

            packages = _ASSETLINKS_PACKAGE_RE.findall(body)
            fingerprints_match = _ASSETLINKS_FINGERPRINT_RE.findall(body)
            has_handle_all = bool(_ASSETLINKS_HANDLE_URLS_RE.search(body))

            if has_handle_all and not any(f.strip() for f in fingerprints_match):
                log_fail(logger, f"assetlinks.json without SHA-256 fingerprints at {url}")
                self.results.append(self._result(
                    url,
                    "Mobile deep link — assetlinks.json missing SHA-256 fingerprints",
                    "FAIL",
                    detail=(
                        f"assetlinks.json at {url} claims 'delegate_permission/common.handle_all_urls' "
                        "but has no or empty SHA-256 certificate fingerprints. "
                        "Without fingerprint verification, any APK with the matching package name "
                        "can claim the Android App Links. "
                        "Fix: add the correct SHA-256 fingerprint of your signing certificate. "
                        "CWE-284."
                    ),
                ))
            elif packages:
                pkg_preview = ", ".join(packages[:3])
                log_warn(logger, f"assetlinks.json discloses Android package names at {url}")
                self.results.append(self._result(
                    url,
                    "Mobile deep link — assetlinks.json discloses Android package names",
                    "WARN",
                    detail=(
                        f"assetlinks.json at {url} reveals Android package name(s): {pkg_preview}. "
                        "This is expected for App Links but review to ensure only the correct "
                        "packages with valid SHA-256 fingerprints are listed. "
                        "CWE-200."
                    ),
                ))
            else:
                log_warn(logger, f"assetlinks.json present at {url}")
                self.results.append(self._result(
                    url,
                    "Mobile deep link — assetlinks.json present (review)",
                    "WARN",
                    detail=(
                        f"assetlinks.json exists at {url}. "
                        "Review to ensure correct package names and SHA-256 fingerprints. CWE-284."
                    ),
                ))
        except Exception:
            pass
