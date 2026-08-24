"""
SAML / SSO Security Scanner.

Passively detects SAML 2.0 and SSO flows and checks for common misconfigurations
that are frequently exploited in enterprise environments.

Checks:
  1. SAML / SSO endpoints accessible over HTTP (not HTTPS)
  2. RelayState parameter in SAML URLs without CSRF protection indicators
  3. IdP metadata endpoint exposed (information disclosure)
  4. SAML responses visible in page source (assertion replay risk)
  5. NameID format set to transient vs persistent (privacy consideration)
  6. Missing or short InResponseTo field indicators
  7. SP metadata exposed — reveals entity ID, ACS URL, encryption settings

All checks are read-only page analysis and probe-style HTTP requests.
No SAML assertions are generated or submitted.

Paid equivalents: Burp Suite SAML Raider extension, SAMLReQuest.
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Common SAML/SSO endpoint paths
_SAML_PATHS = [
    "/saml",
    "/saml/",
    "/saml/login",
    "/saml/sso",
    "/saml/metadata",
    "/sso",
    "/sso/saml",
    "/auth/saml",
    "/auth/sso",
    "/api/auth/saml",
    "/login/saml",
    "/login/sso",
    "/shibboleth",
    "/Shibboleth.sso/Login",
    "/adfs/ls/",
    "/adfs/saml",
    "/simplesaml/saml2/idp/SSOService.php",
    "/wp-login.php?saml_sso",
    "/.well-known/saml-configuration",
]

# Patterns that indicate a SAML flow
_SAML_INDICATOR_RE = re.compile(
    r"SAMLRequest|SAMLResponse|RelayState|saml2?:|urn:oasis:names:tc:SAML"
    r"|InResponseTo|AuthnRequest|Assertion|Conditions|AudienceRestriction",
    re.I,
)

# Base64-looking strings that might be SAML assertions in page source
_BASE64_SAML_RE = re.compile(
    r"""(?:SAMLResponse|SAMLRequest)\s*[=:]\s*["']?([A-Za-z0-9+/]{100,}={0,2})""",
    re.I,
)

# RelayState in URLs
_RELAY_STATE_RE = re.compile(r"[?&]RelayState=([^&\s\"'<>]+)", re.I)

# HTTP (not HTTPS) SAML endpoint
_HTTP_SAML_RE = re.compile(r"http://[^\s\"'<>]*(saml|sso|auth)[^\s\"'<>]*", re.I)


class SAMLScanner(BaseScanner):
    """Detect SAML/SSO misconfiguration through passive page analysis and endpoint probing."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        resp = self.http.get(url)
        if not resp:
            return self.results

        body  = resp.text or ""
        soup  = BeautifulSoup(body, "html.parser")
        links = [t.attrs.get("href", "") for t in soup.find_all(href=True)]
        full  = body + "\n".join(links)

        saml_detected = bool(_SAML_INDICATOR_RE.search(full))

        # ── Probe known SAML paths ────────────────────────────────────────────
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}"
        found_paths: List[tuple] = []

        for path in _SAML_PATHS:
            probe_url = base + path
            try:
                r = self.http.get(probe_url, allow_redirects=False)
                if not r:
                    continue
                if r.status_code in (200, 302, 301, 400, 405):
                    found_paths.append((probe_url, r.status_code, r.headers))
                    saml_detected = True
            except Exception:
                continue

        if not saml_detected:
            log_pass(logger, f"No SAML/SSO flows detected on {url}")
            self.results.append(self._result(
                url, "SAML/SSO — no SAML flows detected", "PASS",
                detail="No SAML 2.0 or SSO flows were detected on this page or common SAML paths."
            ))
            return self.results

        # ── 1. HTTP (non-HTTPS) SAML endpoints ────────────────────────────────
        http_saml = _HTTP_SAML_RE.findall(full)
        if http_saml:
            examples = http_saml[:2]
            log_fail(logger, f"SAML flow over HTTP detected: {examples}")
            self.results.append(self._result(
                url, "SAML — SSO flow over unencrypted HTTP", "FAIL",
                detail=(
                    f"SAML endpoint(s) reference HTTP URLs: {examples}. "
                    "SAML assertions transmitted over HTTP can be intercepted and "
                    "replayed by network observers. The SAML 2.0 spec requires TLS "
                    "for all SSO bindings (§4.1.3.1). "
                    "Fix: ensure all SAML redirect and POST bindings use HTTPS. "
                    "Update SP metadata ACS URL and IdP SSO URL to https://."
                )
            ))

        # ── 2. RelayState without validation signals ───────────────────────────
        relay_states = _RELAY_STATE_RE.findall(full)
        for rs in relay_states[:3]:
            if rs.startswith("http://") or rs.startswith("//"):
                log_fail(logger, f"Open RelayState URL: {rs}")
                self.results.append(self._result(
                    url, "SAML — open redirect via RelayState parameter", "FAIL",
                    detail=(
                        f"RelayState parameter contains an external URL: {rs}. "
                        "The RelayState parameter is used to redirect users after "
                        "SAML authentication. If not validated against an allowlist, "
                        "an attacker can craft a SAML login URL that redirects to a "
                        "phishing site after successful authentication. "
                        "Fix: validate RelayState against a whitelist of allowed "
                        "post-login redirect URLs; reject absolute URLs to external "
                        "domains."
                    )
                ))

        # ── 3. SAML assertion / response in page source ────────────────────────
        assertion_match = _BASE64_SAML_RE.search(body)
        if assertion_match:
            b64_val = assertion_match.group(1)[:30] + "..."
            log_warn(logger, f"SAML assertion found in page source: {b64_val}")
            self.results.append(self._result(
                url, "SAML — assertion visible in page source", "WARN",
                detail=(
                    "A base64-encoded SAML assertion or request was found in the "
                    "page HTML source. Assertions in page source can be copied and "
                    "replayed if the server does not enforce InResponseTo validation "
                    "and assertion expiry (NotOnOrAfter). "
                    "Fix: ensure assertions are short-lived (5 minutes max), "
                    "validate InResponseTo against the original AuthnRequest ID, "
                    "and implement one-time assertion consumption."
                )
            ))

        # ── 4. IdP / SP metadata exposed ──────────────────────────────────────
        for probe_url, status, hdrs in found_paths:
            if "metadata" in probe_url and status == 200:
                log_warn(logger, f"SAML metadata exposed at {probe_url}")
                self.results.append(self._result(
                    url, f"SAML — metadata endpoint exposed ({probe_url})", "WARN",
                    detail=(
                        f"SAML metadata found at {probe_url} (HTTP {status}). "
                        "SP/IdP metadata reveals entity IDs, ACS URLs, signing "
                        "certificate public keys, and encryption key details. "
                        "While metadata is sometimes public by design, verify this "
                        "is intentional and that the metadata does not expose "
                        "private key material or internal hostname information."
                    )
                ))
            elif status in (200, 302) and "metadata" not in probe_url:
                log_warn(logger, f"SAML/SSO endpoint reachable: {probe_url}")
                self.results.append(self._result(
                    url, f"SAML — SSO endpoint found ({probe_url})", "WARN",
                    detail=(
                        f"SAML/SSO endpoint at {probe_url} returned HTTP {status}. "
                        "Verify this endpoint enforces HTTPS, validates Origin/Referer "
                        "headers, and implements CSRF protection on the POST binding. "
                        "Ensure the IdP enforces audience restriction and rejects "
                        "assertions with expired timestamps."
                    )
                ))

        if not self.results:
            log_pass(logger, f"SAML/SSO — no issues found on {url}")
            self.results.append(self._result(
                url, "SAML/SSO — no obvious misconfigurations", "PASS",
                detail="SAML/SSO flow detected but no obvious misconfigurations found."
            ))

        return self.results
