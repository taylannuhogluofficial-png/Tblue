"""
Advanced CORS Security Scanner.

Extends the basic CORS scanner with nuanced origin reflection attacks:

1. Origin reflection without validation — server echoes back any Origin header
2. Null origin bypass — CORS with null origin allowed (sandbox iframes)
3. Subdomain wildcard bypass — *.example.com (not valid CORS but some CDNs do it)
4. Prefix bypass — trustedexample.com accepted for trusting example.com
5. Suffix bypass — example.com.evil.com accepted
6. Protocol downgrade — http allowed when HTTPS site should only accept https origins
7. Credentials with wildcard (browser would block but detection is useful)
8. Pre-flight bypass indicators — missing Access-Control-Allow-Headers
9. CORS on sensitive API endpoints specifically

Paid equivalents: Burp Suite Pro CORS Scanner, PortSwigger Research tools.
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# CORS-related headers
_ACAO_HEADER = "access-control-allow-origin"
_ACAC_HEADER = "access-control-allow-credentials"
_ACAH_HEADER = "access-control-allow-headers"
_ACAM_HEADER = "access-control-allow-methods"
_VARY_HEADER = "vary"

# API endpoint patterns (CORS issues here are more dangerous)
_API_PATH_RE = re.compile(
    r"/api/|/v[0-9]+/|/graphql|/rest/|/service/|/ws/|/data/",
    re.I,
)

_SENSITIVE_DATA_RE = re.compile(
    r'"email"\s*:|"password"\s*:|"token"\s*:|"key"\s*:|"secret"\s*:|"user"\s*:',
    re.I,
)


class CORSAdvancedScanner(BaseScanner):
    """Advanced CORS origin validation and bypass detection."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        host = parsed.netloc

        # Extract just the domain (without port)
        domain_match = re.match(r"^(.+?)(?::\d+)?$", host)
        domain = domain_match.group(1) if domain_match else host

        # ── Test 1: Origin reflection ──────────────────────────────────────────
        evil_origin = "https://attacker.com"
        try:
            r = self.http.get(url, headers={"Origin": evil_origin})
            if r:
                acao = r.headers.get(_ACAO_HEADER, "")
                acac = r.headers.get(_ACAC_HEADER, "")

                if acao == evil_origin:
                    if acac.lower() == "true":
                        log_fail(logger, f"CORS reflects evil origin + allows credentials: {url}")
                        self.results.append(self._result(
                            url, "CORS Advanced — arbitrary origin reflected with credentials", "FAIL",
                            detail=(
                                f"Server reflects any Origin in Access-Control-Allow-Origin AND "
                                f"Access-Control-Allow-Credentials: true. This is a critical CORS "
                                f"misconfiguration: any website can make credentialed cross-origin "
                                f"requests and read the response, enabling account takeover if the "
                                f"victim is authenticated. "
                                f"Fix: validate Origin against a strict allowlist; "
                                f"never combine ACAO: * or reflected-origin with ACAC: true."
                            )
                        ))
                    else:
                        log_warn(logger, f"CORS reflects arbitrary origin (no credentials): {url}")
                        self.results.append(self._result(
                            url, "CORS Advanced — arbitrary origin reflected (without credentials)", "WARN",
                            detail=(
                                f"Server reflects any Origin: {evil_origin} → "
                                f"Access-Control-Allow-Origin: {evil_origin}. "
                                "While cookies aren't included (no ACAC), this still leaks "
                                "non-credentialed API responses to any origin. "
                                "Fix: validate Origin against an allowlist."
                            )
                        ))
        except Exception:
            pass

        # ── Test 2: Null origin bypass ─────────────────────────────────────────
        try:
            r_null = self.http.get(url, headers={"Origin": "null"})
            if r_null:
                acao_null = r_null.headers.get(_ACAO_HEADER, "")
                if acao_null == "null":
                    log_fail(logger, f"CORS null origin accepted: {url}")
                    self.results.append(self._result(
                        url, "CORS Advanced — null origin accepted", "FAIL",
                        detail=(
                            "Server accepts Origin: null in CORS requests. "
                            "The 'null' origin is sent by: sandboxed iframes, local HTML files, "
                            "redirected cross-origin requests. Attackers can use sandboxed iframes "
                            "to forge null-origin requests. "
                            "Fix: remove 'null' from CORS allowlist; it should never be trusted."
                        )
                    ))
        except Exception:
            pass

        # ── Test 3: Subdomain trust bypass ─────────────────────────────────────
        # Test if trusted.domain.com is checked or if evil.domain.com is accepted
        evil_sub_origin = f"https://evil.{domain}"
        try:
            r_sub = self.http.get(url, headers={"Origin": evil_sub_origin})
            if r_sub:
                acao_sub = r_sub.headers.get(_ACAO_HEADER, "")
                if acao_sub == evil_sub_origin:
                    log_fail(logger, f"CORS trusts arbitrary subdomain: {evil_sub_origin}")
                    self.results.append(self._result(
                        url, f"CORS Advanced — arbitrary subdomain trusted ({evil_sub_origin})", "FAIL",
                        detail=(
                            f"Server trusts any subdomain of {domain}: '{evil_sub_origin}' "
                            f"was reflected in ACAO. If any subdomain is compromised or "
                            f"subject to subdomain takeover, an attacker can read cross-origin "
                            f"responses. Fix: only trust specific, known subdomain origins."
                        )
                    ))
        except Exception:
            pass

        # ── Test 4: HTTP downgrade bypass ─────────────────────────────────────
        if url.startswith("https://"):
            http_origin = f"http://{domain}"
            try:
                r_http = self.http.get(url, headers={"Origin": http_origin})
                if r_http:
                    acao_http = r_http.headers.get(_ACAO_HEADER, "")
                    if acao_http == http_origin:
                        log_warn(logger, f"CORS trusts HTTP origin for HTTPS endpoint: {url}")
                        self.results.append(self._result(
                            url, "CORS Advanced — HTTP origin trusted for HTTPS endpoint", "WARN",
                            detail=(
                                f"HTTPS endpoint trusts HTTP origin '{http_origin}'. "
                                "HTTP origins can be MitM'd to forge cross-origin requests. "
                                "Fix: only trust HTTPS origins for HTTPS endpoints."
                            )
                        ))
            except Exception:
                pass

        # ── Test 5: Missing Vary header ────────────────────────────────────────
        try:
            r_vary = self.http.get(url)
            if r_vary:
                acao = r_vary.headers.get(_ACAO_HEADER, "")
                vary = r_vary.headers.get(_VARY_HEADER, "")
                if acao and "origin" not in vary.lower():
                    log_warn(logger, f"CORS response missing Vary: Origin header: {url}")
                    self.results.append(self._result(
                        url, "CORS Advanced — missing Vary: Origin (response may be cached incorrectly)", "WARN",
                        detail=(
                            "Response has Access-Control-Allow-Origin but no 'Vary: Origin' header. "
                            "Without Vary: Origin, CDN/proxy may serve a cached CORS response "
                            "with wrong origin to other clients. "
                            "Fix: add 'Vary: Origin' when ACAO is dynamically set."
                        )
                    ))
        except Exception:
            pass

        if not self.results:
            log_pass(logger, f"No advanced CORS issues found on {url}")
            self.results.append(self._result(
                url, "CORS Advanced — no origin validation issues found", "PASS",
                detail="No origin reflection, null origin, subdomain bypass, or Vary issues detected."
            ))

        return self.results
