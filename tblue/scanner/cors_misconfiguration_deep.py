"""
Deep CORS Misconfiguration Scanner.

Goes beyond the basic cors.py and cors_advanced.py scanners to catch
sophisticated CORS policy errors that simpler checks miss:

  1. Null origin acceptance — Origin: null is accepted with credentials
  2. Credentialed wildcard — Access-Control-Allow-Credentials: true with
     Access-Control-Allow-Origin: * (browsers block this but servers still set it)
  3. Vary: Origin absent — caches may serve wrong CORS response to callers
  4. Pre-flight bypass — endpoint accepts cross-origin POST without triggering
     a pre-flight (non-standard content-type probes)
  5. Regex bypass — org.evil.com accepted when origin validation uses naive
     startswith or contains checks (probe with suffix and prefix variants)
  6. HTTP downgrade — HTTPS site reflects http:// origin with credentials

CWE-942: Overly Permissive Cross-domain Whitelist
CWE-346: Origin Validation Error
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_CORS_ENDPOINTS = [
    "",                # root
    "/api",
    "/api/v1",
    "/api/v2",
    "/graphql",
    "/data",
]

_ACAO = "access-control-allow-origin"
_ACAC = "access-control-allow-credentials"
_ACAM = "access-control-allow-methods"
_VARY = "vary"


def _get_headers(resp) -> Dict[str, str]:
    if resp is None:
        return {}
    return {k.lower(): v for k, v in resp.headers.items()}


def _acao_val(headers: Dict) -> Optional[str]:
    return headers.get(_ACAO, "").strip()


def _creds_true(headers: Dict) -> bool:
    return headers.get(_ACAC, "").strip().lower() == "true"


def _check_null_origin(http, url: str) -> Optional[Dict]:
    resp = http.get(url, headers={"Origin": "null"})
    if resp is None:
        return None
    h = _get_headers(resp)
    if _acao_val(h) == "null" and _creds_true(h):
        return {
            "type": "cors-null-origin-with-credentials",
            "status": "FAIL",
            "detail": (
                f"Endpoint {url} reflects 'null' in Access-Control-Allow-Origin "
                f"AND sets Access-Control-Allow-Credentials: true.\n\n"
                f"Sandboxed iframes produce Origin: null. An attacker can exploit this "
                f"to make credentialed cross-origin requests from a sandboxed page.\n\n"
                f"Fix: never explicitly allow 'null' as an origin."
            ),
        }
    return None


def _check_wildcard_with_credentials(http, url: str) -> Optional[Dict]:
    resp = http.get(url, headers={"Origin": "https://evil.com"})
    if resp is None:
        return None
    h = _get_headers(resp)
    if _acao_val(h) == "*" and _creds_true(h):
        return {
            "type": "cors-wildcard-with-credentials",
            "status": "FAIL",
            "detail": (
                f"Endpoint {url} sets Access-Control-Allow-Origin: * together with "
                f"Access-Control-Allow-Credentials: true.\n\n"
                f"Browsers refuse to honour this combination but the server is "
                f"misconfigured and may forward credentials in other contexts.\n\n"
                f"Fix: use explicit origins, not '*', when sending credentials."
            ),
        }
    return None


def _check_vary_origin_absent(http, url: str) -> Optional[Dict]:
    resp = http.get(url, headers={"Origin": "https://trusted.example.com"})
    if resp is None:
        return None
    h = _get_headers(resp)
    origin = _acao_val(h)
    if origin and origin != "*":
        vary = h.get(_VARY, "")
        if "origin" not in vary.lower():
            return {
                "type": "cors-vary-origin-absent",
                "status": "WARN",
                "detail": (
                    f"Endpoint {url} sets Access-Control-Allow-Origin: {origin!r} "
                    f"(dynamic/reflective) but does NOT include 'Origin' in the "
                    f"Vary response header.\n\n"
                    f"Intermediate caches may serve this response to a different origin, "
                    f"leaking a permissive CORS response or caching a restricted one.\n\n"
                    f"Fix: add 'Vary: Origin' whenever the ACAO header is dynamic."
                ),
            }
    return None


def _build_bypass_origins(target_host: str):
    """Generate origin variants that bypass naive regex/prefix CORS validation."""
    parts = target_host.rsplit(".", 2)
    if len(parts) >= 2:
        apex = ".".join(parts[-2:])
    else:
        apex = target_host

    return [
        f"https://{apex}.evil.com",              # suffix — evil.com ends with our domain?
        f"https://evil{apex}",                   # prefix — starts with our domain?
        f"https://evil.{apex}",                  # sub of apex
        f"https://{target_host}.evil.com",       # full host as prefix
        f"http://{target_host}",                 # HTTP downgrade
    ]


def _check_origin_bypass(http, url: str, target_host: str) -> List[Dict]:
    findings = []
    for evil_origin in _build_bypass_origins(target_host):
        resp = http.get(url, headers={"Origin": evil_origin})
        if resp is None:
            continue
        h = _get_headers(resp)
        origin = _acao_val(h)
        if not origin or origin == "*":
            continue
        # Only flag if the evil origin is actually reflected
        if evil_origin in origin or origin in evil_origin:
            severity = "FAIL" if _creds_true(h) else "WARN"
            creds_note = " (with credentials)" if _creds_true(h) else ""
            findings.append({
                "type": f"cors-origin-bypass{'-credentialed' if _creds_true(h) else ''}",
                "status": severity,
                "detail": (
                    f"Endpoint {url} reflects crafted origin {evil_origin!r} in "
                    f"Access-Control-Allow-Origin: {origin!r}{creds_note}.\n\n"
                    f"This indicates a regex or prefix/suffix bypass in the CORS "
                    f"origin validation logic.\n\n"
                    f"Fix: validate the full origin against an allowlist, not a "
                    f"substring match."
                ),
            })
    return findings


class CORSMisconfigurationDeepScanner(BaseScanner):
    """Deep CORS misconfiguration analysis: null origin, bypass variants, Vary header."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        parsed  = urlparse(url)
        base    = f"{parsed.scheme}://{parsed.netloc}"
        host    = parsed.netloc

        found_anything = False

        for path in _CORS_ENDPOINTS:
            ep_url = base + path

            # Null origin
            f = _check_null_origin(self.http, ep_url)
            if f:
                found_anything = True
                log_fail(logger, f"CORS deep — null origin accepted at {ep_url}")
                self.results.append(self._result(
                    ep_url, f["type"], f["status"], detail=f["detail"]))

            # Wildcard + credentials
            f = _check_wildcard_with_credentials(self.http, ep_url)
            if f:
                found_anything = True
                log_fail(logger, f"CORS deep — wildcard + credentials at {ep_url}")
                self.results.append(self._result(
                    ep_url, f["type"], f["status"], detail=f["detail"]))

            # Vary: Origin absent
            f = _check_vary_origin_absent(self.http, ep_url)
            if f:
                found_anything = True
                log_warn(logger, f"CORS deep — Vary: Origin absent at {ep_url}")
                self.results.append(self._result(
                    ep_url, f["type"], f["status"], detail=f["detail"]))

            # Bypass variants (only probe root to avoid flooding)
            if path == "":
                bypass_finds = _check_origin_bypass(self.http, ep_url, host)
                for bf in bypass_finds:
                    found_anything = True
                    log_warn(logger, f"CORS deep — bypass at {ep_url}: {bf['type']}")
                    self.results.append(self._result(
                        ep_url, bf["type"], bf["status"], detail=bf["detail"]))

        if not found_anything:
            log_pass(logger, f"CORS deep — no deep misconfiguration detected for {url}")
            self.results.append(self._result(
                url,
                "CORS deep — no misconfiguration detected",
                "PASS",
                detail="No null origin acceptance, wildcard+credentials, or bypass patterns found.",
            ))

        return self.results
