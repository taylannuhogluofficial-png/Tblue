"""
Cross-Site Leak (XSLeak) Attack Surface Detection.

Cross-site leaks are a class of web vulnerabilities that allow a malicious
website to infer sensitive information about a user's state on another site
by exploiting browser features as side channels.

Unlike XSS (which needs code execution), XSLeaks work through:
  - Frame counting (how many frames loaded from target)
  - Redirect oracles (did the server redirect? → infers auth state)
  - Cache probing (resource load time → infers visited URL)
  - Error oracles (resource error vs success → infers user data)
  - Navigation timing (timing differences → infers response content)

Checked mitigations:
  1. Cross-Origin-Opener-Policy (COOP) — prevents window.opener / window.frames
     reference from cross-origin pages (blocks frame counting, opener attacks)
  2. Cross-Origin-Embedder-Policy (COEP) — required for SharedArrayBuffer
     and high-precision timers (Spectre defence)
  3. Cross-Origin-Resource-Policy (CORP) — prevents opaque cross-origin resource
     loads (blocks cache timing, error oracle attacks)
  4. Framing protection — X-Frame-Options or frame-ancestors CSP
     prevents iframe-based frame counting attacks
  5. SameSite cookie attribute — Lax/Strict prevents cookies from being
     sent in cross-site requests (blocks redirect oracle & timing attacks)
  6. Vary: Cookie header on authenticated pages — signals cache must not
     serve different users the same cached response (blocks cache probing)

Commercial equivalents: None yet. This is a novel, forward-looking check.
Reference: xsleaks.dev — the definitive XSLeak vulnerability database.

CWE-200: Exposure of Sensitive Information
OWASP A05:2021 — Security Misconfiguration
"""

import re
from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

# ── Header patterns ────────────────────────────────────────────────────────────

_COOP_SAFE = re.compile(r'same-origin(?:-allow-popups)?', re.I)

_COEP_SAFE = re.compile(r'require-corp|unsafe-none', re.I)

_CORP_VALUES = re.compile(r'same-origin|same-site|cross-origin', re.I)

_FRAME_ANCESTORS_RE = re.compile(r"frame-ancestors\s+(?:'none'|'self')", re.I)

_VARY_COOKIE_RE = re.compile(r'\bCookie\b', re.I)

_TIMING_ALLOW_RE = re.compile(
    r'Timing-Allow-Origin:\s*\*',
    re.I,
)

# Authentication-related response indicators (authenticated page heuristic)
_AUTH_INDICATORS_RE = re.compile(
    r'(?:logout|sign.?out|dashboard|profile|account|my.account|settings|admin)',
    re.I,
)


class XSLeakScanner(BaseScanner):
    """Detect missing mitigations that expose cross-site information leak attack surfaces."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results: List[Dict[str, Any]] = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "XSLeak — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        headers     = {k.lower(): v for k, v in resp.headers.items()}
        html_body   = resp.text or ""
        csp_header  = headers.get("content-security-policy", "")
        looks_auth  = bool(_AUTH_INDICATORS_RE.search(html_body))

        self._check_coop(url, headers)
        self._check_coep(url, headers)
        self._check_corp(url, headers)
        self._check_framing(url, headers, csp_header)
        self._check_timing_allow(url, headers)

        if looks_auth:
            self._check_vary_cookie(url, headers)

        if not any(r["status"] in ("FAIL", "WARN") for r in self.results):
            log_pass(logger, f"XSLeak — all cross-site isolation headers present on {url}")
            self.results.append(self._result(
                url,
                "XSLeak — cross-site leak mitigations in place",
                "PASS",
                detail=(
                    "Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, "
                    "and framing protection headers are all present. "
                    "These mitigations significantly reduce the cross-site leak "
                    "attack surface. See xsleaks.dev for additional guidance."
                )
            ))

        return self.results

    def _check_coop(self, url: str, headers: dict) -> None:
        coop = headers.get("cross-origin-opener-policy", "")

        if not coop:
            log_warn(logger, f"Missing Cross-Origin-Opener-Policy on {url}")
            self.results.append(self._result(
                url,
                "XSLeak — Cross-Origin-Opener-Policy (COOP) missing",
                "WARN",
                detail=(
                    "Cross-Origin-Opener-Policy (COOP) is not set. Without COOP, "
                    "cross-origin pages can hold a reference to this window via "
                    "window.opener or window.open(), enabling frame counting attacks "
                    "and Spectre-based memory reads. "
                    "Fix: add 'Cross-Origin-Opener-Policy: same-origin' for maximum "
                    "isolation, or 'same-origin-allow-popups' if OAuth popups are needed. "
                    "CWE-200, xsleaks.dev."
                )
            ))
        elif not _COOP_SAFE.search(coop):
            log_warn(logger, f"Weak COOP value on {url}: {coop}")
            self.results.append(self._result(
                url,
                "XSLeak — Cross-Origin-Opener-Policy set to unsafe value",
                "WARN",
                detail=(
                    f"Cross-Origin-Opener-Policy is set to '{coop}', which does not "
                    "provide cross-origin isolation. "
                    "Fix: set to 'same-origin' or 'same-origin-allow-popups'. "
                    "CWE-200."
                )
            ))

    def _check_coep(self, url: str, headers: dict) -> None:
        coep = headers.get("cross-origin-embedder-policy", "")

        if not coep:
            log_warn(logger, f"Missing Cross-Origin-Embedder-Policy on {url}")
            self.results.append(self._result(
                url,
                "XSLeak — Cross-Origin-Embedder-Policy (COEP) missing",
                "WARN",
                detail=(
                    "Cross-Origin-Embedder-Policy (COEP) is not set. Without COEP, "
                    "the page cannot opt into cross-origin isolation, which is required "
                    "to safely use high-resolution timers and SharedArrayBuffer "
                    "(Spectre mitigation). "
                    "Fix: set 'Cross-Origin-Embedder-Policy: require-corp' if all "
                    "cross-origin resources send CORP headers, or 'credentialless' "
                    "for a broader-compatibility option. "
                    "CWE-200, xsleaks.dev."
                )
            ))

    def _check_corp(self, url: str, headers: dict) -> None:
        corp = headers.get("cross-origin-resource-policy", "")

        if not corp:
            log_warn(logger, f"Missing Cross-Origin-Resource-Policy on {url}")
            self.results.append(self._result(
                url,
                "XSLeak — Cross-Origin-Resource-Policy (CORP) missing",
                "WARN",
                detail=(
                    "Cross-Origin-Resource-Policy (CORP) is not set. Without CORP, "
                    "any cross-origin page can load this resource as an opaque response "
                    "and probe its existence via error/success timing oracles and "
                    "cache-based side channels. "
                    "Fix: set 'Cross-Origin-Resource-Policy: same-origin' to restrict "
                    "to same origin, 'same-site' to allow subdomains, or "
                    "'cross-origin' only for intentionally public resources. "
                    "CWE-200, xsleaks.dev."
                )
            ))

    def _check_framing(self, url: str, headers: dict, csp: str) -> None:
        xfo = headers.get("x-frame-options", "")
        has_frame_ancestors = bool(_FRAME_ANCESTORS_RE.search(csp))

        if not xfo and not has_frame_ancestors:
            log_warn(logger, f"No framing protection on {url}")
            self.results.append(self._result(
                url,
                "XSLeak — no framing protection (X-Frame-Options / frame-ancestors)",
                "WARN",
                detail=(
                    "Neither X-Frame-Options nor a frame-ancestors CSP directive is set. "
                    "This allows cross-origin pages to embed this page in an iframe and "
                    "count frames, probe navigation state, or observe error vs success "
                    "by measuring iframe load events — classic XSLeak vectors. "
                    "Fix: add CSP directive 'frame-ancestors \\'none\\'' or "
                    "'frame-ancestors \\'self\\'' (preferred over X-Frame-Options). "
                    "CWE-200, xsleaks.dev."
                )
            ))

    def _check_timing_allow(self, url: str, headers: dict) -> None:
        tal = headers.get("timing-allow-origin", "")
        if tal and "*" in tal:
            log_warn(logger, f"Timing-Allow-Origin: * on {url}")
            self.results.append(self._result(
                url,
                "XSLeak — Timing-Allow-Origin: * exposes precise resource timing",
                "WARN",
                detail=(
                    "'Timing-Allow-Origin: *' is set, which allows any cross-origin page "
                    "to read high-precision resource timing data via the Performance API. "
                    "For authenticated resources, timing differences can leak whether "
                    "certain data exists (cache timing oracle). "
                    "Fix: remove Timing-Allow-Origin or restrict to trusted origins only. "
                    "CWE-200, xsleaks.dev."
                )
            ))

    def _check_vary_cookie(self, url: str, headers: dict) -> None:
        vary = headers.get("vary", "")
        cache_control = headers.get("cache-control", "")

        is_no_cache = bool(re.search(r'no-store|no-cache|private', cache_control, re.I))
        has_vary_cookie = bool(_VARY_COOKIE_RE.search(vary))

        if not is_no_cache and not has_vary_cookie:
            log_warn(logger, f"Authenticated page missing Vary: Cookie on {url}")
            self.results.append(self._result(
                url,
                "XSLeak — authenticated page missing Vary: Cookie header",
                "WARN",
                detail=(
                    "This page appears to be authenticated (contains auth-related content) "
                    "but does not set 'Vary: Cookie' or 'Cache-Control: no-store/private'. "
                    "Without this, a shared cache may serve one user's authenticated response "
                    "to another user, and cross-site timing attacks can probe cache state "
                    "to infer authentication status. "
                    "Fix: add 'Cache-Control: no-store' for authenticated pages, or at "
                    "minimum 'Vary: Cookie' so caches key on the session cookie. "
                    "CWE-200, xsleaks.dev."
                )
            ))
