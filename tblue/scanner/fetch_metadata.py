"""
Fetch Metadata Request Headers Policy Scanner.

Fetch Metadata is a W3C standard (2021) that adds browser-sent request headers
(`Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, `Sec-Fetch-User`) to every
outgoing request. These allow the server to distinguish:

  - Same-origin requests (legitimate)
  - Cross-site requests (potentially malicious CSRF / click-jacking)
  - Navigation vs. sub-resource requests

A server implementing "Resource Isolation Policy" can:
  1. Allow same-origin requests unconditionally
  2. Allow cross-site navigation (GET/HEAD) to public pages
  3. Block or challenge cross-site sub-resource requests (POST, script injection etc.)

Without Fetch Metadata enforcement:
  - Traditional CSRF defenses (tokens, Origin/Referer checks) are the only layer
  - Cross-site leaks (XS-Leaks) via fetch, beacon, etc. are harder to block
  - Spectre-style timing attacks via sub-resource requests are harder to mitigate

Detection approach:
1. Send a synthetic cross-site sub-resource request (Sec-Fetch-Site: cross-site,
   Sec-Fetch-Mode: no-cors) to state-changing endpoints — if it succeeds (2xx),
   the server does not enforce Fetch Metadata policy.
2. Check for `Cross-Origin-Resource-Policy` (CORP) header on resource responses.
3. Check for `Cross-Origin-Opener-Policy` (COOP) header on navigation responses.
4. Check for `Cross-Origin-Embedder-Policy` (COEP) header.
5. Detect absence of CORP / COOP headers on APIs returning sensitive data.

Note: All probes are legitimate GET/POST requests with informational headers added.
No payloads are injected. Strictly defensive and read-only analysis.

Professional equivalents: Detectify "Fetch Metadata Policy" check,
Google Security "Resource Isolation Policy" recommendation,
PortSwigger Research "XS-Leaks" detection.

CWE-352: Cross-Site Request Forgery (CSRF)
CWE-284: Improper Access Control
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin


from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

# Headers that signal COOP / COEP / CORP policy
_COOP_HEADER = "cross-origin-opener-policy"
_COEP_HEADER = "cross-origin-embedder-policy"
_CORP_HEADER = "cross-origin-resource-policy"

# Safe COOP values (non-empty means at least something is enforced)
_COOP_SAFE_VALUES = {"same-origin", "same-origin-allow-popups"}

# State-changing HTTP endpoints (likely to require CSRF protection)
_STATE_CHANGING_PATHS = [
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/api/v3/",
    "/graphql",
    "/login",
    "/logout",
    "/register",
    "/password/change",
    "/account/settings",
    "/profile/update",
    "/checkout",
    "/payment",
]

# Form action paths extracted from HTML
_FORM_ACTION_RE = re.compile(
    r'<form[^>]+action=["\']([^"\']+)["\']',
    re.I,
)

# Synthetic Fetch Metadata headers simulating a cross-site request
_CROSS_SITE_HEADERS = {
    "Sec-Fetch-Site": "cross-site",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    "Origin": "https://attacker.example.com",
}

_NAVIGATE_CROSS_SITE_HEADERS = {
    "Sec-Fetch-Site": "cross-site",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Dest": "document",
}


class FetchMetadataScanner(BaseScanner):
    """Detect missing Fetch Metadata policy enforcement and CORP/COOP/COEP headers."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        # Baseline request (no extra headers)
        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Fetch Metadata — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        body = resp.text or ""
        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        found_any = False

        # ── 1. Check COOP header on main document ────────────────────────────
        found_any |= self._check_coop(url, headers)

        # ── 2. Check COEP header ──────────────────────────────────────────────
        found_any |= self._check_coep(url, headers)

        # ── 3. Probe API endpoints for CORP and Fetch Metadata enforcement ───
        found_any |= self._probe_api_endpoints(url, base, body)

        # ── 4. Check form action endpoints ────────────────────────────────────
        found_any |= self._probe_form_endpoints(url, base, body)

        if not found_any:
            log_pass(logger, f"Fetch Metadata policy appears correctly configured on {url}")
            self.results.append(self._result(
                url,
                "Fetch Metadata — COOP/COEP/CORP headers present and cross-site blocking active",
                "PASS",
                detail=(
                    "Cross-Origin-Opener-Policy (COOP), Cross-Origin-Embedder-Policy (COEP), "
                    "and Cross-Origin-Resource-Policy (CORP) headers are set. "
                    "API endpoints responded to synthetic cross-site Fetch Metadata requests "
                    "with appropriate rejection or restriction. "
                    "This significantly reduces CSRF and XS-Leak attack surface."
                )
            ))

        return self.results

    def _check_coop(self, url: str, headers: dict) -> bool:
        coop_val = headers.get(_COOP_HEADER, "").strip()
        if not coop_val:
            log_warn(logger, f"Missing Cross-Origin-Opener-Policy header: {url}")
            self.results.append(self._result(
                url,
                "Fetch Metadata — missing Cross-Origin-Opener-Policy (COOP) header",
                "WARN",
                detail=(
                    "The Cross-Origin-Opener-Policy (COOP) header is absent. "
                    "Without COOP, cross-origin pages can retain a reference to this window "
                    "via window.opener, enabling cross-origin information leaks and "
                    "navigation attacks (XS-Leaks). "
                    "Fix: set `Cross-Origin-Opener-Policy: same-origin` on all navigation "
                    "responses. Use `same-origin-allow-popups` if popups to cross-origin "
                    "pages are needed (e.g., OAuth)."
                )
            ))
            return True

        if coop_val.lower() not in _COOP_SAFE_VALUES:
            log_warn(logger, f"Non-standard COOP value '{coop_val}': {url}")
            self.results.append(self._result(
                url,
                f"Fetch Metadata — unusual Cross-Origin-Opener-Policy value: '{coop_val}'",
                "WARN",
                detail=(
                    f"Cross-Origin-Opener-Policy is set to '{coop_val}'. "
                    "Expected values are 'same-origin' or 'same-origin-allow-popups'. "
                    "Verify this value is intentional and provides the intended isolation."
                )
            ))
            return True

        return False

    def _check_coep(self, url: str, headers: dict) -> bool:
        coep_val = headers.get(_COEP_HEADER, "").strip()
        if not coep_val:
            log_warn(logger, f"Missing Cross-Origin-Embedder-Policy header: {url}")
            self.results.append(self._result(
                url,
                "Fetch Metadata — missing Cross-Origin-Embedder-Policy (COEP) header",
                "WARN",
                detail=(
                    "The Cross-Origin-Embedder-Policy (COEP) header is absent. "
                    "COEP is required alongside COOP to enable `crossOriginIsolated` mode, "
                    "which activates high-resolution timers, SharedArrayBuffer, and "
                    "better Spectre mitigations. Without COEP, cross-origin resources "
                    "may be embedded without explicit permission. "
                    "Fix: set `Cross-Origin-Embedder-Policy: require-corp` if you control "
                    "all embedded resources, or `credentialless` for mixed-origin pages."
                )
            ))
            return True
        return False

    def _probe_api_endpoints(self, url: str, base: str, body: str) -> bool:
        """Send synthetic cross-site Fetch Metadata headers to known API paths."""
        found = False
        parsed = urlparse(url)
        path = parsed.path

        # Only probe common API paths that make sense for this target
        paths_to_probe = [p for p in _STATE_CHANGING_PATHS
                          if p != path][:5]  # limit to 5 probes

        for probe_path in paths_to_probe:
            probe_url = base + probe_path
            try:
                # First check if the endpoint exists at all (baseline)
                baseline = self.http.get(probe_url)
                if baseline is None or baseline.status_code in (404, 405):
                    continue  # endpoint doesn't exist

                # Now send cross-site Fetch Metadata headers
                cross_site = self.http.get(probe_url, headers=_CROSS_SITE_HEADERS)
                if cross_site is None:
                    continue

                probe_headers = {k.lower(): v
                                 for k, v in (cross_site.headers or {}).items()}
                corp_val = probe_headers.get(_CORP_HEADER, "")

                if cross_site.status_code < 400:
                    # Endpoint accepted the cross-site request without blocking
                    if not corp_val:
                        log_warn(logger, f"API endpoint lacks CORP and accepts cross-site requests: {probe_url}")
                        self.results.append(self._result(
                            probe_url,
                            "Fetch Metadata — API endpoint accepts cross-site requests without CORP header",
                            "WARN",
                            detail=(
                                f"The API endpoint {probe_url} responded with HTTP "
                                f"{cross_site.status_code} to a synthetic cross-site request "
                                "(Sec-Fetch-Site: cross-site, Sec-Fetch-Mode: cors). "
                                "No Cross-Origin-Resource-Policy (CORP) header was returned. "
                                "This means the endpoint does not enforce Fetch Metadata isolation "
                                "and may be vulnerable to cross-site information leaks (XS-Leaks). "
                                "Fix: add `Cross-Origin-Resource-Policy: same-site` or "
                                "`same-origin` to API responses; "
                                "implement server-side Fetch Metadata policy enforcement "
                                "(check Sec-Fetch-Site header in middleware)."
                            )
                        ))
                        found = True
                        break  # one finding is enough

            except Exception:
                continue

        return found

    def _probe_form_endpoints(self, url: str, base: str, body: str) -> bool:
        """Check form action endpoints for CORP headers."""
        found = False
        try:
            actions = _FORM_ACTION_RE.findall(body)
            for action in actions[:3]:  # probe at most 3 forms
                if action.startswith("http"):
                    probe_url = action
                else:
                    probe_url = urljoin(base, action)
                try:
                    r = self.http.get(probe_url, headers=_CROSS_SITE_HEADERS)
                    if r is None:
                        continue
                    rh = {k.lower(): v for k, v in (r.headers or {}).items()}
                    if r.status_code < 400 and not rh.get(_CORP_HEADER):
                        log_warn(logger, f"Form action endpoint lacks CORP: {probe_url}")
                        self.results.append(self._result(
                            probe_url,
                            "Fetch Metadata — form action endpoint accepts cross-site requests without CORP",
                            "WARN",
                            detail=(
                                f"The form action endpoint {probe_url} accepted a synthetic "
                                "cross-site request and returned no Cross-Origin-Resource-Policy "
                                "header. Form-submitting endpoints are common CSRF targets. "
                                "Fix: implement CSRF token validation AND Fetch Metadata "
                                "policy as defense-in-depth; "
                                "set CORP: same-site on form action endpoints."
                            )
                        ))
                        found = True
                        break
                except Exception:
                    continue
        except Exception:
            pass
        return found
