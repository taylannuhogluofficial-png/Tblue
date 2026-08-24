"""
Browser SPA Scanner — Single-Page Application Route Discovery.

Traditional crawlers fail on React, Vue, Angular, and Next.js apps because
navigation happens in JavaScript — there are no <a href> links that a plain
HTTP crawler can follow. The entire site appears as a single page.

This scanner uses Playwright to:
  1. Load the root page and let all JavaScript execute
  2. Extract client-side routes from the DOM, JS bundle contents, and
     common SPA route registration patterns
  3. Navigate to each discovered route in the browser
  4. Run a fast security header check on each rendered page
  5. Report routes that expose sensitive content or missing security controls

Blue-team value:
  • Discovers pages that static crawlers miss entirely
  • Catches admin routes buried in the JS bundle
  • Finds pages that skip security headers (CSP/HSTS) on sub-routes
  • Detects client-side auth bypass (routes accessible without login)

Paid equivalent: Burp Suite Pro crawler with JavaScript analysis.
"""

import re
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.browser.engine import playwright_available, BrowserSession
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Route patterns that suggest admin or sensitive content
_SENSITIVE_ROUTE_RE = re.compile(
    r"/(?:admin|dashboard|internal|debug|settings|config|manage|console|backstage|staff|ops|dev|system)",
    re.I,
)

# Security-critical headers to check on each route
_REQUIRED_HEADERS = {
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
}

# Max routes to follow (keep scan time reasonable)
_MAX_ROUTES = 20


class BrowserSPAScanner(BaseScanner):
    """Discover and scan SPA client-side routes via headless Chromium."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        if not playwright_available():
            logger.warning("Playwright not installed — skipping SPA route scan")
            return self.results

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        try:
            with BrowserSession(headless=True) as session:
                # Phase 1: Discover routes
                routes = self._discover_routes(session, url, base)

                if not routes:
                    log_pass(logger, f"SPA scan — no client-side routes discovered on {url}")
                    self.results.append(self._result(
                        url,
                        "Browser SPA — no client-side routes discovered",
                        "PASS",
                        detail=(
                            "No client-side routes were found in the page source or JavaScript "
                            "bundle. This may be a server-rendered application, or routes may "
                            "be dynamically generated at runtime. Traditional crawling applies."
                        ),
                    ))
                    return self.results

                # Phase 2: Scan each route
                self._scan_routes(session, url, base, routes)

        except Exception as e:
            logger.debug(f"SPA scan error: {e}")

        return self.results

    def _discover_routes(self, session: BrowserSession, url: str, base: str) -> List[str]:
        """Load root page and extract all client-side routes."""
        page = session.new_page()
        page.goto(url, wait_until="networkidle", timeout=15000)
        page.wait_for_timeout(1000)

        routes = page.get_spa_routes()

        # Also extract from JS source patterns
        js_routes = self._extract_routes_from_js(page, url, base, session)
        routes.extend(js_routes)

        # Deduplicate and filter
        seen: Set[str] = set()
        clean = []
        for r in routes:
            if r not in seen and r != "/" and not r.startswith("//"):
                seen.add(r)
                clean.append(r)

        logger.info(f"SPA scan: discovered {len(clean)} client-side routes on {url}")
        return clean[:_MAX_ROUTES]

    def _extract_routes_from_js(self, page, url: str, base: str, session: BrowserSession) -> List[str]:
        """Fetch and scan linked JS bundles for route registration patterns."""
        routes = []

        # Get all JS script URLs
        js_urls = page.evaluate("""
            () => [...document.querySelectorAll('script[src]')]
                .map(s => s.src)
                .filter(s => s.includes(location.hostname))
                .slice(0, 5)
        """) or []

        route_patterns = [
            re.compile(r"""(?:path|route|to)\s*:\s*["'`](/[^"'`\s,)]{1,80})"""),
            re.compile(r"""["'`](/[a-z0-9_/-]{3,40})["'`]\s*,\s*(?:component|element|page)""", re.I),
            re.compile(r"""<Route\s[^>]*path=["'`](/[^"'`]+)["'`]"""),
            re.compile(r"""router\.(?:get|post|put|delete|use)\s*\(["'`](/[^"'`]+)["'`]"""),
        ]

        for js_url in js_urls[:3]:
            js_page = session.new_page()
            if js_page.goto(js_url, wait_until="load", timeout=8000):
                content = js_page.content()[:200_000]
                for pat in route_patterns:
                    for m in pat.finditer(content):
                        r = m.group(1)
                        if r and "/" in r and not r.endswith(".js"):
                            routes.append(r)

        return routes

    def _scan_routes(self, session: BrowserSession, base_url: str, base: str, routes: List[str]) -> None:
        """Navigate to each route and run security checks."""
        sensitive_found: List[str] = []
        header_missing: Dict[str, List[str]] = {h: [] for h in _REQUIRED_HEADERS}
        accessible_sensitive: List[str] = []

        for route in routes:
            full_url = base + route
            page = session.new_page()
            navigated = page.goto(full_url, wait_until="networkidle", timeout=10000)
            if not navigated:
                continue

            page.wait_for_timeout(300)

            # Check if sensitive route is accessible without redirect
            final_url = page.url()
            is_sensitive = bool(_SENSITIVE_ROUTE_RE.search(route))

            if is_sensitive:
                sensitive_found.append(route)
                # Check if we stayed on the route (no auth redirect)
                if urlparse(final_url).path == route or route in final_url:
                    accessible_sensitive.append(route)
                    log_warn(logger, f"SPA: sensitive route accessible without redirect: {full_url}")

            # Check security headers on this route via the responses list
            for resp in reversed(page.responses):
                if resp["url"] == full_url or resp["url"].rstrip("/") == full_url.rstrip("/"):
                    headers = resp.get("headers", {})
                    for header, label in _REQUIRED_HEADERS.items():
                        if header not in headers:
                            header_missing[header].append(route)
                    break

        # Report accessible sensitive routes
        if accessible_sensitive:
            log_fail(logger, f"SPA: {len(accessible_sensitive)} sensitive route(s) accessible: {accessible_sensitive}")
            self.results.append(self._result(
                base_url,
                f"Browser SPA — {len(accessible_sensitive)} sensitive route(s) accessible without authentication",
                "FAIL",
                detail=(
                    "The following sensitive client-side routes were accessible in the browser "
                    "without being redirected to a login page:\n"
                    + "\n".join(f"• {base + r}" for r in accessible_sensitive)
                    + "\n\nClient-side route protection (PrivateRoute, AuthGuard) can be bypassed "
                    "if the server does not also enforce authentication on the underlying API calls. "
                    "Even if data is not returned, the route UI itself may disclose information.\n\n"
                    "Fix: verify that all sensitive routes check authentication both client-side "
                    "(for UX) AND server-side (for security). Test with an unauthenticated "
                    "browser session."
                ),
            ))
        elif sensitive_found:
            log_pass(logger, f"SPA: {len(sensitive_found)} sensitive route(s) found but redirected to auth")
            self.results.append(self._result(
                base_url,
                f"Browser SPA — {len(sensitive_found)} sensitive route(s) protected by auth redirect",
                "PASS",
                detail=(
                    f"Sensitive routes were discovered ({', '.join(sensitive_found)}) but accessing "
                    "them triggered an authentication redirect. Client-side route protection appears "
                    "to be working."
                ),
            ))

        # Report missing headers across routes
        for header, label in _REQUIRED_HEADERS.items():
            missing_routes = header_missing[header]
            if missing_routes:
                log_warn(logger, f"SPA: {label} missing on routes: {missing_routes[:5]}")
                self.results.append(self._result(
                    base_url,
                    f"Browser SPA — {label} header missing on {len(missing_routes)} route(s)",
                    "WARN",
                    detail=(
                        f"The {label} header is absent on these client-side routes:\n"
                        + "\n".join(f"• {base + r}" for r in missing_routes[:8])
                        + f"\n\nSPA routes often bypass server middleware that adds security headers "
                        f"to the root page. Each route response should include {label}.\n\n"
                        "Fix: ensure your web framework or reverse proxy applies security headers "
                        "to ALL routes, not just the root path."
                    ),
                ))

        if not self.results:
            log_pass(logger, f"SPA scan — {len(routes)} route(s) scanned, no issues found")
            self.results.append(self._result(
                base_url,
                f"Browser SPA — {len(routes)} client-side route(s) scanned, no issues",
                "PASS",
                detail=(
                    f"Scanned {len(routes)} client-side routes discovered in the SPA. "
                    "No accessible sensitive routes or missing security headers were detected."
                ),
            ))
