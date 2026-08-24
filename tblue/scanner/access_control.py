"""
Access control scanner for Tblue.

Discovers admin interfaces, checks robots.txt for exposed admin paths,
and verifies sensitive admin areas require authentication.
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Common admin/management paths to probe
_ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/admin/login.php",
    "/administrator", "/administrator/", "/administrator/index.php",
    "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/dashboard", "/dashboard/", "/dashboard/login",
    "/cpanel", "/cPanel/", "/whm",
    "/phpmyadmin", "/phpMyAdmin/", "/pma/",
    "/manager", "/manager/html",
    "/panel", "/panel/", "/control-panel",
    "/backend", "/backend/",
    "/cms", "/cms/",
    "/moderator", "/moderator/",
    "/superadmin", "/super-admin",
    "/management", "/manage",
    "/staff", "/staff/login",
    "/secure", "/secure/admin",
    "/root",
    "/console",
    "/api/admin", "/api/v1/admin",
    "/django-admin", "/django-admin/",
]

# Keywords that indicate a login/authentication gate is present on the page
_AUTH_KEYWORDS = frozenset([
    "password", "username", "log in", "login", "sign in", "signin",
    "email address", "user name", "passphrase", "authentication required",
])

# Keywords / patterns that suggest we're seeing a live admin dashboard (not just login)
_PANEL_KEYWORDS = frozenset([
    "dashboard", "admin panel", "control panel", "management console",
    "welcome, admin", "logged in as", "users management", "site settings",
])

# Robots.txt Disallow patterns pointing to admin areas
_ROBOTS_ADMIN_RE = re.compile(
    r"^Disallow:\s*(/(?:admin|wp-admin|administrator|dashboard|cpanel|phpmyadmin|manager|backend|panel|cms)[/\w]*)",
    re.IGNORECASE | re.MULTILINE,
)


class AccessControlScanner(BaseScanner):
    """
    Discovers publicly reachable admin interfaces and access control issues.

    Checks:
    - Admin paths returning 200 (open panels) or 401/403 (properly locked)
    - robots.txt leaking admin path locations
    """

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        self._base_url = _base(url)

        self._check_robots_leakage(url)
        self._probe_admin_paths(url)
        return self.results

    # ── robots.txt leakage ────────────────────────────────────────────────────

    def _check_robots_leakage(self, url: str) -> None:
        robots_url = urljoin(self._base_url, "/robots.txt")
        try:
            resp = self.http.get(robots_url, allow_redirects=True)
        except Exception:
            return

        if resp.status_code != 200:
            return

        body = resp.text or ""
        matches = _ROBOTS_ADMIN_RE.findall(body)
        if not matches:
            return

        unique = sorted(set(matches))
        log_warn(logger, f"robots.txt reveals admin paths: {unique}")
        self.results.append(self._result(
            robots_url,
            "Access control — robots.txt leaks admin path locations",
            "WARN",
            detail=(
                f"robots.txt Disallow rules expose admin path locations: {', '.join(unique)}. "
                "While Disallow prevents indexing, the paths are now public knowledge — attackers "
                "can target them directly. "
                "Fix: remove admin paths from robots.txt; rely on authentication, not obscurity."
            )
        ))

    # ── admin path probing ────────────────────────────────────────────────────

    def _probe_admin_paths(self, url: str) -> None:
        found_open:   List[str] = []
        found_login:  List[str] = []
        found_locked: List[str] = []

        for path in _ADMIN_PATHS:
            target = urljoin(self._base_url, path)
            try:
                resp = self.http.get(target, allow_redirects=True)
            except Exception:
                continue

            code = resp.status_code
            if code == 404 or code == 410:
                continue
            if code in (401, 403):
                found_locked.append(path)
                continue

            if code != 200:
                continue

            body_lower = (resp.text or "").lower()
            soup = BeautifulSoup(resp.text or "", "html.parser")
            page_text = soup.get_text(" ", strip=True).lower()

            has_auth_form = (
                soup.find("input", {"type": "password"}) is not None
                or any(kw in page_text for kw in _AUTH_KEYWORDS)
            )
            looks_like_panel = any(kw in page_text for kw in _PANEL_KEYWORDS)

            if looks_like_panel and not has_auth_form:
                found_open.append(path)
            elif has_auth_form:
                found_login.append(path)
            else:
                found_open.append(path)

        # Report
        if found_open:
            log_fail(logger, f"Admin areas publicly accessible (no auth): {found_open}")
            self.results.append(self._result(
                url,
                "Access control — admin interface publicly accessible",
                "FAIL",
                detail=(
                    f"The following admin paths are accessible without authentication: "
                    f"{', '.join(found_open)}. "
                    "Fix: restrict access to admin interfaces via IP allowlisting, VPN, or "
                    "strong authentication. Do not rely on obscurity."
                )
            ))
        elif found_login:
            log_warn(logger, f"Admin login pages found: {found_login}")
            self.results.append(self._result(
                url,
                "Access control — admin login page discoverable",
                "WARN",
                detail=(
                    f"Admin login page(s) found at: {', '.join(found_login)}. "
                    "The pages require authentication (good), but their existence is discoverable — "
                    "a targeted brute-force attack could follow. "
                    "Fix: move admin access behind a VPN or IP allowlist, and ensure account "
                    "lockout and MFA are enabled."
                )
            ))
        else:
            log_pass(logger, "No open admin interfaces found")
            self.results.append(self._result(
                url,
                "Access control — admin interface exposure",
                "PASS",
                detail=(
                    "No common admin interfaces were found publicly accessible. "
                    + (f"({len(found_locked)} path(s) returned 401/403 — properly locked.)" if found_locked else "")
                )
            ))


def _base(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"
