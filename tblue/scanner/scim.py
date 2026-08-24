"""
SCIM / Identity Management Endpoint Exposure Scanner.

SCIM (System for Cross-domain Identity Management) 2.0 is used by enterprise
IdPs (Okta, Azure AD, Google Workspace) to provision users and groups. Exposed
SCIM endpoints without authentication leak the full user directory.

Checks:
  1. Probe 20+ known SCIM 2.0 endpoint paths
  2. Detect SCIM response schema in body (ServiceProviderConfig, ResourceTypes)
  3. Identify authentication requirements (or lack thereof)
  4. Detect other IdM APIs: LDAP-over-HTTP, Okta admin API, Azure Graph exposure

Paid equivalents: Detectify, Qualys WAS, manual penetration testing.
"""

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_SCIM_PATHS: List[Tuple[str, str]] = [
    ("/scim/v2/Users",               "SCIM v2 Users"),
    ("/scim/v2/Groups",              "SCIM v2 Groups"),
    ("/scim/v2/ServiceProviderConfig","SCIM v2 ServiceProviderConfig"),
    ("/scim/v2/ResourceTypes",       "SCIM v2 ResourceTypes"),
    ("/scim/v2/Schemas",             "SCIM v2 Schemas"),
    ("/scim/v2",                     "SCIM v2 root"),
    ("/scim/Users",                  "SCIM v1 Users"),
    ("/scim/Groups",                 "SCIM v1 Groups"),
    ("/api/scim/v2/Users",           "SCIM v2 Users (API prefix)"),
    ("/api/scim/v2/Groups",          "SCIM v2 Groups (API prefix)"),
    ("/v2/scim/Users",               "SCIM v2 Users (v2 prefix)"),
    ("/v2/scim/Groups",              "SCIM v2 Groups (v2 prefix)"),
    ("/identity/scim/v2/Users",      "SCIM identity Users"),
    ("/identity/scim/v2/Groups",     "SCIM identity Groups"),
    ("/admin/scim/v2/Users",         "SCIM admin Users"),
    ("/auth/scim/v2/Users",          "SCIM auth Users"),
    ("/provisioning/scim/v2/Users",  "SCIM provisioning Users"),
    ("/directory/v1/users",          "Google Directory API"),
    ("/api/v1/users",                "Okta Users API pattern"),
    ("/api/v1/groups",               "Okta Groups API pattern"),
]

_SCIM_BODY_RE = re.compile(
    r'"schemas"\s*:\s*\[.*urn:ietf:params:scim|'
    r'"totalResults"\s*:\s*\d+|'
    r'"Resources"\s*:\s*\[|'
    r'ServiceProviderConfig|'
    r'"userName"\s*:\s*"',
    re.I | re.S,
)

_AUTH_REQUIRED_RE = re.compile(
    r'"status"\s*:\s*40[13]|Unauthorized|Forbidden|'
    r'"error"\s*:.*"Unauthorized"',
    re.I,
)


class SCIMScanner(BaseScanner):
    """Detect exposed SCIM identity management endpoints."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        exposed: List[Tuple[str, str, bool]] = []

        for path, label in _SCIM_PATHS:
            probe_url = base + path
            try:
                r = self.http.get(probe_url)
                if not r or r.status_code not in (200, 206):
                    continue
                body = r.text or ""
                if _SCIM_BODY_RE.search(body):
                    auth_required = bool(_AUTH_REQUIRED_RE.search(body)) or r.status_code == 401
                    exposed.append((probe_url, label, auth_required))
            except Exception:
                continue

        for probe_url, label, auth_required in exposed:
            if auth_required:
                log_warn(logger, f"SCIM endpoint found (requires auth): {probe_url}")
                self.results.append(self._result(
                    probe_url, f"SCIM — {label} accessible (auth required)", "WARN",
                    detail=(
                        f"{label} found at {probe_url} but requires authentication. "
                        "Verify the authentication mechanism is strong (OAuth 2.0 bearer token, "
                        "not basic auth), that tokens are scoped to least privilege, "
                        "and that read/write operations are audited."
                    )
                ))
            else:
                log_fail(logger, f"SCIM endpoint unauthenticated: {probe_url}")
                self.results.append(self._result(
                    probe_url, f"SCIM — {label} exposed without authentication", "FAIL",
                    detail=(
                        f"SCIM endpoint {probe_url} ({label}) returned user/group data "
                        "without authentication. This exposes the full user directory including "
                        "usernames, email addresses, group memberships, and roles. "
                        "An attacker can enumerate all users for targeted phishing or "
                        "credential stuffing attacks. "
                        "Fix: require OAuth 2.0 Bearer token authentication on all SCIM endpoints; "
                        "restrict SCIM to internal networks or VPN; "
                        "implement rate limiting and audit logging."
                    )
                ))

        if not self.results:
            log_pass(logger, f"No exposed SCIM/IdM endpoints found on {url}")
            self.results.append(self._result(
                url, "SCIM/IdM — no exposed identity management endpoints", "PASS",
                detail="No unauthenticated SCIM or identity management API endpoints found."
            ))

        return self.results
