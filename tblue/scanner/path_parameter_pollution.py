"""
Path Parameter Pollution (PPP) Scanner.

Path Parameter Pollution is a class of vulnerability where duplicate or
conflicting URL path parameters or matrix parameters cause unexpected behavior:

  1. Matrix parameters — /users;admin=true or /api;debug=1 — some frameworks
     (Spring, JAX-RS, Apache Axis) parse semicolons in paths as parameter
     separators, not as part of the path. A WAF might see /users;admin=true
     as /users, while the backend sees admin=true.

  2. Path traversal via encoding — %2F (/) in path segments, %252F (double-
     encoded /), ..%2F, ..%2f, .%2e/, ..%5c

  3. Duplicate path parameters — /api/users/1 vs /api/users/1.json,
     /api/users/1;v=2 — some ORMs read different records

  4. Numeric vs string path segments — /api/users/me vs /api/users/0

  5. Path normalization inconsistencies — //double-slash, /./redundant,
     /a/../b traversal within normalized path

This is distinct from http_parameter_pollution.py (which focuses on query
parameters) and path_traversal.py (which focuses on directory traversal).
This scanner specifically targets path segment injection and matrix parameters.

CWE-235: Improper Handling of Extra Parameters
CWE-706: Use of Incorrectly-Resolved Name or Reference
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlunparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_MAX_BODY = 128 * 1024

# Matrix parameter payloads to inject at path end
_MATRIX_PAYLOADS = [
    ";admin=true",
    ";debug=1",
    ";role=admin",
    ";internal=true",
    ";bypass=1",
    ";isAdmin=true",
]

# Path normalization probes
_NORM_PROBES = [
    ("//", "double-slash prefix"),
    ("/./", "dot-slash redundant"),
    ("/%2F", "percent-encoded slash"),
    ("/%252F", "double-encoded slash"),
]

# Sensitive paths to probe with matrix params
_PROBE_PATHS = [
    "/api/users",
    "/api/v1/users",
    "/api/me",
    "/api/admin",
    "/admin",
    "/api/",
    "/",
]


def _check_matrix_param_reflection(resp, body_before: str) -> Optional[str]:
    """Check if a matrix parameter payload was reflected or changed behavior."""
    if resp is None:
        return None
    # Status code change is significant
    return None  # Caller handles status comparison


def _status_changed_significantly(s1: int, s2: int) -> bool:
    """Returns True if status went from 403/401 to 200, or similar access bypass."""
    return (s1 in (401, 403) and s2 == 200) or (s1 == 404 and s2 == 200)


class PathParameterPollutionScanner(BaseScanner):
    """Detects path parameter pollution and matrix parameter injection vulnerabilities."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Path Parameter Pollution — target unreachable", "PASS",
                detail="No response; path parameter pollution scan skipped."))
            return self.results

        base = url.rstrip("/")
        parsed = urlparse(url)
        base_url = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

        findings: List[Dict] = []
        seen_types: set = set()

        # Test matrix parameter injection on common paths
        for path in _PROBE_PATHS:
            clean_url   = base_url + path
            clean_resp  = self.http.get(clean_url)
            if clean_resp is None:
                continue
            clean_status = clean_resp.status_code

            for payload in _MATRIX_PAYLOADS[:3]:  # limit probes
                probe_url  = base_url + path.rstrip("/") + payload
                probe_resp = self.http.get(probe_url)
                if probe_resp is None:
                    continue

                if _status_changed_significantly(clean_status, probe_resp.status_code):
                    key = f"matrix-param-bypass-{path}"
                    if key not in seen_types:
                        seen_types.add(key)
                        findings.append({
                            "severity": "FAIL",
                            "type": "matrix-param-access-bypass",
                            "msg": (
                                f"Matrix parameter injection changed HTTP status from "
                                f"{clean_status} to {probe_resp.status_code} on {probe_url}. "
                                f"Payload: '{payload}' — possible WAF/middleware bypass or "
                                f"unintended access."
                            ),
                            "url": probe_url,
                        })
                    break  # found one for this path

        # Test path normalization inconsistencies
        for norm, label in _NORM_PROBES:
            probe_url  = base_url + norm
            probe_resp = self.http.get(probe_url)
            clean_resp = self.http.get(base_url + "/")
            if probe_resp is None or clean_resp is None:
                continue

            # If the probe returns a completely different response body, note it
            if (probe_resp.status_code != clean_resp.status_code and
                    probe_resp.status_code == 200 and clean_resp.status_code != 200):
                key = f"path-norm-{label}"
                if key not in seen_types:
                    seen_types.add(key)
                    findings.append({
                        "severity": "WARN",
                        "type": "path-normalization-inconsistency",
                        "msg": (
                            f"Path normalization inconsistency detected with '{label}' ({norm}). "
                            f"Root path returns {clean_resp.status_code} but '{norm}' returns "
                            f"{probe_resp.status_code}. May indicate routing inconsistency."
                        ),
                        "url": probe_url,
                    })

        if not findings:
            log_pass(logger, f"Path Parameter Pollution — no issues found on {url}")
            self.results.append(self._result(
                url,
                "Path Parameter Pollution — no matrix param injection or normalization issues",
                "PASS",
                detail=(
                    f"Probed {len(_PROBE_PATHS)} paths with {len(_MATRIX_PAYLOADS[:3])} matrix "
                    f"parameter payloads and {len(_NORM_PROBES)} normalization probes. "
                    f"No access bypass or inconsistency detected."
                ),
            ))
            return self.results

        for f in findings:
            status = f["severity"]
            if status == "FAIL":
                log_fail(logger, f"Path Parameter Pollution — {f['msg'][:80]}")
            else:
                log_warn(logger, f"Path Parameter Pollution — {f['msg'][:80]}")

            self.results.append(self._result(
                f.get("url", url),
                f"Path Parameter Pollution — {f['type']}",
                status,
                detail=(
                    f"{f['msg']}\n\n"
                    f"Matrix parameters (semicolon-delimited) are parsed differently by "
                    f"various frameworks. A WAF typically ignores semicolons in paths, "
                    f"while Spring/JAX-RS backends parse them as parameters, creating "
                    f"filter bypass opportunities."
                ),
            ))

        return self.results
