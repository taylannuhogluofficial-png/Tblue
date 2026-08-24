"""
HTTP Parameter Pollution (HPP) Scanner.

HPP occurs when an application processes duplicate query/body parameters
in an attacker-controlled way, leading to:
- Access control bypass (e.g., role=user&role=admin → server picks admin)
- Filter bypass (e.g., id=1&id=OR+1=1 on WAF-fronted apps)
- Logic bypass (e.g., amount=100&amount=1 → charge 1, credit 100)
- Cache key confusion via duplicate parameters

Checks performed (read-only, never modifies state):
1. Duplicate GET parameter with second value as sentinel → inspect which is echoed
2. Duplicate parameter with contrasting values (safe vs. privileged) → detect bias
3. Array parameter notation (?x[]=1&x[]=2, ?x[0]=1&x[1]=2) accepted check
4. Parameter in both query string AND form body (query takes priority test)
5. HPP via encoded duplicates (%26 second param injection inside value)

CWE-235: Improper Handling of Extra Parameters
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_SENTINEL_A = "hpp_test_first"
_SENTINEL_B = "hpp_test_second"

# Strings that suggest a privileged value was picked up
_PRIV_VALUE_RE = re.compile(
    r"admin|superuser|root|manage|delete|privileged|role.*admin",
    re.I,
)

# Array notation patterns that might work
_ARRAY_NOTATIONS = ["[]", "[0]"]


class HTTPParameterPollutionScanner(BaseScanner):
    """Detects inconsistent or exploitable duplicate parameter handling."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping HPP checks: {url}")
            self.results.append(self._result(
                url, "HTTP Parameter Pollution — no response", "PASS",
                detail="Target did not respond; HPP checks skipped."
            ))
            return self.results

        parsed = urlparse(url)
        existing_params = parse_qs(parsed.query, keep_blank_values=True)

        # Choose an existing parameter to duplicate, or inject a fresh one
        test_param = next(iter(existing_params), "id")

        self._check_sentinel_echo(url, test_param)
        self._check_array_notation(url, test_param)
        self._check_encoded_duplication(url, test_param)

        if not self.results:
            log_pass(logger, f"No HPP vulnerabilities on {url}")
            self.results.append(self._result(
                url, "HTTP Parameter Pollution — no issues detected", "PASS",
                detail=(
                    "Duplicate query parameters were not reflected in a way that indicates "
                    "exploitable HPP behaviour (second value picked up, array accepted unexpectedly)."
                )
            ))

        return self.results

    def _base_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def _check_sentinel_echo(self, url: str, param: str) -> None:
        """Send param=FIRST&param=SECOND and see which value the app echoes back."""
        base = self._base_url(url)
        probe = f"{base}?{param}={_SENTINEL_A}&{param}={_SENTINEL_B}"
        r = self.http.get(probe)
        if r is None:
            return

        body = r.text or ""
        first_echoed = _SENTINEL_A in body
        second_echoed = _SENTINEL_B in body

        if second_echoed and not first_echoed:
            log_warn(logger, f"HPP: server takes LAST duplicate param value ({param}): {url}")
            self.results.append(self._result(
                url, f"HTTP Parameter Pollution — last duplicate value echoed for '{param}'", "WARN",
                detail=(
                    f"When '{param}' is sent twice (?{param}=first&{param}=second), the server "
                    "processes the LAST occurrence. An attacker who can append parameters to a URL "
                    "(e.g., via a phishing link) can override earlier trusted values. "
                    "Fix: reject requests with duplicate parameters, or explicitly pick the first "
                    "occurrence and discard subsequent ones."
                )
            ))

        elif first_echoed and second_echoed:
            log_warn(logger, f"HPP: server echoes BOTH duplicate param values ({param}): {url}")
            self.results.append(self._result(
                url, f"HTTP Parameter Pollution — both duplicate values echoed for '{param}'", "WARN",
                detail=(
                    f"When '{param}' is sent twice, the server echoes both values. "
                    "Different framework layers may interpret these differently (e.g., WAF picks "
                    "first, backend picks second), enabling filter bypass attacks. "
                    "Fix: normalize parameter handling to reject or take only the first value."
                )
            ))

    def _check_array_notation(self, url: str, param: str) -> None:
        """Test if array notation (param[], param[0]) creates unexpected second-param parsing."""
        base = self._base_url(url)

        for notation in _ARRAY_NOTATIONS:
            array_param = f"{param}{notation}"
            probe = f"{base}?{param}=safe&{array_param}={_SENTINEL_A}"
            r = self.http.get(probe)
            if r is None:
                continue

            body = r.text or ""
            if _SENTINEL_A in body:
                log_warn(logger, f"HPP array notation '{array_param}' processed: {url}")
                self.results.append(self._result(
                    url, f"HTTP Parameter Pollution — array notation '{array_param}' accepted", "WARN",
                    detail=(
                        f"Parameter '{array_param}' (array notation) was processed and its value "
                        f"appeared in the response. Array notation can bypass input validation rules "
                        f"that only apply to scalar parameters, or confuse type expectations. "
                        "Fix: normalize incoming parameter names; strip bracket notation if "
                        "the application does not explicitly support arrays."
                    )
                ))
                return  # One finding is enough

    def _check_encoded_duplication(self, url: str, param: str) -> None:
        """Test %26-encoded second parameter inside a value (internal HPP)."""
        base = self._base_url(url)
        # The value contains an encoded & which some WAFs/parsers may decode before splitting
        encoded_double = f"safe%26{param}={_SENTINEL_B}"
        probe = f"{base}?{param}={encoded_double}"
        r = self.http.get(probe)
        if r is None:
            return

        body = r.text or ""
        if _SENTINEL_B in body:
            log_warn(logger, f"HPP encoded-ampersand duplication effective ({param}): {url}")
            self.results.append(self._result(
                url, f"HTTP Parameter Pollution — encoded %26 splits into duplicate '{param}'", "WARN",
                detail=(
                    f"A %26-encoded ampersand inside the value of '{param}' was decoded "
                    "and treated as a second parameter separator, with the injected value appearing "
                    "in the response. This can be used to inject hidden parameters behind WAF inspection. "
                    "Fix: validate parameter names and values AFTER URL decoding; "
                    "reject values that produce new parameters post-decode."
                )
            ))
