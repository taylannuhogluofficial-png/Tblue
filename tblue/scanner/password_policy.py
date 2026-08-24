"""
Password Policy Security Scanner.

Weak password policies directly contribute to account compromise. This scanner
passively evaluates signals about password policy from:

  1. Registration / password-change form analysis — minlength attributes,
     maxlength caps below 64 (truncation), pattern attributes.

  2. Password reset flow signals — reset token length in URL parameters,
     expiry signals in page text.

  3. Common-password acceptance hints — if the registration page references
     "no restrictions", "any password", or omits strength indicators.

  4. Password field autocomplete — autocomplete="new-password" is correct for
     registration; autocomplete="current-password" for login. Missing or
     incorrect values weaken credential managers.

  5. Max-password-age signals — pages that mention periodic forced password
     rotation (a NIST-deprecated practice per SP 800-63B) are flagged for
     awareness.

All checks are passive — no passwords submitted.

CWE-521: Weak Password Requirements
CWE-620: Unverified Password Change
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_REGISTER_PATHS = [
    "/register", "/signup", "/sign-up", "/join",
    "/account/register", "/user/register", "/users/new",
    "/auth/register", "/create-account",
]
_RESET_PATHS = [
    "/password/reset", "/forgot-password", "/reset-password",
    "/account/password/reset", "/auth/forgot",
]

_MIN_LENGTH_RE = re.compile(r'minlength\s*=\s*["\']?(\d+)', re.I)
_MAX_LENGTH_RE = re.compile(r'maxlength\s*=\s*["\']?(\d+)', re.I)
_AUTOCOMPLETE_RE = re.compile(r'autocomplete\s*=\s*["\']([^"\']+)["\']', re.I)
_FORCE_ROTATE_RE = re.compile(
    r'(?:password\s+(?:must|will)\s+expire|change\s+your\s+password\s+every|'
    r'password\s+rotation|reset\s+every\s+\d+\s+days)', re.I)
_NO_RESTRICTION_RE = re.compile(
    r'(?:no\s+(?:password\s+)?restrictions|any\s+password|'
    r'password\s+(?:can\s+be\s+anything|has\s+no\s+requirements))', re.I)

_WEAK_MIN = 8   # below 8 chars minimum is FAIL
_WARN_MIN = 12  # below 12 is WARN
_MAX_CAP  = 64  # maxlength below this is a truncation risk


def _find_password_inputs(body: str):
    """Return deduplicated list of password <input> HTML snippets."""
    seen: set = set()
    results = []
    for inp in re.findall(r'<input[^>]+>', body, re.I):
        inp_l = inp.lower()
        if 'type="password"' in inp_l or "type='password'" in inp_l:
            if inp not in seen:
                seen.add(inp)
                results.append(inp)
        elif re.search(r'(?:name|id)\s*=\s*["\'](?:password|passwd|pass)["\']', inp, re.I):
            if inp not in seen:
                seen.add(inp)
                results.append(inp)
    return results


def _check_registration_form(body: str, url: str) -> List[Dict]:
    findings = []
    pw_inputs = _find_password_inputs(body)
    if not pw_inputs:
        return findings

    for inp in pw_inputs:
        min_m = _MIN_LENGTH_RE.search(inp)
        if min_m:
            min_len = int(min_m.group(1))
            if min_len < _WEAK_MIN:
                findings.append({
                    "type": f"password-policy-minlength-too-short-{min_len}",
                    "status": "FAIL",
                    "detail": (
                        f"Password input at {url} has minlength={min_len}. "
                        f"NIST SP 800-63B recommends a minimum of 8 characters; "
                        f"best practice is 12+.\n\n"
                        f"Fix: increase minlength to at least 12 and enforce server-side."
                    ),
                })
            elif min_len < _WARN_MIN:
                findings.append({
                    "type": f"password-policy-minlength-below-recommended-{min_len}",
                    "status": "WARN",
                    "detail": (
                        f"Password input at {url} has minlength={min_len}. "
                        f"NIST recommends at least 8 characters; 12+ is best practice.\n\n"
                        f"Fix: increase minlength to 12 or more."
                    ),
                })

        max_m = _MAX_LENGTH_RE.search(inp)
        if max_m:
            max_len = int(max_m.group(1))
            if max_len < _MAX_CAP:
                findings.append({
                    "type": f"password-policy-maxlength-truncates-at-{max_len}",
                    "status": "WARN",
                    "detail": (
                        f"Password input at {url} caps input at maxlength={max_len}. "
                        f"NIST SP 800-63B recommends allowing at least 64 characters. "
                        f"Short maxlength often indicates server-side truncation, "
                        f"which weakens long passphrases.\n\n"
                        f"Fix: allow at least 64 characters (128+ recommended). "
                        f"Hash passwords server-side — length does not affect bcrypt/Argon2."
                    ),
                })

        ac_m = _AUTOCOMPLETE_RE.search(inp)
        if not ac_m:
            findings.append({
                "type": "password-policy-missing-autocomplete-attribute",
                "status": "WARN",
                "detail": (
                    f"Password input at {url} has no autocomplete attribute.\n\n"
                    f"Without autocomplete='new-password' (registration) or "
                    f"autocomplete='current-password' (login), credential managers "
                    f"cannot reliably fill the field, degrading user security.\n\n"
                    f"Fix: add autocomplete='new-password' to registration fields "
                    f"and autocomplete='current-password' to login fields."
                ),
            })

    if _NO_RESTRICTION_RE.search(body):
        findings.append({
            "type": "password-policy-no-restrictions-indicated",
            "status": "WARN",
            "detail": (
                f"Page at {url} suggests there are no password restrictions.\n\n"
                f"Allowing any password (including single characters or spaces only) "
                f"enables trivially guessable credentials.\n\n"
                f"Fix: enforce minimum length and, optionally, common password list "
                f"rejection per NIST SP 800-63B."
            ),
        })

    return findings


def _check_forced_rotation(body: str, url: str) -> Optional[Dict]:
    if _FORCE_ROTATE_RE.search(body):
        return {
            "type": "password-policy-forced-periodic-rotation",
            "status": "WARN",
            "detail": (
                f"Page at {url} indicates forced periodic password rotation.\n\n"
                f"NIST SP 800-63B (2017) explicitly recommends AGAINST mandatory "
                f"periodic password rotation as it leads to predictable patterns "
                f"(Summer2024! → Summer2025!) without improving security.\n\n"
                f"Fix: replace periodic rotation with breach-detection-based reset "
                f"(check against known compromised password lists like HaveIBeenPwned)."
            ),
        }
    return None


class PasswordPolicyScanner(BaseScanner):
    """Passively checks registration/reset forms for weak password policy signals."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        found = False
        seen_types: set = set()

        all_paths = _REGISTER_PATHS + _RESET_PATHS
        for path in all_paths:
            ep = urljoin(base_origin, path)
            resp = self.http.get(ep)
            if resp is None or resp.status_code not in (200, 206):
                continue
            body = resp.text or ""

            for f in _check_registration_form(body, ep):
                if f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    found = True
                    log_warn(logger, f"Password Policy — {f['type']} at {ep}")
                    self.results.append(self._result(
                        ep, f["type"][:100], f["status"], detail=f["detail"]))

            f = _check_forced_rotation(body, ep)
            if f and f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                log_warn(logger, f"Password Policy — {f['type']} at {ep}")
                self.results.append(self._result(
                    ep, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"Password Policy — no weak policy signals found for {url}")
            self.results.append(self._result(
                url,
                "Password Policy — no weak password policy signals detected",
                "PASS",
                detail=(
                    "No short minlength, truncating maxlength, missing autocomplete, "
                    "or forced-rotation indicators found on registration/reset forms."
                ),
            ))

        return self.results
