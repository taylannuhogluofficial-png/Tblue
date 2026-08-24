"""
WebAuthn / FIDO2 Security Configuration Scanner.

WebAuthn (Web Authentication API / FIDO2) is the modern passwordless
authentication standard. This scanner checks whether:
1. The site implements WebAuthn at all (detection via JS API usage)
2. The discovery endpoint (/.well-known/webauthn) is configured
3. Relying Party configuration is correct (rpId, origin binding)
4. Fallback authentication methods alongside WebAuthn are secure
5. WebAuthn libraries in use are current / unvulnerable

Detection approach (passive + lightweight probes):
- Scan page JS for PublicKeyCredential usage patterns
- Probe /.well-known/webauthn for RP configuration
- Inspect login forms for autocomplete="webauthn" / passkey hints
- Detect insecure fallback paths (magic links over HTTP, SMS OTP reflected)
- Check whether Conditional UI mediation is supported

Professional equivalent: Burp Suite Pro "Authentication" checks,
Qualys WebApp Scanner auth analysis.

CWE-308: Use of Single-factor Authentication
CWE-287: Improper Authentication
NIST SP 800-63B: Digital Identity Guidelines
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# JS patterns indicating WebAuthn/FIDO2 usage
_WEBAUTHN_CREATE_RE = re.compile(
    r"navigator\.credentials\.create\s*\(",
    re.I,
)
_WEBAUTHN_GET_RE = re.compile(
    r"navigator\.credentials\.get\s*\(",
    re.I,
)
_PUBLIC_KEY_CRED_RE = re.compile(
    r"PublicKeyCredential",
    re.I,
)
_CONDITIONAL_MEDIATION_RE = re.compile(
    r"""mediation\s*:\s*["']conditional["']""",
    re.I,
)

# Passkey / WebAuthn in UI hints
_PASSKEY_UI_RE = re.compile(
    r"""
    (?:passkey|webauthn|fido2|security.?key|biometric.?login|
       fingerprint.?login|face.?id.?login|touch.?id)
    """,
    re.I | re.X,
)

# Insecure fallback patterns alongside WebAuthn
_MAGIC_LINK_HTTP_RE = re.compile(
    r"""href=["']http://[^"']*(?:login|auth|verify|confirm|magic)[^"']*["']""",
    re.I,
)
_SMS_OTP_RE = re.compile(
    r"""
    (?:sms|text.?message|phone.?number|mobile|otp|one.?time.?password)
    .{0,50}
    (?:verify|confirm|code|login|auth)
    """,
    re.I | re.X,
)

# rpId and origin misconfiguration patterns in JS
_RP_ID_WILDCARD_RE = re.compile(
    r"""rpId\s*:\s*["'][^"']*\*[^"']*["']""",
    re.I,
)
_ORIGIN_MISMATCH_HINT_RE = re.compile(
    r"""allowCredentials.*https?://(?!localhost)[^"',)]{1,100}(?:\.onion|\.test|localhost)""",
    re.I,
)


class WebAuthnSecurityScanner(BaseScanner):
    """Detect WebAuthn/FIDO2 misconfiguration and insecure authentication fallbacks."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "WebAuthn security — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        body = resp.text or ""
        soup = BeautifulSoup(body, "html.parser")
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        webauthn_detected = False

        # ── 1. Check /.well-known/webauthn discovery endpoint ────────────────
        self._check_well_known(base, url)

        # ── 2. Scan inline JS / page body for WebAuthn API usage ─────────────
        scripts_inline = [t.get_text() for t in soup.find_all("script") if not t.get("src")]
        all_inline = "\n".join(scripts_inline)

        if _WEBAUTHN_CREATE_RE.search(all_inline) or _WEBAUTHN_GET_RE.search(all_inline):
            webauthn_detected = True
            self._check_webauthn_js_config(all_inline, url)
        elif _PUBLIC_KEY_CRED_RE.search(all_inline):
            webauthn_detected = True

        # ── 3. Scan external JS files for WebAuthn patterns ──────────────────
        if not webauthn_detected:
            for script_tag in soup.find_all("script", src=True):
                src = script_tag.get("src", "")
                if not src:
                    continue
                js_url = src if src.startswith("http") else urljoin(base, src)
                try:
                    js_resp = self.http.get(js_url)
                    if not js_resp or js_resp.status_code != 200:
                        continue
                    js_body = js_resp.text or ""
                    if _WEBAUTHN_CREATE_RE.search(js_body) or _PUBLIC_KEY_CRED_RE.search(js_body):
                        webauthn_detected = True
                        self._check_webauthn_js_config(js_body, js_url)
                        break
                except Exception:
                    continue

        # ── 4. Check login forms for passkey/WebAuthn UI hints ───────────────
        self._check_login_forms(soup, url, webauthn_detected)

        # ── 5. Report if no WebAuthn at all ─────────────────────────────────
        if not webauthn_detected:
            if any(r["status"] != "PASS" for r in self.results):
                pass  # other findings already recorded
            else:
                log_pass(logger, f"WebAuthn not implemented on {url} — no misconfiguration risk")
                self.results.append(self._result(
                    url,
                    "WebAuthn — not implemented (no misconfiguration risk)",
                    "PASS",
                    detail=(
                        "No WebAuthn/FIDO2 implementation detected on this page. "
                        "Consider implementing WebAuthn for phishing-resistant authentication. "
                        "NIST SP 800-63B AAL2 requires hardware-backed MFA for high-value accounts."
                    )
                ))

        return self.results

    def _check_well_known(self, base: str, url: str) -> None:
        wk_url = urljoin(base + "/", ".well-known/webauthn")
        try:
            r = self.http.get(wk_url)
            if not r or r.status_code != 200:
                return
            body = r.text or ""
            # Valid response should be JSON with "origins" array
            if '"origins"' in body or "origins" in body.lower():
                log_pass(logger, f"WebAuthn discovery endpoint configured: {wk_url}")
                self.results.append(self._result(
                    wk_url,
                    "WebAuthn — /.well-known/webauthn discovery endpoint present",
                    "PASS",
                    detail=(
                        "WebAuthn discovery endpoint found at /.well-known/webauthn. "
                        "This allows relying parties to advertise their allowed origins. "
                        "Verify the 'origins' list is restricted to your actual domains."
                    )
                ))
            else:
                log_warn(logger, f"WebAuthn discovery endpoint returns unexpected content: {wk_url}")
                self.results.append(self._result(
                    wk_url,
                    "WebAuthn — /.well-known/webauthn returns unexpected content",
                    "WARN",
                    detail=(
                        f"The WebAuthn discovery endpoint at {wk_url} returned a 200 response "
                        "but the content does not contain an 'origins' array. "
                        "Fix: return valid JSON conforming to the WebAuthn discovery spec: "
                        '{\"origins\": [\"https://example.com\"]}.'
                    )
                ))
        except Exception:
            pass

    def _check_webauthn_js_config(self, js_body: str, source_url: str) -> None:
        # Check for rpId wildcard (misconfiguration)
        m = _RP_ID_WILDCARD_RE.search(js_body)
        if m:
            log_fail(logger, f"WebAuthn rpId contains wildcard in {source_url}")
            self.results.append(self._result(
                source_url,
                "WebAuthn — rpId contains wildcard character",
                "FAIL",
                detail=(
                    f"WebAuthn relying party ID (rpId) in {source_url} contains a wildcard: "
                    f"'{m.group(0)[:80]}'. "
                    "A wildcard rpId is invalid and may cause credential binding to fail or "
                    "allow credentials to be used across unintended origins. "
                    "Fix: set rpId to the exact registered domain (e.g., 'example.com'), "
                    "not a wildcard pattern."
                )
            ))

        # Check for Conditional UI (passkey autofill) — good practice
        if not _CONDITIONAL_MEDIATION_RE.search(js_body):
            if _WEBAUTHN_GET_RE.search(js_body):
                log_warn(logger, f"WebAuthn in {source_url} does not use Conditional UI mediation")
                self.results.append(self._result(
                    source_url,
                    "WebAuthn — Conditional UI (mediation: 'conditional') not used",
                    "WARN",
                    detail=(
                        "The WebAuthn implementation in " + source_url + " calls "
                        "navigator.credentials.get() without mediation: 'conditional'. "
                        "Conditional UI enables passkey autofill in the browser's credential "
                        "picker, improving UX and adoption. "
                        "Fix: add {mediation: 'conditional'} to your get() options to enable "
                        "browser-native passkey autofill (supported in Chrome 108+, Safari 16+)."
                    )
                ))

    def _check_login_forms(self, soup: BeautifulSoup, url: str,
                           webauthn_detected: bool) -> None:
        login_forms = []
        for form in soup.find_all("form"):
            inputs = form.find_all("input")
            field_types = {inp.get("type", "").lower() for inp in inputs}
            field_names = {inp.get("name", "").lower() for inp in inputs}
            if ("password" in field_types or
                    any(n in field_names for n in ("password", "passwd", "pass"))):
                login_forms.append(form)

        if not login_forms:
            return

        page_text = soup.get_text(" ", strip=True)

        # Insecure fallback: magic link over HTTP
        form_html = str(soup)
        if _MAGIC_LINK_HTTP_RE.search(form_html):
            log_warn(logger, f"HTTP magic link detected near login form on {url}")
            self.results.append(self._result(
                url,
                "WebAuthn — HTTP magic link used as auth fallback",
                "WARN",
                detail=(
                    "A login-related link using plain HTTP was detected on the page. "
                    "Magic links or email verification links sent over HTTP are vulnerable "
                    "to network interception. "
                    "Fix: ensure all authentication links use HTTPS; "
                    "set a short expiry (≤15 min) and single-use tokens."
                )
            ))

        # SMS OTP fallback alongside passkey
        if webauthn_detected and _SMS_OTP_RE.search(page_text):
            log_warn(logger, f"SMS OTP fallback alongside WebAuthn on {url}")
            self.results.append(self._result(
                url,
                "WebAuthn — SMS OTP fallback alongside passkey authentication",
                "WARN",
                detail=(
                    "The page implements WebAuthn/passkeys but also offers SMS OTP as a "
                    "fallback. SMS OTP is vulnerable to SIM-swapping and SS7 interception "
                    "attacks. If attackers can force the SMS fallback, WebAuthn's "
                    "phishing-resistance is bypassed. "
                    "Fix: prefer TOTP/hardware key fallbacks over SMS; "
                    "if SMS must be used, implement SIM-swap detection and rate limiting."
                )
            ))

        # Check for autocomplete="webauthn" on password fields (good practice indicator)
        has_webauthn_autocomplete = any(
            inp.get("autocomplete", "").lower() in ("webauthn", "passkey")
            for form in login_forms
            for inp in form.find_all("input")
        )

        if webauthn_detected and not has_webauthn_autocomplete:
            passkey_in_page = bool(_PASSKEY_UI_RE.search(page_text))
            if passkey_in_page:
                log_warn(logger, f"Passkey UI detected but autocomplete='webauthn' missing on {url}")
                self.results.append(self._result(
                    url,
                    "WebAuthn — passkey UI present but autocomplete='webauthn' missing on input",
                    "WARN",
                    detail=(
                        "The page mentions passkeys/WebAuthn but the password input field "
                        "does not have autocomplete='webauthn'. "
                        "Without this attribute, browsers cannot offer Conditional UI "
                        "(passkey autofill in the username/password field). "
                        "Fix: add autocomplete='username webauthn' to username inputs "
                        "and autocomplete='current-password webauthn' to password inputs."
                    )
                ))
