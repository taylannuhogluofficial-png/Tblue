"""Web OTP API security scanner — OTP interception, auto-read, forwarding to remote."""
import re
from .base import BaseScanner

_OTP_CREDENTIAL_RE = re.compile(r'OTPCredential\b', re.I)
_OTP_GET_RE        = re.compile(r'navigator\.credentials\.get\s*\([^)]*otp', re.I | re.S)
_OTP_ANY_RE        = re.compile(r'(?:OTPCredential|otp\s*:\s*\{)', re.I)

# OTP code transmitted to non-same-origin
_OTP_SEND_RE = re.compile(
    r'(?:code|otp|oneTimeCode)[^;]{0,200}(?:fetch|XMLHttpRequest|sendBeacon)',
    re.I | re.S
)

# OTP sent to analytics/third party
_OTP_THIRD_PARTY_RE = re.compile(
    r'(?:gtag|analytics|fbq|mixpanel)[^;]{0,200}(?:code|otp|oneTimeCode)',
    re.I | re.S
)

# OTP read automatically on page load
_OTP_AUTO_READ_RE = re.compile(
    r'(?:DOMContentLoaded|window\.onload|addEventListener\s*\(\s*["\']load["\'])[^;]{0,400}OTPCredential',
    re.I | re.S
)

# OTP not used for verification — just stored
_OTP_STORED_INSECURE_RE = re.compile(
    r'(?:localStorage|sessionStorage|cookie)[^;]{0,100}(?:code|otp|oneTimeCode)',
    re.I | re.S
)

# Signal AbortController not used — OTP stays pending indefinitely
_OTP_NO_ABORT_RE = re.compile(r'OTPCredential\b', re.I)
_OTP_ABORT_RE    = re.compile(r'AbortController\b', re.I)


class WebOTPSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "web_otp_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _OTP_ANY_RE.search(body):
            return [self._result(url, "web_otp_not_used", "INFO",
                                 detail="Web OTP API not detected")]

        results = []

        if _OTP_AUTO_READ_RE.search(body):
            results.append(self._result(url, "web_otp_auto_read", "WARN",
                                        detail="OTP credential requested on page load — OTP stays pending until dismissed or used"))

        if _OTP_SEND_RE.search(body):
            results.append(self._result(url, "web_otp_code_transmitted", "WARN",
                                        detail="OTP code transmitted over fetch/XHR — ensure server-side verification, not just forwarding"))

        if _OTP_THIRD_PARTY_RE.search(body):
            results.append(self._result(url, "web_otp_code_to_analytics", "FAIL",
                                        detail="OTP code passed to analytics/third-party — OTP values must never be shared with third parties"))

        if _OTP_STORED_INSECURE_RE.search(body):
            results.append(self._result(url, "web_otp_stored_insecure", "FAIL",
                                        detail="OTP code stored in localStorage/sessionStorage/cookie — OTPs should be single-use and ephemeral"))

        if _OTP_NO_ABORT_RE.search(body) and not _OTP_ABORT_RE.search(body):
            results.append(self._result(url, "web_otp_no_abort_controller", "WARN",
                                        detail="OTP credential request without AbortController — request may hang indefinitely"))

        if not results:
            results.append(self._result(url, "web_otp_found_no_issues", "PASS",
                                        detail="Web OTP API usage appears safe"))

        return results
