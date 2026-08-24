"""Email configuration exposure — SMTP credentials in JS, mail server headers, test endpoints."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_SMTP_CRED_RE = re.compile(
    r'(?:smtp|mail|mailer|nodemailer|sendmail)\s*[=:]\s*\{[^}]*(?:password|pass|pwd|auth)\s*[=:]\s*["\'][^"\']+["\']',
    re.I | re.S,
)
_SMTP_HOST_RE = re.compile(
    r'(?:smtp_host|smtp\.host|smtpHost|MAIL_HOST|SMTP_HOST)\s*[=:]\s*["\']([^"\']+)["\']',
    re.I,
)
_MAILHOG_RE   = re.compile(r"MailHog|mailhog\.local|MailCatcher|mailcatcher\.me", re.I)
_TEST_SMTP_PATHS = [
    "/mail", "/mailhog", "/mail/", "/webmail", "/_mail",
    "/mail-ui", "/email-preview",
]


def _check_smtp_in_js(body: str, url: str) -> list:
    findings = []
    if _SMTP_CRED_RE.search(body):
        findings.append({
            "type": "smtp_credentials_in_js",
            "status": "FAIL",
            "detail": "SMTP credentials found in JavaScript source — rotate credentials immediately",
        })
    hosts = _SMTP_HOST_RE.findall(body)
    for host in hosts[:3]:
        findings.append({
            "type": "smtp_host_disclosure",
            "status": "WARN",
            "detail": f"SMTP host disclosed in response: {host}",
        })
    return findings


def _check_test_mail_ui(http, origin: str) -> list:
    findings = []
    for path in _TEST_SMTP_PATHS:
        try:
            r = http.get(origin + path)
            if r and r.status_code == 200:
                if _MAILHOG_RE.search(r.text) or "inbox" in r.text.lower()[:500]:
                    findings.append({
                        "type": "test_mail_ui_exposed",
                        "status": "FAIL",
                        "url": origin + path,
                        "detail": f"Test mail UI (MailHog/MailCatcher) exposed at {path} — "
                                  "captures all emails sent by the application",
                    })
                    break
        except Exception:
            pass
    return findings


class EmailConfigExposureScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "email_config_no_response", "PASS",
                                 detail="No response")]

        # Check page source for SMTP credentials/host
        for f in _check_smtp_in_js(resp.text, url):
            results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        # Check SMTP-related response headers
        for header_name in ("x-mailer", "x-smtp-server", "x-mail-host"):
            val = next((v for k, v in resp.headers.items() if k.lower() == header_name), None)
            if val:
                results.append(self._result(url, "smtp_header_disclosure", "WARN",
                                            detail=f"SMTP configuration header '{header_name}: {val}' disclosed"))

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Probe for test mail UI
        for f in _check_test_mail_ui(self.http, origin):
            results.append(self._result(f.get("url", url), f["type"], f["status"],
                                        detail=f["detail"]))

        if not results:
            results.append(self._result(url, "email_config_clean", "PASS",
                                        detail="No email configuration exposure detected"))
        return results
