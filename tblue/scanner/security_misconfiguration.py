"""Security misconfiguration — cross-cutting checks beyond individual headers."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_BACKUP_EXTENSIONS = [
    ".bak", ".old", ".orig", ".backup", ".copy", ".tmp", ".save", ".swp", "~",
]
_COMMON_FILE_BASES = ["index", "config", "database", "db", "app", "main", "settings"]

_VERSION_COMMENT_RE = re.compile(
    r"<!--\s*(?:version|ver|v)\s*[\d.]+|<!--\s*\d+\.\d+", re.I
)
_DEBUG_COMMENT_RE = re.compile(
    r"<!--\s*(?:TODO|FIXME|HACK|debug|password|secret|key|token)\b", re.I
)
_INTERNAL_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)


def _check_backup_files(http, origin: str) -> list:
    findings = []
    for base in _COMMON_FILE_BASES[:3]:  # limit probes
        for ext in _BACKUP_EXTENSIONS[:4]:
            path = f"/{base}{ext}"
            try:
                r = http.get(origin + path)
                if r and r.status_code == 200 and len(r.text) > 50:
                    findings.append({
                        "type": "backup_file_exposure",
                        "status": "FAIL",
                        "url": origin + path,
                        "detail": f"Backup file accessible: {path}",
                    })
                    return findings  # one is enough signal
            except Exception:
                pass
    return findings


def _check_html_comments(body: str, url: str) -> list:
    findings = []
    if _VERSION_COMMENT_RE.search(body):
        findings.append({
            "type": "version_in_html_comment",
            "status": "WARN",
            "url": url,
            "detail": "Version number found in HTML comment — information disclosure",
        })
    if _DEBUG_COMMENT_RE.search(body):
        findings.append({
            "type": "sensitive_html_comment",
            "status": "WARN",
            "url": url,
            "detail": "Sensitive keyword (TODO/FIXME/password/secret) in HTML comment",
        })
    return findings


def _check_internal_ip_leak(body: str, headers: dict, url: str) -> dict | None:
    combined = body[:4096] + " ".join(headers.values())
    if _INTERNAL_IP_RE.search(combined):
        return {
            "type": "internal_ip_disclosure",
            "status": "WARN",
            "url": url,
            "detail": "Private/internal IP address found in response body or headers",
        }
    return None


class SecurityMisconfigurationScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "security_misconfiguration_no_response", "PASS",
                                 detail="No response")]

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # HTML comment leakage
        for f in _check_html_comments(resp.text, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        # Internal IP in response
        ip_finding = _check_internal_ip_leak(resp.text, dict(resp.headers), url)
        if ip_finding:
            results.append(self._result(ip_finding["url"], ip_finding["type"],
                                        ip_finding["status"], detail=ip_finding["detail"]))

        # Backup file exposure
        for f in _check_backup_files(self.http, origin):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "security_misconfiguration_clean", "PASS",
                                        detail="No security misconfigurations detected"))
        return results
