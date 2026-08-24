"""Host header injection — reflected Host, password reset poisoning, cache poisoning via Host override."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_PROBE_HOST = "attacker-tbl9z7x-hostinject.example.com"

_HOST_OVERRIDE_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
]

_PASSWORD_RESET_PATHS = [
    "/forgot-password", "/forgot_password", "/reset-password", "/reset_password",
    "/account/reset", "/password/reset", "/auth/forgot", "/users/password/new",
]

_LINK_RE = re.compile(r'href=["\']([^"\']+)["\']', re.I)
_ACTION_RE = re.compile(r'action=["\']([^"\']+)["\']', re.I)


def _check_host_reflected_in_body(http, url: str) -> list:
    """Send request with spoofed Host/X-Forwarded-Host and check if probe appears in response."""
    findings = []
    for hdr in _HOST_OVERRIDE_HEADERS:
        try:
            resp = http.get(url, headers={hdr: _PROBE_HOST})
            if resp is None:
                continue
            body = resp.text or ""
            if _PROBE_HOST in body:
                findings.append({
                    "type": "host_header_reflected_in_body",
                    "status": "FAIL",
                    "url": url,
                    "detail": (f"Probe host ({_PROBE_HOST}) reflected in response body via {hdr} — "
                               f"password reset link poisoning or cache poisoning possible"),
                })
                return findings
            location = (resp.headers or {}).get("location", "")
            if _PROBE_HOST in location:
                findings.append({
                    "type": "host_header_reflected_in_redirect",
                    "status": "FAIL",
                    "url": url,
                    "detail": (f"Probe host reflected in Location redirect via {hdr}: {location[:80]}"),
                })
                return findings
        except Exception:
            pass
    return findings


def _check_password_reset_paths(http, origin: str) -> list:
    """Check if password reset pages are accessible (not protected behind auth)."""
    findings = []
    for path in _PASSWORD_RESET_PATHS[:4]:
        try:
            r = http.get(origin + path)
            if r and r.status_code == 200:
                findings.append({
                    "type": "host_header_password_reset_page",
                    "status": "WARN",
                    "url": origin + path,
                    "detail": (f"Password reset page accessible at {path} — "
                               f"ensure Host header is validated to prevent link poisoning"),
                })
                return findings
        except Exception:
            pass
    return findings


def _check_absolute_links_use_host(body: str, url: str) -> list:
    """Check if response contains absolute links using the Host header (could be poisoned)."""
    findings = []
    parsed = urlparse(url)
    probe_origin = f"https://{_PROBE_HOST}"
    all_links = [m.group(1) for m in _LINK_RE.finditer(body)]
    all_links += [m.group(1) for m in _ACTION_RE.finditer(body)]
    for link in all_links:
        if link.startswith(probe_origin):
            findings.append({
                "type": "host_header_link_poisoned",
                "status": "FAIL",
                "url": url,
                "detail": f"Response link points to attacker host: {link[:80]}",
            })
    return findings


class HostHeaderInjectionScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "host_header_no_response", "PASS",
                                 detail="No response")]

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for f in _check_host_reflected_in_body(self.http, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        for f in _check_password_reset_paths(self.http, origin):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        if not results:
            results.append(self._result(url, "host_header_injection_clean", "PASS",
                                        detail="No host header injection indicators detected"))
        return results
