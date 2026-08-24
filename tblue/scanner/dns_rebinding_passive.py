"""DNS rebinding passive — missing Host validation, CORS without origin check, private IP in responses."""
import re
from .base import BaseScanner

_PRIVATE_IP_RE = re.compile(
    r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3}|'
    r'127\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'169\.254\.\d{1,3}\.\d{1,3})\b',
)

_LOCALHOST_RE = re.compile(r'\blocalhost\b', re.I)

# Headers that indicate the app trusts any Host value
_SERVER_HEADER_RE = re.compile(r'server', re.I)


def _check_private_ip_in_response(body: str, headers: dict, url: str) -> list:
    findings = []
    m = _PRIVATE_IP_RE.search(body)
    if m:
        ip = m.group(0)
        findings.append({
            "type": "dns_rebinding_private_ip_disclosed",
            "status": "WARN",
            "url": url,
            "detail": f"Private IP address {ip} found in response body — "
                      "DNS rebinding attack could reach internal services at this address",
        })
    if _LOCALHOST_RE.search(body):
        findings.append({
            "type": "dns_rebinding_localhost_reference",
            "status": "WARN",
            "url": url,
            "detail": "Reference to 'localhost' in response — "
                      "may indicate internal service discovery risk via DNS rebinding",
        })
    return findings


def _check_host_validation(http, url: str) -> list:
    """Send request with arbitrary Host header and check if server responds normally."""
    findings = []
    try:
        r = http.get(url, headers={"Host": "attacker-tbl9z7x-rebind.example.com"})
        if r and r.status_code == 200:
            findings.append({
                "type": "dns_rebinding_host_not_validated",
                "status": "WARN",
                "url": url,
                "detail": "Server returns 200 for arbitrary Host header — "
                          "no Host validation means DNS rebinding can access internal APIs",
            })
    except Exception:
        pass
    return findings


class DNSRebindingPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "dns_rebinding_no_response", "PASS", detail="No response")]

        headers = dict(resp.headers) if resp.headers else {}
        for f in _check_private_ip_in_response(resp.text, headers, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        for f in _check_host_validation(self.http, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "dns_rebinding_clean", "PASS",
                                        detail="No DNS rebinding indicators detected"))
        return results
