"""Active CORS Origin Fuzzer — send crafted Origin headers and map what the server reflects."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

active = True

_ACOF_ANY_RE = re.compile(r'^https?://', re.I)


def _extract_etld_plus1(host: str) -> str:
    """Return the registrable domain (e.g. sub.example.com → example.com)."""
    parts = host.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


class ActiveCORSOriginFuzzScanner(BaseScanner):
    def scan(self, url: str) -> list:
        if not _ACOF_ANY_RE.match(url):
            return [self._result(url, "active_cors_fuzz_not_used", "PASS")]

        parsed = urlparse(url)
        host = parsed.hostname or ""
        scheme = parsed.scheme or "https"
        base_domain = _extract_etld_plus1(host)

        # Build a set of crafted Origins covering common bypass techniques
        origins = [
            ("null_origin",             "null"),
            ("arbitrary_third_party",   "https://evil.com"),
            ("prefix_bypass",           f"https://{base_domain}.evil.com"),
            ("subdomain_suffix_bypass", f"https://evil{base_domain}"),
            ("http_downgrade",          f"http://{host}"),
            ("legitimate_origin",       f"{scheme}://{host}"),
        ]

        findings = []

        for label, origin in origins:
            try:
                resp = self.http.get(url, headers={"Origin": origin})
            except Exception:
                continue
            if resp is None:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            acam = resp.headers.get("Access-Control-Allow-Methods", "")

            if not acao:
                continue

            is_reflected = acao.strip() == origin
            is_wildcard  = acao.strip() == "*"
            is_null      = acao.strip().lower() == "null"
            creds_true   = acac.strip().lower() == "true"

            if label == "null_origin" and is_null and creds_true:
                findings.append(self._result(
                    url, "active_cors_null_origin_with_credentials", "FAIL",
                    detail=f"Server reflects Access-Control-Allow-Origin: null with Access-Control-Allow-Credentials: true — a sandboxed iframe can set Origin: null and make cross-origin credentialed requests; attacker serves victim an iframe with sandbox='allow-scripts allow-same-origin' and reads authenticated API responses (CVE pattern: CORS null origin bypass).",
                ))

            elif label == "null_origin" and is_null:
                findings.append(self._result(
                    url, "active_cors_null_origin_reflected", "WARN",
                    detail="Server allows Origin: null — sandboxed iframes and local HTML files send null origin; combined with ACAC:true this becomes exploitable for credential theft; restrict allowed origins to explicit HTTPS domain list.",
                ))

            elif label == "arbitrary_third_party" and is_reflected and creds_true:
                findings.append(self._result(
                    url, "active_cors_arbitrary_origin_with_credentials", "FAIL",
                    detail=f"Server reflects arbitrary Origin (evil.com → ACAO: {acao}) with ACAC: true — any attacker-controlled site can make credentialed cross-origin requests and read the response; full session-authenticated API access from attacker's domain; fix by maintaining an explicit allowlist of trusted origins.",
                ))

            elif label == "arbitrary_third_party" and is_reflected:
                findings.append(self._result(
                    url, "active_cors_arbitrary_origin_reflected", "WARN",
                    detail=f"Server reflects arbitrary Origin without credentials flag — ACAO: {acao}; if this endpoint handles sensitive data or is combined with CSRF, the response is readable cross-origin; validate Origin against an explicit allowlist.",
                ))

            elif label == "prefix_bypass" and is_reflected and creds_true:
                findings.append(self._result(
                    url, "active_cors_prefix_bypass_with_credentials", "FAIL",
                    detail=f"CORS origin validation vulnerable to suffix bypass — {origin} accepted with ACAO: {acao} and ACAC: true; server checks if Origin ends with the domain but attacker registers a domain that ends with your domain string; validates incorrectly; fix: check exact domain match including dot separator.",
                ))

            elif label == "subdomain_suffix_bypass" and is_reflected and creds_true:
                findings.append(self._result(
                    url, "active_cors_subdomain_suffix_bypass", "FAIL",
                    detail=f"CORS origin validation vulnerable to prefix bypass — {origin} accepted with ACAO: {acao} and ACAC: true; server checks if Origin starts with domain but attackers register a domain starting with your domain; fix: validate full origin string with exact match including scheme.",
                ))

            elif label == "http_downgrade" and is_reflected and creds_true:
                findings.append(self._result(
                    url, "active_cors_http_downgrade_allowed", "WARN",
                    detail=f"HTTP version of origin accepted in CORS policy — {origin} reflected; allows man-in-the-middle on the trusted-origin side to intercept the credentialed cross-origin response; only allow HTTPS origins.",
                ))

            elif is_wildcard and creds_true:
                findings.append(self._result(
                    url, "active_cors_wildcard_with_credentials", "FAIL",
                    detail="Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true — browsers block this combination per spec but some frameworks incorrectly allow it; audit the CORS middleware configuration for this invalid combination.",
                ))

        return findings or [self._result(url, "active_cors_origin_fuzz_clean", "PASS",
                                          detail="No CORS origin reflection vulnerabilities detected across null, arbitrary, prefix-bypass, suffix-bypass, and HTTP-downgrade Origin vectors.")]
