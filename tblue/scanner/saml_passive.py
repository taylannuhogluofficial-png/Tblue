"""SAML passive — SSO login page detection, signature bypass hints, XXE in SAML, weak bindings."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_SAML_PATHS = [
    "/saml/login", "/saml/sso", "/auth/saml", "/sso/saml",
    "/saml2/login", "/Shibboleth.sso", "/idp/profile/SAML2",
    "/saml/metadata", "/saml/acs",
]

_SAML_RESPONSE_RE = re.compile(r'SAMLResponse|SAMLRequest|SAMLart', re.I)
_SAML_REDIRECT_RE = re.compile(r'RelayState=|SigAlg=|Signature=', re.I)
_XML_SIG_RE = re.compile(r'ds:Signature|ds:SignatureValue|ds:SignedInfo', re.I)
_WEAK_SIG_ALG_RE = re.compile(
    r'SigAlg=([^&\s]+)',
    re.I,
)
_SHA1_ALG = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
_COMMENT_INJECTION_RE = re.compile(r'<!-[^>]*->|<!--', re.I)

_SAML_FORM_RE = re.compile(
    r'<input\b[^>]*\bname=["\']SAMLResponse["\'][^>]*>', re.I
)


def _check_saml_in_page(body: str, url: str) -> list:
    findings = []
    if _SAML_RESPONSE_RE.search(body):
        if _SAML_FORM_RE.search(body):
            findings.append({
                "type": "saml_response_in_form",
                "status": "WARN",
                "url": url,
                "detail": "SAMLResponse found in HTML form — POST binding in use; "
                          "verify signature validation and recipient matching",
            })
        if _COMMENT_INJECTION_RE.search(body):
            findings.append({
                "type": "saml_comment_injection_risk",
                "status": "WARN",
                "url": url,
                "detail": "XML comments detected in SAML context — "
                          "some parsers may allow comment injection to bypass signature validation",
            })
    return findings


def _check_saml_weak_sig_alg(url: str) -> list:
    """Check URL for weak signature algorithm in SAML redirect binding."""
    findings = []
    m = _WEAK_SIG_ALG_RE.search(url)
    if m:
        import urllib.parse
        alg = urllib.parse.unquote(m.group(1))
        if "sha1" in alg.lower() or alg == _SHA1_ALG:
            findings.append({
                "type": "saml_weak_signature_algorithm",
                "status": "WARN",
                "url": url,
                "detail": f"SAML uses SHA-1 signature algorithm: {alg[:80]} — "
                          "upgrade to SHA-256 (rsa-sha256)",
            })
    return findings


def _probe_saml_endpoints(http, origin: str) -> list:
    """Check if SAML endpoints are exposed."""
    findings = []
    for path in _SAML_PATHS[:4]:
        try:
            r = http.get(origin + path)
            if r and r.status_code in (200, 302, 400, 405):
                findings.append({
                    "type": "saml_endpoint_exposed",
                    "status": "WARN",
                    "url": origin + path,
                    "detail": f"SAML endpoint {path} accessible (HTTP {r.status_code}) — "
                              "verify signature validation, recipient binding, and replay protection",
                })
                return findings
        except Exception:
            pass
    return findings


class SAMLPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "saml_no_response", "PASS", detail="No response")]

        for f in _check_saml_in_page(resp.text, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        for f in _check_saml_weak_sig_alg(url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        for f in _probe_saml_endpoints(self.http, origin):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "saml_clean", "PASS",
                                        detail="No SAML security issues detected"))
        return results
