"""XXE passive — XML external entity indicators in API responses, Content-Type negotiation."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_XML_CONTENT_TYPES = {
    "application/xml", "text/xml", "application/xhtml+xml",
    "application/soap+xml", "application/rss+xml", "application/atom+xml",
}

_DTD_RE = re.compile(r'<!DOCTYPE\s+\w+\s*(?:PUBLIC|SYSTEM)\s+["\'][^"\']+["\']', re.I)
_EXTERNAL_ENTITY_RE = re.compile(r'<!ENTITY\s+\w+\s+SYSTEM\s+["\']([^"\']+)["\']', re.I)
_PARAMETER_ENTITY_RE = re.compile(r'<!ENTITY\s+%\s+\w+\s+SYSTEM\s+["\']([^"\']+)["\']', re.I)

# Paths that might accept XML input
_XML_UPLOAD_PATHS = [
    "/api/", "/api/v1/", "/upload", "/import", "/data",
    "/feed", "/rss", "/atom", "/sitemap.xml",
]

# XXE payloads to detect in error responses (only passive — we send legitimate XML)
_XXE_ERROR_INDICATORS = [
    "xml parsing error",
    "xml syntax error",
    "entity declaration",
    "external entity",
    "doctype not allowed",
]
_XXE_ERROR_RE = re.compile("|".join(_XXE_ERROR_INDICATORS), re.I)


def _check_xml_response_for_xxe(body: str, content_type: str, url: str) -> list:
    """Check XML response body for DTD/entity declarations that could indicate XXE surface."""
    findings = []
    ct = content_type.split(";")[0].strip().lower()
    if ct not in _XML_CONTENT_TYPES:
        # Only flag if content looks like XML
        if not body.strip().startswith("<?xml") and not body.strip().startswith("<"):
            return findings

    m = _EXTERNAL_ENTITY_RE.search(body)
    if m:
        protocol = m.group(1)
        findings.append({
            "type": "xxe_external_entity_in_response",
            "status": "FAIL",
            "url": url,
            "detail": (f"External ENTITY SYSTEM declaration in XML response: {protocol[:60]} — "
                       f"server may be reflecting attacker-supplied XML with XXE"),
        })

    m = _PARAMETER_ENTITY_RE.search(body)
    if m:
        findings.append({
            "type": "xxe_parameter_entity_in_response",
            "status": "FAIL",
            "url": url,
            "detail": "Parameter entity SYSTEM declaration in XML response — blind XXE indicator",
        })

    if _DTD_RE.search(body) and not findings:
        findings.append({
            "type": "xxe_dtd_in_response",
            "status": "WARN",
            "url": url,
            "detail": "DOCTYPE with PUBLIC/SYSTEM in XML response — DTD present, XXE surface exists",
        })

    return findings


def _check_xml_endpoint_accepts_dtd(http, url: str) -> list:
    """Send XML with DOCTYPE to API endpoint; if error mentions DTD/entity → XXE surface."""
    findings = []
    payload = ('<?xml version="1.0"?><!DOCTYPE tbl9z7x [<!ENTITY test "probe">]>'
               '<root>&test;</root>')
    try:
        resp = http.post(url, data=payload,
                         headers={"Content-Type": "application/xml"})
        if resp and resp.status_code in (200, 201, 400, 422, 500):
            body = resp.text or ""
            if "probe" in body:
                findings.append({
                    "type": "xxe_entity_reflected",
                    "status": "FAIL",
                    "url": url,
                    "detail": "XML entity value 'probe' reflected in API response — "
                              "internal entities processed, XXE may be exploitable",
                })
            elif _XXE_ERROR_RE.search(body):
                findings.append({
                    "type": "xxe_dtd_error_disclosed",
                    "status": "WARN",
                    "url": url,
                    "detail": "XML parser error mentions entities/DTD — XXE parsing surface confirmed",
                })
    except Exception:
        pass
    return findings


class XXEPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "xxe_no_response", "PASS",
                                 detail="No response")]

        headers = dict(resp.headers) if resp.headers else {}
        content_type = headers.get("content-type", "")

        for f in _check_xml_response_for_xxe(resp.text, content_type, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for path in _XML_UPLOAD_PATHS[:3]:
            for f in _check_xml_endpoint_accepts_dtd(self.http, origin + path):
                results.append(self._result(f["url"], f["type"], f["status"],
                                            detail=f["detail"]))

        if not results:
            results.append(self._result(url, "xxe_clean", "PASS",
                                        detail="No XXE indicators detected"))
        return results
