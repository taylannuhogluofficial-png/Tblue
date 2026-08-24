"""XML security passive — XXE-prone content types, DTD in responses, SOAP exposure."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_XML_CONTENT_TYPES = re.compile(
    r"application/(?:xml|soap\+xml|xhtml\+xml|rss\+xml|atom\+xml|xslt\+xml)|text/xml",
    re.I,
)
_DTD_RE     = re.compile(r"<!DOCTYPE\s+\w+\s+(?:PUBLIC|SYSTEM)\s+[\"']", re.I)
_ENTITY_RE  = re.compile(r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']", re.I)
_SOAP_RE    = re.compile(r"(?:SOAP-ENV:|soapenv:|soap:)(?:Envelope|Body|Header)", re.I)
_XXERISK_RE = re.compile(r"<!DOCTYPE[^>]*(?:file|http|ftp|expect|php)://", re.I)

_SOAP_PATHS = ["/soap", "/ws", "/services", "/wsdl", "/api/soap", "/webservice"]
_WSDL_PATHS = ["/service?wsdl", "/ws?wsdl", "/?wsdl", "/api?wsdl", "/wsdl"]


def _check_xml_response(body: str, content_type: str, url: str) -> list:
    findings = []
    is_xml = bool(_XML_CONTENT_TYPES.search(content_type))

    if is_xml and _DTD_RE.search(body):
        if _XXERISK_RE.search(body):
            findings.append({
                "type": "xml_dtd_with_external_uri",
                "status": "FAIL",
                "detail": "XML response contains DOCTYPE with external URI — XXE potential",
            })
        else:
            findings.append({
                "type": "xml_dtd_in_response",
                "status": "WARN",
                "detail": "XML response contains DOCTYPE declaration — review XXE mitigations",
            })

    if _ENTITY_RE.search(body):
        findings.append({
            "type": "xml_external_entity_declaration",
            "status": "FAIL",
            "detail": "XML ENTITY with SYSTEM reference found — direct XXE vector",
        })

    if _SOAP_RE.search(body):
        findings.append({
            "type": "soap_endpoint_exposure",
            "status": "WARN",
            "detail": "SOAP envelope detected in response — verify SOAP endpoint authentication",
        })
    return findings


def _check_wsdl_exposure(http, origin: str) -> list:
    findings = []
    for path in _WSDL_PATHS:
        try:
            r = http.get(origin + path)
            if r and r.status_code == 200:
                ct = r.headers.get("content-type", "")
                if "xml" in ct.lower() or "<definitions" in r.text or "<wsdl:" in r.text:
                    findings.append({
                        "type": "wsdl_exposure",
                        "status": "WARN",
                        "url": origin + path,
                        "detail": f"WSDL document exposed at {path} — discloses service API surface",
                    })
                    break
        except Exception:
            pass
    return findings


class XMLSecurityPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "xml_security_no_response", "PASS",
                                 detail="No response")]

        ct = resp.headers.get("content-type", "")
        for f in _check_xml_response(resp.text, ct, url):
            results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for path in _SOAP_PATHS:
            try:
                r = self.http.get(origin + path)
                if r and r.status_code == 200:
                    r_ct = r.headers.get("content-type", "")
                    for f in _check_xml_response(r.text, r_ct, origin + path):
                        results.append(self._result(origin + path, f["type"],
                                                    f["status"], detail=f["detail"]))
            except Exception:
                pass

        for f in _check_wsdl_exposure(self.http, origin):
            results.append(self._result(f.get("url", url), f["type"], f["status"],
                                        detail=f["detail"]))

        if not results:
            results.append(self._result(url, "xml_security_clean", "PASS",
                                        detail="No XML/SOAP security issues detected"))
        return results
