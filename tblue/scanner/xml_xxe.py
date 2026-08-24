"""
XML / XXE (XML External Entity) Indicator Scanner.

Passively detects XML-consuming endpoints and checks for XXE-prone
configurations visible from the outside:

1. WSDL / WADL endpoint exposure — reveals full SOAP API surface
2. XML content-type forms — POST endpoints accepting application/xml without
   visible protection headers
3. SOAP action headers — legacy SOAP services often lack XXE mitigation
4. DTD / DOCTYPE references in responses — suggests XML parsing without hardening
5. XML error messages — parser errors that confirm XML consumption
6. Spring WS / Apache CXF / JAX-WS endpoint indicators

All checks are passive or limited HTTP probing — no XXE payload injection.

Paid equivalents: Burp Suite Pro active scanner, Acunetix XXE scan.
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# WSDL / WADL / SOAP probe paths
_WSDL_PATHS = [
    "?wsdl", "?WSDL", "?wsdl=1",
    "/service?wsdl", "/ws?wsdl", "/soap?wsdl", "/api?wsdl",
    "/services?wsdl", "/WebService?wsdl",
    "/service.asmx?wsdl", "/Service.svc?wsdl",
    "/endpoint?wsdl",
    "?wadl", "/application.wadl", "/api/wadl",
    "/services", "/soap", "/wsdl",
    "/api/soap", "/soap/api",
    "/rpc", "/xmlrpc", "/xmlrpc.php",
]

# XML namespace / SOAP indicators in response bodies
_SOAP_INDICATOR_RE = re.compile(
    r"<(?:soap|soapenv|wsdl|wsa|xsd|xs):[\w-]+|"
    r'xmlns(?::\w+)?=["\']http://schemas\.xmlsoap\.org|'
    r"<definitions\s|<wsdl:|<service\s|<binding\s+name=|"
    r"Content-Type:\s*text/xml|SOAPAction:",
    re.I,
)

# DTD / DOCTYPE in response — a flag for un-hardened XML parsing
_DOCTYPE_RE = re.compile(r"<!DOCTYPE\s+\w+\s+(?:SYSTEM|PUBLIC)\s+", re.I)

# XML parser error messages that confirm XML consumption
_XML_ERROR_RE = re.compile(
    r"org\.xml\.sax\.|javax\.xml\.|"
    r"SAXParseException|XMLParseException|"
    r"xml\.etree\.|lxml\.|expat error|"
    r"DOMException|XmlException|"
    r"System\.Xml\.|XmlDocument\.|"
    r"XML parse error|malformed XML|"
    r"unexpected end of file.*XML|"
    r"content is not allowed in prolog",
    re.I,
)

# Form action with XML-hinting content types
_XML_FORM_MIME_RE = re.compile(r'enctype=["\'](?:text/xml|application/xml)', re.I)

# Content-Type in response indicating XML
_XML_CONTENT_TYPE_RE = re.compile(
    r"application/xml|text/xml|application/soap\+xml|application/rss\+xml|"
    r"application/atom\+xml|application/xhtml\+xml",
    re.I,
)


class XXEScanner(BaseScanner):
    """Detect XML/XXE-prone endpoints through passive analysis and lightweight probing."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if not resp:
            return self.results

        body = resp.text or ""
        soup = BeautifulSoup(body, "html.parser")

        # ── 1. Page-level XML content type check ─────────────────────────────
        content_type = resp.headers.get("content-type", "")
        if _XML_CONTENT_TYPE_RE.search(content_type):
            log_warn(logger, f"Page itself served as XML content type: {content_type}")
            self.results.append(self._result(
                url, f"XML endpoint — page served as {content_type}", "WARN",
                detail=(
                    f"The target URL returns Content-Type: {content_type}. "
                    "XML-serving endpoints must disable external entity processing "
                    "(XXE) in their parser. Set features: "
                    "FEATURE_EXTERNAL_GENERAL_ENTITIES=false, "
                    "FEATURE_EXTERNAL_PARAMETER_ENTITIES=false. "
                    "Use secure parser settings (defusedxml in Python, "
                    "disableExternalEntities() in Java)."
                )
            ))

        # ── 2. XML error messages in page source ──────────────────────────────
        error_match = _XML_ERROR_RE.search(body)
        if error_match:
            snippet = error_match.group(0)[:80]
            log_warn(logger, f"XML parser error message in response: {snippet}")
            self.results.append(self._result(
                url, "XML endpoint — parser error message exposed", "WARN",
                detail=(
                    f"XML parser exception visible in page source: '{snippet}'. "
                    "This confirms the endpoint parses XML and reveals the XML library "
                    "in use. Error message suppression should be implemented, and the "
                    "parser should be configured to reject external entity definitions."
                )
            ))

        # ── 3. DOCTYPE / DTD reference in response ────────────────────────────
        if _DOCTYPE_RE.search(body):
            log_fail(logger, "DOCTYPE reference found in XML response")
            self.results.append(self._result(
                url, "XML endpoint — DOCTYPE/DTD reference in response", "FAIL",
                detail=(
                    "A DOCTYPE or DTD reference was found in the XML response. "
                    "If the server-side parser processes DTD references without "
                    "disabling them, this is a direct XXE precondition. "
                    "Fix: configure XML parsers to disallow DOCTYPE declarations "
                    "(e.g., setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)). "
                    "In Python use defusedxml; in Java use XMLInputFactory with "
                    "IS_SUPPORTING_EXTERNAL_ENTITIES=false."
                )
            ))

        # ── 4. XML forms on the page ──────────────────────────────────────────
        if _XML_FORM_MIME_RE.search(body):
            log_warn(logger, "Form with XML content type detected")
            self.results.append(self._result(
                url, "XML endpoint — form with XML MIME type", "WARN",
                detail=(
                    "A form was found with enctype='application/xml' or 'text/xml'. "
                    "XML form submissions must be parsed securely with external "
                    "entity processing disabled."
                )
            ))

        # ── 5. SOAP indicators in page ────────────────────────────────────────
        if _SOAP_INDICATOR_RE.search(body):
            log_warn(logger, f"SOAP/XML namespace indicators detected on {url}")
            self.results.append(self._result(
                url, "XML endpoint — SOAP/XML service indicators in page source", "WARN",
                detail=(
                    "SOAP XML namespace declarations or WSDL content found in the page. "
                    "SOAP services are frequent targets for XXE injection via crafted "
                    "SOAP envelopes. Verify the endpoint disables external entity "
                    "processing and validates SOAPAction headers."
                )
            ))

        # ── 6. WSDL / WADL probe ─────────────────────────────────────────────
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        found_wsdl: List[str] = []
        for path in _WSDL_PATHS:
            probe_url = url.rstrip("/") + path if path.startswith("?") else base + path
            try:
                r = self.http.get(probe_url)
                if not r or r.status_code not in (200, 206):
                    continue
                rbody = r.text or ""
                if _SOAP_INDICATOR_RE.search(rbody) or "wsdl" in rbody.lower()[:500]:
                    found_wsdl.append(probe_url)
            except Exception:
                continue

        for wsdl_url in found_wsdl[:3]:
            sev = "FAIL" if "wsdl" in wsdl_url.lower() or "wadl" in wsdl_url.lower() else "WARN"
            log_fail(logger, f"WSDL/SOAP descriptor exposed: {wsdl_url}") if sev == "FAIL" else \
                log_warn(logger, f"SOAP service endpoint found: {wsdl_url}")
            self.results.append(self._result(
                probe_url, f"XML endpoint — WSDL/SOAP service exposed ({wsdl_url})", sev,
                detail=(
                    f"A WSDL or SOAP descriptor was found at {wsdl_url}. "
                    "WSDL files expose the full API surface including method names, "
                    "parameter types, and service bindings. Ensure: "
                    "(1) WSDL access is restricted to authorized clients, "
                    "(2) The SOAP handler disables XXE, "
                    "(3) Input validation is applied to all SOAP parameters. "
                    "Restrict WSDL access behind authentication if the service is internal."
                )
            ))

        if not self.results:
            log_pass(logger, f"No XML/XXE-prone indicators found on {url}")
            self.results.append(self._result(
                url, "XML/XXE — no XML endpoints or indicators detected", "PASS",
                detail="No WSDL, SOAP, DTD references, or XML content types found."
            ))

        return self.results
