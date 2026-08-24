"""XPath injection passive — XML/LDAP/XPath error patterns in responses, tainted input in queries."""
import re
from .base import BaseScanner

_XPATH_ERROR_RE = re.compile(
    r'(?:'
    r'XPathException|XPath error|xpath.*expression|'
    r'javax\.xml\.xpath|net\.sf\.saxon|'
    r'Invalid XPath|XPath syntax|unterminated string|'
    r'SimpleXML.*XPath|DOMXPath.*query|'
    r'System\.Xml\.XPath|XPathNavigator|'
    r'XPath.*\beval\b'
    r')',
    re.I,
)

_XML_ERROR_RE = re.compile(
    r'(?:'
    r'XML parse error|SAXParseException|'
    r'org\.xml\.sax|com\.sun\.org\.apache.*parser|'
    r'XML document.*malformed|Premature end of file|'
    r'javax\.xml\.parsers|DocumentBuilderFactory|'
    r'XMLReader.*error'
    r')',
    re.I,
)

_LDAP_ERROR_RE = re.compile(
    r'(?:'
    r'LDAPException|LDAP error|javax\.naming\.ldap|'
    r'com\.sun\.jndi\.ldap|'
    r'Invalid DN syntax|LDAP.*filter.*error|'
    r'javax\.naming\.NamingException'
    r')',
    re.I,
)

_XQUERY_ERROR_RE = re.compile(
    r'(?:'
    r'XQuery error|XQueryException|'
    r'net\.sf\.saxon\.query|'
    r'XQuery.*compilation|Saxon-EE.*XQuery'
    r')',
    re.I,
)

_PROBE_PATHS = [
    "/?id=1'", "/?q=1'", "/?search=1'",
    "/?user=admin'", "/?name=test'",
    "/?id=1%27", "/?q=test%27",
]

_TAINTED_XPATH_IN_JS_RE = re.compile(
    r'(?:evaluate|selectNodes|selectSingleNode)\s*\([^)]*(?:param|query|search|input)',
    re.I,
)

_XML_CONTENT_TYPE_RE = re.compile(r'(?:text/xml|application/xml|application/xhtml)', re.I)


def _check_xpath_error_disclosure(http, url: str) -> list:
    findings = []
    for probe in _PROBE_PATHS[:4]:
        try:
            probe_url = url.rstrip("/") + probe
            resp = http.get(probe_url)
            if resp is None:
                continue
            body = resp.text or ""
            if _XPATH_ERROR_RE.search(body):
                findings.append({
                    "type": "xpath_injection_error_disclosed",
                    "status": "FAIL",
                    "url": probe_url,
                    "detail": (f"XPath exception/error message in response to probe {probe!r} — "
                               f"XPath injection may be possible; error details reveal query structure"),
                })
                return findings
            if _XML_ERROR_RE.search(body):
                findings.append({
                    "type": "xml_parse_error_disclosed",
                    "status": "WARN",
                    "url": probe_url,
                    "detail": (f"XML parse error in response to probe {probe!r} — "
                               f"XML processing with user input detected; review for injection"),
                })
                return findings
            if _LDAP_ERROR_RE.search(body):
                findings.append({
                    "type": "ldap_error_disclosed",
                    "status": "FAIL",
                    "url": probe_url,
                    "detail": ("LDAP exception in response to probe — LDAP injection may be possible"),
                })
                return findings
        except Exception:
            pass
    return findings


class XPathInjectionPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "xpath_injection_no_response", "PASS",
                                 detail="No response")]

        body = resp.text or ""

        if _TAINTED_XPATH_IN_JS_RE.search(body):
            results.append(self._result(url, "xpath_tainted_js_query", "WARN",
                                        detail="XPath evaluate/selectNodes called with potentially user-controlled argument in client JS"))

        if _XQUERY_ERROR_RE.search(body):
            results.append(self._result(url, "xquery_error_disclosed", "WARN",
                                        detail="XQuery error message detected in page — review XQuery inputs for injection"))

        for f in _check_xpath_error_disclosure(self.http, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "xpath_injection_clean", "PASS",
                                        detail="No XPath/LDAP/XML injection error indicators detected"))
        return results
