"""XML External Entity Advanced scanner — passive detection of XXE indicators in responses and source."""
import re
from .base import BaseScanner

_XXE_ANY_RE = re.compile(
    r'(?:<!DOCTYPE|<!ENTITY|SYSTEM\s+["\']|PUBLIC\s+["\']|'
    r'xml version|application/xml|text/xml|'
    r'SAXParseException|XMLSyntaxError|ExpatError|'
    r'DOMParser|parseFromString|XMLHttpRequest)',
    re.I,
)

_XXE_DOCTYPE_RE = re.compile(
    r'<!DOCTYPE\s+\w+\s*\[',
    re.I,
)

_XXE_EXTERNAL_ENTITY_RE = re.compile(
    r'<!ENTITY\s+\w+\s+SYSTEM\s+["\'](?:file://|http://|https://|ftp://|/dev/|/etc/)',
    re.I,
)

_XXE_PARAMETER_ENTITY_RE = re.compile(
    r'<!ENTITY\s+%\s+\w+\s+SYSTEM\s+["\']',
    re.I,
)

_XXE_ERROR_DISCLOSURE_RE = re.compile(
    r'(?:XML\s+parsing\s+error|SAXParseException|XMLSyntaxError|'
    r'ExpatError|ParseError.*line\s+\d+|'
    r'org\.xml\.sax\.|javax\.xml\.|System\.Xml\.)',
    re.I,
)

_XXE_SERVER_SIDE_INCLUDE_RE = re.compile(
    r'<!--\s*#(?:include|exec|echo|printenv|set)\s+',
    re.I,
)

_XXE_DOM_PARSE_UNSAFE_RE = re.compile(
    r'new\s+DOMParser\s*\(\s*\).*?parseFromString\s*\([^,)]{0,200}'
    r'(?:searchParams|location\.hash|userInput|req\.body)',
    re.I | re.S,
)


class XMLExternalEntityAdvancedScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "xxe_advanced_not_used", "PASS")]

        body = resp.text
        if not _XXE_ANY_RE.search(body):
            return [self._result(url, "xxe_advanced_not_used", "PASS")]

        findings = []

        if _XXE_EXTERNAL_ENTITY_RE.search(body):
            findings.append(self._result(
                url, "xxe_external_entity_declaration", "FAIL",
                detail="DOCTYPE with SYSTEM entity referencing file:// or http:// URL — XML parser may resolve the entity and include contents of local files (e.g., /etc/passwd) or trigger SSRF to internal services.",
            ))

        if _XXE_PARAMETER_ENTITY_RE.search(body):
            findings.append(self._result(
                url, "xxe_parameter_entity", "FAIL",
                detail="Parameter entity (% name SYSTEM) in DOCTYPE — used in blind XXE to exfiltrate data out-of-band via DNS or HTTP to attacker-controlled server; effective even when entity values aren't reflected.",
            ))

        if _XXE_DOCTYPE_RE.search(body) and not _XXE_EXTERNAL_ENTITY_RE.search(body):
            findings.append(self._result(
                url, "xxe_doctype_present", "WARN",
                detail="DOCTYPE declaration with internal subset [ — even without external entities, an internal DTD with recursive entity expansion can cause billion laughs (exponential entity expansion DoS).",
            ))

        if _XXE_ERROR_DISCLOSURE_RE.search(body):
            findings.append(self._result(
                url, "xxe_xml_error_disclosure", "WARN",
                detail="XML parser error message in response (SAXParseException, XMLSyntaxError, ExpatError) — reveals XML parser type and version, enabling targeted XXE payload selection; attackers submit malformed XML to probe parser behavior.",
            ))

        if _XXE_SERVER_SIDE_INCLUDE_RE.search(body):
            findings.append(self._result(
                url, "xxe_server_side_include", "WARN",
                detail="SSI directive (<!--#include -->, <!--#exec -->) in response — Server-Side Includes processed by Apache/Nginx can execute OS commands or read files; often overlooked alongside XXE in XML contexts.",
            ))

        if _XXE_DOM_PARSE_UNSAFE_RE.search(body):
            findings.append(self._result(
                url, "xxe_dom_parser_from_param", "FAIL",
                detail="DOMParser.parseFromString() called with URL parameter or user input — client-side XML parsing of attacker-controlled XML; while XXE in browsers is limited, SVG/XML injection can execute scripts.",
            ))

        return findings or [self._result(url, "xxe_advanced_safe", "PASS")]
