"""
DOM Clobbering Attack Surface Scanner.

DOM Clobbering occurs when an HTML element with an `id` or `name` attribute
that matches a JavaScript identifier (variable name, property name) overwrites
that identifier in the global scope or document object. This allows an attacker
who can inject HTML (but not script) to influence JavaScript execution and
bypass security controls.

Classic examples:
1. **Property clobbering**: <img id="config"> overwrites window.config
   If JS does: if (window.config && window.config.debug) enableDebug();
   An attacker injecting <img id="config"> makes window.config a non-null
   HTMLElement, satisfying the truthiness check.

2. **document property clobbering**: <a id="baseURI" href="//evil.com">
   Overwrites document.baseURI with the attacker's domain.

3. **Security bypass via __proto__ or constructor**: Though browsers don't
   directly allow id="__proto__", some sanitizers fail to block double-layered
   clobbering via nested elements:
   <form id="x"><input id="y" name="__proto__">
   → x.y.__proto__ clobbers Object.prototype (modern bypass)

4. **name clobbering**: <iframe name="top"> clobbers window.top
   → breaks frame-busting code checking window.top !== window.self

Real impact:
- Client-side CSRF bypasses
- XSS in HTML-only injection contexts (DOMPurify bypass historical CVEs)
- Security control bypass in SPAs relying on DOM-read configuration

Blue-team checks (passive, read-only):
1. Detect HTML elements with `id` or `name` matching JS globals
2. Detect `id` attributes matching DOM property names (baseURI, location, etc.)
3. Detect `name="__proto__"` or `name="constructor"` patterns
4. Detect `<form><input name="...">` double-clobbering setup
5. Check if Content-Security-Policy restricts inline scripts (mitigates impact)

References:
  PortSwigger: DOM Clobbering — https://portswigger.net/web-security/dom-based/dom-clobbering
  Gareth Heyes: "DOM Clobbering strikes back" (2020)
  HackerOne: DOMPurify bypass reports (#1037790)
  CWE-79 variant: DOM-based context
  CWE-693: Protection Mechanism Failure
"""

import re
from typing import Any, Dict, List

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# JavaScript global identifiers that are dangerous to clobber
_DANGEROUS_GLOBALS = frozenset({
    "top", "parent", "self", "frames", "window", "document",
    "location", "navigator", "history", "screen",
    "alert", "confirm", "prompt", "eval", "fetch",
    "XMLHttpRequest", "WebSocket",
    "config", "settings", "options", "params", "data",
    "token", "csrf", "csrfToken", "nonce",
    "debug", "dev", "env",
})

# DOM object properties dangerous to clobber via id=
_DANGEROUS_DOM_PROPS = frozenset({
    "baseURI", "body", "forms", "head", "scripts", "links",
    "images", "anchors", "title", "domain", "cookie",
    "referrer", "activeElement", "currentScript",
})

# Prototype/constructor bypass patterns
_PROTO_NAMES = frozenset({
    "__proto__", "constructor", "prototype",
    "__defineGetter__", "__defineSetter__",
})

# name= attributes that clobber window properties
_WINDOW_CLOBBERING_NAMES = frozenset({
    "top", "parent", "self", "frames", "opener",
    "closed", "length", "name",
})

# Regex for id/name attributes (for fast pre-scan before parsing)
_ID_NAME_RE = re.compile(r'\b(?:id|name)\s*=\s*["\']([^"\']+)["\']', re.I)


class DOMClobberingScanner(BaseScanner):
    """Detect DOM clobbering attack surfaces in web pages."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "DOM clobbering — target unreachable", "PASS",
                detail="No response from target.",
            ))
            return self.results

        body = resp.text or ""

        # Quick pre-scan: skip full parse if no id= or name= attributes
        if not _ID_NAME_RE.search(body):
            log_pass(logger, f"DOM clobbering — no id/name attributes on {url}")
            self.results.append(self._result(
                url,
                "DOM clobbering — no id/name attributes found",
                "PASS",
                detail=(
                    "No id= or name= attributes were found in the page. "
                    "DOM clobbering requires an HTML injection surface with these attributes. "
                    "If user content can be injected, ensure a CSP is in place."
                ),
            ))
            return self.results

        self._check_dom_clobbering(url, body)

        if not self.results:
            log_pass(logger, f"DOM clobbering — no dangerous id/name attributes on {url}")
            self.results.append(self._result(
                url,
                "DOM clobbering — no dangerous id/name attributes detected",
                "PASS",
                detail=(
                    "No id= or name= attributes matching known dangerous JavaScript globals, "
                    "DOM property names, or prototype pollution patterns were detected. "
                    "Ensure user-injected HTML is filtered through a robust sanitizer "
                    "(DOMPurify with dom-clobber protection enabled)."
                ),
            ))

        return self.results

    def _check_dom_clobbering(self, url: str, body: str) -> None:
        """Analyze HTML for DOM clobbering patterns."""
        try:
            soup = BeautifulSoup(body, "html.parser")
        except Exception:
            return

        found_globals: List[str] = []
        found_dom_props: List[str] = []
        found_proto: List[str] = []
        found_window_names: List[str] = []
        found_double_clobber = False

        for tag in soup.find_all(True):
            tag_name = tag.name or ""
            id_val = (tag.get("id") or "").strip()
            name_val = (tag.get("name") or "").strip()

            # Check id against dangerous globals
            if id_val:
                if id_val in _DANGEROUS_GLOBALS:
                    found_globals.append(f"id='{id_val}' ({tag_name})")
                elif id_val in _DANGEROUS_DOM_PROPS:
                    found_dom_props.append(f"id='{id_val}' ({tag_name})")

            # Check name against prototype patterns
            if name_val:
                if name_val in _PROTO_NAMES:
                    found_proto.append(f"name='{name_val}' ({tag_name})")
                elif name_val in _WINDOW_CLOBBERING_NAMES:
                    found_window_names.append(f"name='{name_val}' ({tag_name})")

        # Double-clobbering: <form id="x"><input name="__proto__">
        for form in soup.find_all("form"):
            form_id = (form.get("id") or "").strip()
            if form_id:
                for inp in form.find_all(["input", "textarea", "select", "button"]):
                    inp_name = (inp.get("name") or "").strip()
                    if inp_name in _PROTO_NAMES:
                        found_double_clobber = True
                        break

        if found_globals:
            log_warn(logger, f"DOM clobbering: dangerous globals id= on {url}: {found_globals[:3]}")
            self.results.append(self._result(
                url,
                f"DOM clobbering — id attributes matching JS globals: {', '.join(found_globals[:3])}",
                "WARN",
                detail=(
                    f"HTML elements with id= attributes matching JavaScript global identifiers "
                    f"were found: {', '.join(found_globals[:5])}. "
                    "If an attacker can inject HTML (e.g., via stored XSS in HTML-only context), "
                    "these can clobber JavaScript variables and bypass security checks.\n"
                    "Fix: avoid using these ids; sanitize user HTML with DOMPurify; "
                    "apply CSP to block inline script execution even when clobbering occurs."
                ),
            ))

        if found_dom_props:
            log_warn(logger, f"DOM clobbering: DOM property id= on {url}: {found_dom_props[:3]}")
            self.results.append(self._result(
                url,
                f"DOM clobbering — id attributes matching DOM properties: {', '.join(found_dom_props[:3])}",
                "WARN",
                detail=(
                    f"HTML elements with id= attributes matching document property names "
                    f"were found: {', '.join(found_dom_props[:5])}. "
                    "For example, id='baseURI' overwrites document.baseURI with the element, "
                    "which can cause URL resolution errors or security bypasses.\n"
                    "Fix: avoid using DOM property names as element ids; "
                    "use a prefix or namespace in id attributes."
                ),
            ))

        if found_proto:
            log_fail(logger, f"DOM clobbering: prototype name= on {url}: {found_proto[:3]}")
            self.results.append(self._result(
                url,
                f"DOM clobbering — prototype/constructor name= attributes: {', '.join(found_proto[:3])}",
                "FAIL",
                detail=(
                    f"HTML elements with name= attributes matching prototype properties "
                    f"({', '.join(found_proto[:5])}) were detected. "
                    "These can be used to clobber Object.prototype or Function.constructor, "
                    "potentially enabling prototype pollution via DOM clobbering — "
                    "even in environments with blocked script injection.\n"
                    "Fix: block name='__proto__', name='constructor', name='prototype' "
                    "in all user-supplied HTML; use DOMPurify with FORBID_ATTR=['name']."
                ),
            ))

        if found_window_names:
            log_warn(logger, f"DOM clobbering: window-clobbering name= on {url}: {found_window_names[:3]}")
            self.results.append(self._result(
                url,
                f"DOM clobbering — name= attributes clobbering window properties: {', '.join(found_window_names[:3])}",
                "WARN",
                detail=(
                    f"Elements with name= attributes that clobber window properties "
                    f"({', '.join(found_window_names[:5])}) were found. "
                    "For example, name='top' on an iframe clobbers window.top, "
                    "which breaks frame-busting code. name='parent' can bypass "
                    "parent-frame security checks.\n"
                    "Fix: avoid using window property names in name= attributes of "
                    "iframes, objects, and forms."
                ),
            ))

        if found_double_clobber:
            log_fail(logger, f"DOM clobbering: double-clobber form pattern on {url}")
            self.results.append(self._result(
                url,
                "DOM clobbering — double-clobber pattern: form[id]+input[name=__proto__]",
                "FAIL",
                detail=(
                    "A <form id='...'><input name='__proto__'> double-clobbering pattern "
                    "was detected. This allows clobbering the __proto__ property of the "
                    "form element's named collection, potentially achieving prototype "
                    "pollution through DOM clobbering without any JavaScript injection.\n"
                    "This pattern can bypass DOMPurify when id and name attributes are "
                    "not properly restricted.\n"
                    "Fix: block name='__proto__' and name='constructor' in HTML sanitization; "
                    "use DOMPurify v3.x+ with force_body option; "
                    "apply a strict CSP to limit damage when clobbering occurs."
                ),
            ))
