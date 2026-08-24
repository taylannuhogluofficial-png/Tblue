"""JavaScript Prototype Chain scanner — passive detection of prototype chain manipulation and gadget exposure."""
import re
from .base import BaseScanner

_JPC_ANY_RE = re.compile(
    r'(?:__proto__|Object\.prototype|prototype\[|'
    r'hasOwnProperty|getPrototypeOf|setPrototypeOf)',
    re.I,
)

_JPC_PROTO_ASSIGN_RE = re.compile(
    r'__proto__\s*(?:\[|\s*=\s*\S|\.)',
    re.I,
)

_JPC_OBJ_PROTO_MODIFY_RE = re.compile(
    r'Object\.prototype\s*\.\s*\w+\s*=',
    re.I,
)

_JPC_BRACKET_PROTO_RE = re.compile(
    r'prototype\s*\[\s*(?:searchParams|location\.hash|userInput|req\.body)',
    re.I,
)

_JPC_SET_PROTOTYPE_OF_PARAM_RE = re.compile(
    r'Object\.setPrototypeOf\s*\([^,)]{0,100},\s*'
    r'(?:JSON\.parse\s*\(|searchParams|location\.hash)',
    re.I,
)

_JPC_HAS_OWN_BYPASS_RE = re.compile(
    r'hasOwnProperty\s*=\s*(?:function|=>|\bfalse\b)|'
    r'Object\.prototype\.hasOwnProperty\s*=',
    re.I,
)

_JPC_GETTER_SETTER_GADGET_RE = re.compile(
    r'Object\.defineProperty\s*\(\s*Object\.prototype',
    re.I,
)


class JavaScriptPrototypeChainScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "js_prototype_chain_not_used", "PASS")]

        body = resp.text
        if not _JPC_ANY_RE.search(body):
            return [self._result(url, "js_prototype_chain_not_used", "PASS")]

        findings = []

        if _JPC_PROTO_ASSIGN_RE.search(body):
            findings.append(self._result(
                url, "js_prototype_chain_proto_assign", "FAIL",
                detail="__proto__ assignment or bracket access detected — attacker-controlled __proto__ values poison all objects inheriting from Object.prototype, enabling property injection across the entire application.",
            ))

        if _JPC_OBJ_PROTO_MODIFY_RE.search(body):
            findings.append(self._result(
                url, "js_prototype_chain_object_proto_modify", "FAIL",
                detail="Object.prototype property assignment detected — extending Object.prototype affects every object in the runtime; attacker injection here propagates to all property lookups.",
            ))

        if _JPC_BRACKET_PROTO_RE.search(body):
            findings.append(self._result(
                url, "js_prototype_chain_bracket_from_param", "FAIL",
                detail="prototype[] bracket notation with URL parameter/userInput — attacker-controlled key written to prototype chain; classic prototype pollution via bracket notation.",
            ))

        if _JPC_SET_PROTOTYPE_OF_PARAM_RE.search(body):
            findings.append(self._result(
                url, "js_prototype_chain_set_prototype_of_param", "FAIL",
                detail="Object.setPrototypeOf() with JSON.parse or URL parameter as the prototype argument — attacker controls the prototype chain target, enabling full prototype poisoning.",
            ))

        if _JPC_HAS_OWN_BYPASS_RE.search(body):
            findings.append(self._result(
                url, "js_prototype_chain_hasownproperty_bypass", "WARN",
                detail="hasOwnProperty overridden or set to false — property existence checks are bypassed, allowing prototype-inherited attacker properties to pass hasOwnProperty guards.",
            ))

        if _JPC_GETTER_SETTER_GADGET_RE.search(body):
            findings.append(self._result(
                url, "js_prototype_chain_getter_setter_gadget", "FAIL",
                detail="Object.defineProperty on Object.prototype — defines getter/setter gadget on all objects; used in prototype pollution gadget chains to trigger code execution on innocent property access.",
            ))

        return findings or [self._result(url, "js_prototype_chain_safe", "PASS")]
