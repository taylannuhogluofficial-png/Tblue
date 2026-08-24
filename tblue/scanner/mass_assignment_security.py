"""Mass Assignment security scanner — detection of unrestricted object property assignment from user input."""
import re
from .base import BaseScanner

_MA_ANY_RE = re.compile(
    r'(?:Object\.assign\s*\(|'
    r'\.\.\.(?:req|body|params|data|input)\b|'
    r'\.\.\.\s*JSON\.parse\s*\(|'
    r'Object\.keys\s*\([^)]{0,100}\.forEach|'
    r'for\s*\([^)]{0,100}in\s+(?:req|body|data|input))',
    re.I,
)

_MA_SPREAD_FROM_PARAM_RE = re.compile(
    r'\.\.\.\s*(?:searchParams|JSON\.parse\s*\([^)]{0,100}(?:location|param|input)|'
    r'req\.body|req\.params|req\.query)',
    re.I,
)

_MA_ASSIGN_ALL_PROPS_RE = re.compile(
    r'Object\.assign\s*\(\s*(?:this|self|model|user|account)\b[^;]{0,200}'
    r'(?:req\.body|req\.params|searchParams|JSON\.parse)',
    re.I,
)

_MA_FOR_IN_ASSIGN_RE = re.compile(
    r'for\s*\([^)]{0,50}in\s+(?:req\.body|req\.params|userInput|params)\b[^;]{0,300}'
    r'(?:this|self|model|target)\s*\[',
    re.I,
)

_MA_ROLE_ESCALATION_RE = re.compile(
    r'(?:role|isAdmin|permissions?|privilege)\b[^;]{0,200}'
    r'(?:req\.body|searchParams|JSON\.parse)',
    re.I,
)


class MassAssignmentSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "mass_assignment_not_used", "PASS")]

        body = resp.text
        if not _MA_ANY_RE.search(body):
            return [self._result(url, "mass_assignment_not_used", "PASS")]

        findings = []

        if _MA_SPREAD_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "mass_assignment_spread_from_param", "FAIL",
                detail="...spread of URL parameter/req.body/JSON.parse — all user-supplied properties assigned without allowlist; attacker may set role, isAdmin, or internal fields.",
            ))

        if _MA_ASSIGN_ALL_PROPS_RE.search(body):
            findings.append(self._result(
                url, "mass_assignment_object_assign_model", "FAIL",
                detail="Object.assign(this/model/user, req.body/searchParams) — entire user-controlled object merged into model without field filtering; classic mass assignment vulnerability.",
            ))

        if _MA_FOR_IN_ASSIGN_RE.search(body):
            findings.append(self._result(
                url, "mass_assignment_for_in_loop", "WARN",
                detail="for...in loop over req.body/userInput assigns to this[key] — unrestricted property iteration allows injecting arbitrary model fields.",
            ))

        if _MA_ROLE_ESCALATION_RE.search(body):
            findings.append(self._result(
                url, "mass_assignment_role_escalation", "FAIL",
                detail="role/isAdmin/permissions value derived from req.body/searchParams — privilege escalation via mass assignment if sensitive field not excluded from user input.",
            ))

        return findings or [self._result(url, "mass_assignment_safe", "PASS")]
