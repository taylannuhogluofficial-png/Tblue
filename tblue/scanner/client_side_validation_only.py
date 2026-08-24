"""Client-Side Validation Only scanner — detects HTML5 validation without server-side checks."""
import re
from .base import BaseScanner

_CSV_ANY_RE = re.compile(
    r'(?:required\s*(?:>|/?>|\s+\w)|minlength\s*=|maxlength\s*=|'
    r'pattern\s*=\s*["\']|type=["\'](?:email|number|tel|url|date)["\']|'
    r'<form\b|novalidate\b|\.setCustomValidity|checkValidity\s*\(|'
    r'reportValidity\s*\()',
    re.I,
)

_CSV_HTML5_REQUIRED_RE = re.compile(
    r'<input[^>]{0,300}required(?:\s|>|/)',
    re.I | re.S,
)

_CSV_MINLENGTH_RE = re.compile(
    r'<input[^>]{0,300}minlength\s*=\s*["\']?\d+',
    re.I | re.S,
)

_CSV_PATTERN_RE = re.compile(
    r'<input[^>]{0,300}pattern\s*=\s*["\'][^"\']{1,200}["\']',
    re.I | re.S,
)

_CSV_TYPE_CONSTRAINT_RE = re.compile(
    r'<input[^>]{0,300}type=["\'](?:email|number|tel|url|date|range)["\']',
    re.I | re.S,
)

_CSV_NOVALIDATE_RE = re.compile(
    r'<form[^>]{0,200}novalidate(?:\s|>)',
    re.I | re.S,
)

_CSV_SERVER_VALIDATION_RE = re.compile(
    r'(?:\.validate\s*\(|Validator\.|validator\.|validate_email|'
    r'is_valid\s*\(\)|form\.is_valid|request\.validate|'
    r'sanitize\s*\(|filter_var\s*\(|preg_match\s*\(|'
    r'zod\.|joi\.|yup\.|express-validator|class-validator|'
    r'@IsEmail|@MinLength|@MaxLength|@IsNotEmpty|@Matches)',
    re.I,
)


class ClientSideValidationOnlyScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "client_side_validation_not_used", "PASS")]

        body = resp.text

        if not _CSV_ANY_RE.search(body):
            return [self._result(url, "client_side_validation_not_used", "PASS")]

        findings = []

        has_required = bool(_CSV_HTML5_REQUIRED_RE.search(body))
        has_minlength = bool(_CSV_MINLENGTH_RE.search(body))
        has_pattern = bool(_CSV_PATTERN_RE.search(body))
        has_type_constraint = bool(_CSV_TYPE_CONSTRAINT_RE.search(body))
        has_novalidate = bool(_CSV_NOVALIDATE_RE.search(body))
        has_server_validation = bool(_CSV_SERVER_VALIDATION_RE.search(body))

        if has_required and not has_server_validation:
            findings.append(self._result(
                url, "client_side_validation_required_only", "WARN",
                detail="HTML5 'required' attribute on input fields but no server-side validation code detected — HTML validation is trivially bypassed by removing the attribute in DevTools, sending a raw HTTP request with curl, or using a proxy to intercept and modify the request; all required fields can be submitted empty.",
            ))

        if has_minlength and not has_server_validation:
            findings.append(self._result(
                url, "client_side_validation_minlength_only", "WARN",
                detail="HTML5 minlength constraint on input but no server-side length validation detected — attacker sends POST request directly without browser; minlength is client-side hint only; single-character passwords, empty usernames, and truncated values accepted by the server.",
            ))

        if has_pattern and not has_server_validation:
            findings.append(self._result(
                url, "client_side_validation_pattern_only", "WARN",
                detail="HTML5 pattern= regex constraint on input but no server-side pattern validation detected — pattern attribute enforced only by browser UI; direct HTTP requests bypass regex entirely; format constraints (email, phone, ZIP, date) can be violated server-side.",
            ))

        if has_type_constraint and not has_server_validation:
            findings.append(self._result(
                url, "client_side_validation_type_only", "INFO",
                detail="HTML5 type=email/number/tel/url/date input constraint without server-side type validation — browser enforces type format in UI only; server must independently parse and validate input type; malformed values (NaN, arbitrary strings for number fields) reach server logic unchecked.",
            ))

        if has_novalidate:
            findings.append(self._result(
                url, "client_side_validation_novalidate_form", "FAIL",
                detail="<form novalidate> disables all HTML5 browser validation — even the minimal client-side validation is explicitly disabled; form submits without any constraint enforcement; if no server-side validation exists, all input constraints are completely absent.",
            ))

        return findings or [self._result(url, "client_side_validation_ok", "PASS")]
