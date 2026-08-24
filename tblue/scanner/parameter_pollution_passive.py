"""Parameter Pollution Passive scanner — passive detection of HTTP parameter pollution indicators."""
import re
from .base import BaseScanner

_PP_ANY_RE = re.compile(
    r'(?:req\.query|req\.params|searchParams|'
    r'getParameter|getParameterValues|'
    r'\[\s*0\s*\]|\[\s*-1\s*\]|\.pop\s*\(|\.shift\s*\()',
    re.I,
)

_PP_ARRAY_FROM_PARAM_RE = re.compile(
    r'(?:req\.query\.\w+\s*\[|searchParams\.getAll\s*\(|'
    r'getParameterValues\s*\([^)]{1,100}\))',
    re.I,
)

_PP_FIRST_VALUE_ONLY_RE = re.compile(
    r'(?:req\.query\.\w+|searchParams\.get\s*\([^)]{1,100}\))'
    r'[^;\n]{0,100}?\[\s*0\s*\]',
    re.I,
)

_PP_DUPLICATE_PARAM_IN_BODY_RE = re.compile(
    r'(?:\?|&)[a-zA-Z_][a-zA-Z0-9_]{0,50}=[^&\s]+&[^&\s]*[a-zA-Z_][a-zA-Z0-9_]{0,50}=[^&\s]+',
)

_PP_PHP_ARRAY_POLLUTION_RE = re.compile(
    r'\$_(?:GET|POST|REQUEST)\s*\[\s*["\'][^"\']{1,50}["\']'
    r'\s*\]\s*\[\s*',
    re.I,
)

_PP_OVERRIDE_IN_URL_RE = re.compile(
    r'[?&](?:_method|X-HTTP-Method-Override|X-Method-Override)\s*=',
    re.I,
)

_PP_BACKEND_PARAM_SPLIT_RE = re.compile(
    r'(?:split\s*\(\s*["\'],|explode\s*\(["\'],|'
    r'\.split\s*\(["\'],)[^)]{0,100}'
    r'(?:req\.query|searchParams|getParameter)',
    re.I,
)


class ParameterPollutionPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "parameter_pollution_not_used", "PASS")]

        body = resp.text
        if not _PP_ANY_RE.search(body) and not _PP_ANY_RE.search(url):
            return [self._result(url, "parameter_pollution_not_used", "PASS")]

        findings = []

        if _PP_FIRST_VALUE_ONLY_RE.search(body):
            findings.append(self._result(
                url, "parameter_pollution_first_value_only", "WARN",
                detail="Code takes only the first value [0] from a multi-value parameter — if front-end security check reads first value but back-end uses second value of a duplicated parameter, attacker injects malicious second value that bypasses the check.",
            ))

        if _PP_PHP_ARRAY_POLLUTION_RE.search(body):
            findings.append(self._result(
                url, "parameter_pollution_php_array", "WARN",
                detail="PHP superglobal array access with double bracket ($_GET['x'][...]) — PHP accepts param[] as array input; attacker sends param[0]=safe&param[1]=malicious to bypass string-level checks on first element.",
            ))

        if _PP_ARRAY_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "parameter_pollution_multi_value_param", "WARN",
                detail="getParameterValues() or searchParams.getAll() retrieves all values for a parameter — server explicitly handles multi-value parameters; confirm security checks apply to all values, not just first or last.",
            ))

        if _PP_OVERRIDE_IN_URL_RE.search(url) or _PP_OVERRIDE_IN_URL_RE.search(body):
            findings.append(self._result(
                url, "parameter_pollution_method_override", "WARN",
                detail="_method or X-HTTP-Method-Override parameter in URL or body — HTTP method tunneling via parameter; front-end firewall sees GET/POST but back-end processes DELETE/PUT, bypassing method-based WAF rules.",
            ))

        if _PP_BACKEND_PARAM_SPLIT_RE.search(body):
            findings.append(self._result(
                url, "parameter_pollution_backend_split", "WARN",
                detail="Backend splits a parameter value on a delimiter — attacker injects the delimiter character into a parameter to inject additional key=value pairs into the back-end request (HPP via comma/newline injection).",
            ))

        return findings or [self._result(url, "parameter_pollution_safe", "PASS")]
