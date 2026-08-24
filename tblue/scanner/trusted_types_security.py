"""Trusted Types API security scanner — policy bypass, dangerous sinks, policy override."""
import re
from .base import BaseScanner

_TT_ANY_RE = re.compile(
    r'(?:trustedTypes\b|TrustedTypePolicy\b|createPolicy\s*\(|TrustedHTML\b|TrustedScript\b)',
    re.I
)

# createPolicy callback just returns the input unchanged — no sanitization
_TT_PASSTHROUGH_RE = re.compile(
    r'createPolicy\s*\([^)]*\)\s*,\s*\{[^}]*createHTML\s*:\s*(?:s|str|input|val|v|html|data)\s*=>\s*(?:s|str|input|val|v|html|data)\s*[},]',
    re.I | re.S
)

# createPolicy named 'default' — overrides browser enforcement globally
_TT_DEFAULT_POLICY_RE = re.compile(
    r'createPolicy\s*\(\s*["\']default["\']',
    re.I
)

# innerHTML/outerHTML/document.write assigned with raw string (not a TrustedHTML object)
_TT_BYPASS_SINK_RE = re.compile(
    r'(?:innerHTML|outerHTML|document\.write)\s*=\s*(?!.*\btrustPolicy\b)(?!.*\bcreateHTML\b)(?!.*\bTrustedHTML\b)[^;]{0,200}(?:location\.|searchParams|document\.referrer|window\.name)',
    re.I | re.S
)

# eval/Function constructor used despite Trusted Types enforcement
_TT_EVAL_BYPASS_RE = re.compile(
    r'(?:trustedTypes|createPolicy)[^;]{0,400}(?:eval\s*\(|new\s+Function\s*\()',
    re.I | re.S
)

# Policy created that allows arbitrary scripts via createScript passthrough
_TT_SCRIPT_PASSTHROUGH_RE = re.compile(
    r'createPolicy\s*\([^)]*\)\s*,\s*\{[^}]*createScript\s*:\s*(?:s|str|input|val|v|script|data)\s*=>\s*(?:s|str|input|val|v|script|data)\s*[},]',
    re.I | re.S
)


class TrustedTypesSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "trusted_types_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _TT_ANY_RE.search(body):
            return [self._result(url, "trusted_types_not_used", "INFO",
                                 detail="Trusted Types API not detected")]

        results = []

        if _TT_DEFAULT_POLICY_RE.search(body):
            results.append(self._result(url, "trusted_types_default_policy_override", "FAIL",
                                        detail="createPolicy('default') overrides browser TT enforcement globally — attacker can forge trusted values"))

        if _TT_PASSTHROUGH_RE.search(body):
            results.append(self._result(url, "trusted_types_html_passthrough", "FAIL",
                                        detail="TrustedTypes createHTML policy returns input unchanged — sanitization bypassed"))

        if _TT_SCRIPT_PASSTHROUGH_RE.search(body):
            results.append(self._result(url, "trusted_types_script_passthrough", "FAIL",
                                        detail="TrustedTypes createScript policy returns input unchanged — arbitrary script execution enabled"))

        if _TT_BYPASS_SINK_RE.search(body):
            results.append(self._result(url, "trusted_types_sink_bypass", "WARN",
                                        detail="innerHTML/outerHTML/document.write assigned from URL parameter without TrustedHTML wrapper"))

        if _TT_EVAL_BYPASS_RE.search(body):
            results.append(self._result(url, "trusted_types_eval_bypass", "WARN",
                                        detail="eval/Function constructor used alongside Trusted Types — may bypass policy enforcement"))

        if not results:
            results.append(self._result(url, "trusted_types_found_no_issues", "PASS",
                                        detail="Trusted Types API usage appears safe"))

        return results
