"""srcdoc injection — iframe srcdoc with user-controlled data, javascript: URL iframes, data: URL iframes."""
import re
from .base import BaseScanner

_SRCDOC_RE = re.compile(r'<iframe\b[^>]*\bsrcdoc\s*=\s*["\']', re.I | re.S)
_SRCDOC_WITH_SCRIPT_RE = re.compile(
    r'<iframe\b[^>]*\bsrcdoc\s*=\s*["\'][^"\']*<script\b',
    re.I | re.S,
)
_SRCDOC_FROM_PARAM_RE = re.compile(
    r'(?:\.setAttribute\s*\(\s*["\']srcdoc["\']\s*,\s*|\.srcdoc\s*=\s*)'
    r'[^;]*(?:location\.|URLSearchParams|getParam|searchParams|document\.referrer)',
    re.I,
)
_JAVASCRIPT_SRC_RE = re.compile(
    r'<iframe\b[^>]*\bsrc\s*=\s*["\']javascript:',
    re.I,
)
_DATA_URL_IFRAME_RE = re.compile(
    r'<iframe\b[^>]*\bsrc\s*=\s*["\']data:text/html',
    re.I,
)
_DYNAMIC_SRCDOC_RE = re.compile(
    r'(?:createElement\s*\(\s*["\']iframe["\']|new\s+HTMLIFrameElement\s*\(\s*\))'
    r'[^;]{0,200}\.srcdoc\s*=',
    re.I | re.S,
)
_BLOB_IFRAME_RE = re.compile(
    r'<iframe\b[^>]*\bsrc\s*=\s*["\']blob:|'
    r'\.src\s*=\s*URL\.createObjectURL',
    re.I,
)

_SANDBOX_RE = re.compile(r'\bsandbox\b', re.I)


class SrcdocInjectionScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "srcdoc_injection_no_response", "PASS",
                                 detail="No response")]

        body = resp.text or ""

        if _JAVASCRIPT_SRC_RE.search(body):
            results.append(self._result(url, "srcdoc_javascript_src", "FAIL",
                                        detail="<iframe src=\"javascript:...\"> detected — "
                                               "javascript: URL iframes execute script in parent page context"))

        if _DATA_URL_IFRAME_RE.search(body):
            results.append(self._result(url, "srcdoc_data_url_iframe", "WARN",
                                        detail="<iframe src=\"data:text/html,...\"> detected — "
                                               "data: URL iframes may execute arbitrary HTML/script; "
                                               "modern browsers sandbox but some older versions don't"))

        if _SRCDOC_WITH_SCRIPT_RE.search(body):
            results.append(self._result(url, "srcdoc_with_script_tag", "FAIL",
                                        detail="<iframe srcdoc=\"...<script>...\"> with embedded script detected — "
                                               "if srcdoc value includes user-controlled content, script executes in iframe origin"))

        elif _SRCDOC_RE.search(body):
            m = _SRCDOC_RE.search(body)
            tag = m.group(0) if m else ""
            if not _SANDBOX_RE.search(tag):
                results.append(self._result(url, "srcdoc_without_sandbox", "WARN",
                                            detail="<iframe srcdoc=\"...\"> without sandbox attribute — "
                                                   "srcdoc content runs in null origin without sandbox, "
                                                   "allowing scripts if CSP permits"))

        if _SRCDOC_FROM_PARAM_RE.search(body):
            results.append(self._result(url, "srcdoc_from_url_param", "FAIL",
                                        detail="iframe.srcdoc assigned from URL parameter/location — "
                                               "attacker controls iframe content via URL manipulation"))

        if _DYNAMIC_SRCDOC_RE.search(body):
            results.append(self._result(url, "srcdoc_dynamic_creation", "WARN",
                                        detail="Dynamically created iframe with .srcdoc assignment — "
                                               "verify srcdoc value is not user-controlled"))

        if _BLOB_IFRAME_RE.search(body):
            results.append(self._result(url, "srcdoc_blob_iframe", "WARN",
                                        detail="iframe src set to blob: URL or createObjectURL — "
                                               "blob URLs can load arbitrary HTML; verify content is trusted"))

        if not results:
            results.append(self._result(url, "srcdoc_injection_clean", "PASS",
                                        detail="No srcdoc injection or dangerous iframe patterns detected"))
        return results
