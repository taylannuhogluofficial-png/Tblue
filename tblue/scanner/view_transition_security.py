"""View Transition API security scanner — snapshot capture, cross-document content leakage."""
import re
from .base import BaseScanner

_VT_ANY_RE = re.compile(
    r'(?:document\.startViewTransition\b|ViewTransition\b|view-transition\b|::view-transition)',
    re.I
)

# Transition captures sensitive content (password field, auth area) in screenshot snapshot
_VT_SENSITIVE_CAPTURE_RE = re.compile(
    r'startViewTransition[^;]{0,400}(?:password|token|secret|auth|creditCard|ssn|cvv)',
    re.I | re.S
)

# Transition name derived from URL parameter — attacker controls which element is captured
_VT_NAME_FROM_PARAM_RE = re.compile(
    r'(?:viewTransitionName|view-transition-name)[^;]{0,200}(?:searchParams|getParam|location\.search|location\.hash)',
    re.I | re.S
)

# Cross-document view transition captures cross-origin content
_VT_CROSS_DOC_RE = re.compile(
    r'startViewTransition[^;]{0,300}(?:cross-document|crossDocument|@view-transition)',
    re.I | re.S
)

# Transition callback reads DOM and transmits to analytics
_VT_SNAPSHOT_EXFIL_RE = re.compile(
    r'startViewTransition\s*\([^;]{0,400}(?:fetch|sendBeacon|XMLHttpRequest|toDataURL|toBlob)',
    re.I | re.S
)

# view-transition-name applied to sensitive element from URL parameter
_VT_ELEMENT_HIJACK_RE = re.compile(
    r'style\.setProperty\s*\([^)]*view-transition-name[^)]*(?:searchParams|getParam)',
    re.I
)


class ViewTransitionSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "view_transition_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _VT_ANY_RE.search(body):
            return [self._result(url, "view_transition_not_used", "INFO",
                                 detail="View Transition API not detected")]

        results = []

        if _VT_SENSITIVE_CAPTURE_RE.search(body):
            results.append(self._result(url, "view_transition_captures_sensitive_content", "WARN",
                                        detail="startViewTransition callback references sensitive data (password/token/auth) — sensitive content may be captured in transition snapshot"))

        if _VT_NAME_FROM_PARAM_RE.search(body):
            results.append(self._result(url, "view_transition_name_from_url_param", "WARN",
                                        detail="view-transition-name derived from URL parameter — attacker controls which element is selected for transition capture"))

        if _VT_ELEMENT_HIJACK_RE.search(body):
            results.append(self._result(url, "view_transition_element_hijack", "WARN",
                                        detail="view-transition-name CSS property set from URL parameter — attacker can force specific elements to be captured in transition"))

        if _VT_SNAPSHOT_EXFIL_RE.search(body):
            results.append(self._result(url, "view_transition_snapshot_exfiltrated", "FAIL",
                                        detail="startViewTransition callback transmits data or canvas snapshot to remote — page visual snapshot potentially exfiltrated"))

        if _VT_CROSS_DOC_RE.search(body):
            results.append(self._result(url, "view_transition_cross_document", "WARN",
                                        detail="Cross-document view transition detected — transition may capture content from a different page during navigation"))

        if not results:
            results.append(self._result(url, "view_transition_found_no_issues", "PASS",
                                        detail="View Transition API usage appears safe"))

        return results
