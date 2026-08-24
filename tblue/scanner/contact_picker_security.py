"""Contact Picker API security scanner — mass contact exfiltration, multiple property selection."""
import re
from .base import BaseScanner

_CP_SELECT_RE = re.compile(r'navigator\.contacts\.select\s*\(', re.I)
_CP_ANY_RE    = re.compile(r'navigator\.contacts\b', re.I)

# All contact properties requested (mass data grab)
_CP_ALL_PROPS_RE = re.compile(
    r'navigator\.contacts\.select\s*\([^)]*\[[^\]]*(?:name|email|tel|address|icon)[^\]]*,[^\]]*(?:name|email|tel|address|icon)',
    re.I | re.S
)

# Contact data transmitted to remote
_CP_SEND_RE = re.compile(
    r'(?:contacts|contact)\b[^;]{0,200}(?:fetch|XMLHttpRequest|sendBeacon)', re.I | re.S
)

# Contact data sent to analytics/third party
_CP_ANALYTICS_RE = re.compile(
    r'(?:gtag|analytics|fbq|mixpanel)[^;]{0,200}(?:contact|email|tel|address)', re.I | re.S
)

# Multiple = true — selects all contacts in phonebook
_CP_MULTIPLE_RE = re.compile(r'multiple\s*:\s*true', re.I)

# Contact data stored locally (XSS accessible)
_CP_STORED_RE = re.compile(
    r'(?:localStorage|sessionStorage|IndexedDB)[^;]{0,100}(?:contact|email|tel)',
    re.I | re.S
)


class ContactPickerSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "contact_picker_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _CP_ANY_RE.search(body):
            return [self._result(url, "contact_picker_not_used", "INFO",
                                 detail="Contact Picker API not detected")]

        results = []

        if _CP_ALL_PROPS_RE.search(body):
            results.append(self._result(url, "contact_picker_all_properties", "WARN",
                                        detail="Multiple contact properties requested — requesting name+email+tel+address constitutes mass contact grab"))

        if _CP_MULTIPLE_RE.search(body):
            results.append(self._result(url, "contact_picker_multiple_contacts", "WARN",
                                        detail="multiple:true allows selecting all contacts — full phonebook access"))

        if _CP_SEND_RE.search(body):
            results.append(self._result(url, "contact_picker_data_transmitted", "FAIL",
                                        detail="Contact data transmitted to remote endpoint — personal information exfiltration"))

        if _CP_ANALYTICS_RE.search(body):
            results.append(self._result(url, "contact_picker_data_to_analytics", "FAIL",
                                        detail="Contact email/phone/address passed to analytics — third-party PII exfiltration"))

        if _CP_STORED_RE.search(body):
            results.append(self._result(url, "contact_picker_data_stored_insecure", "WARN",
                                        detail="Contact data stored in localStorage/IndexedDB — XSS-accessible PII store"))

        if not results:
            results.append(self._result(url, "contact_picker_found_no_issues", "PASS",
                                        detail="Contact Picker API usage appears safe"))

        return results
