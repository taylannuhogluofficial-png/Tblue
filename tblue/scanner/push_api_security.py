"""Push API security scanner — subscription endpoint exfiltration, missing VAPID, unencrypted payloads."""
import re
from .base import BaseScanner

_PUSH_SUBSCRIBE_RE  = re.compile(r'\.subscribe\s*\(\s*\{', re.I)
_PUSH_ANY_RE        = re.compile(r'(?:PushSubscription|pushManager|PushManager|pushsubscriptionchange)\b', re.I)

# Subscription endpoint sent to third party
_PUSH_ENDPOINT_THIRD_RE = re.compile(
    r'(?:endpoint|subscription)[^;]{0,200}(?:gtag|analytics|fbq|mixpanel|third.party)',
    re.I | re.S
)

# Missing applicationServerKey (VAPID) — unauthenticated subscriptions
_PUSH_NO_VAPID_RE   = re.compile(r'\.subscribe\s*\(\s*\{\s*userVisibleOnly', re.I)
_PUSH_VAPID_KEY_RE  = re.compile(r'applicationServerKey', re.I)

# Push data decrypted and logged
_PUSH_LOG_DATA_RE   = re.compile(
    r'event\.data[^;]{0,100}(?:console\.log|console\.warn|console\.error)', re.I | re.S
)

# Push handler sends data to remote (push amplification)
_PUSH_AMPLIFY_RE    = re.compile(
    r'(?:push|onsync)[^;]{0,300}event\.data[^;]{0,200}(?:fetch|XMLHttpRequest)', re.I | re.S
)

# userVisibleOnly: false — silent push (not allowed in Chrome, but still detectable)
_PUSH_SILENT_RE     = re.compile(r'userVisibleOnly\s*:\s*false', re.I)

# Subscription stored in localStorage (XSS accessible)
_PUSH_STORED_INSECURE_RE = re.compile(
    r'(?:localStorage|sessionStorage)[^;]{0,100}(?:endpoint|subscription)',
    re.I | re.S
)


class PushAPISecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "push_api_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _PUSH_ANY_RE.search(body):
            return [self._result(url, "push_api_not_used", "INFO",
                                 detail="Push API not detected")]

        results = []

        if _PUSH_SILENT_RE.search(body):
            results.append(self._result(url, "push_api_silent_push", "FAIL",
                                        detail="userVisibleOnly:false — silent push attempts bypass notification requirement"))

        if _PUSH_NO_VAPID_RE.search(body) and not _PUSH_VAPID_KEY_RE.search(body):
            results.append(self._result(url, "push_api_missing_vapid", "WARN",
                                        detail="Push subscription without applicationServerKey (VAPID) — unauthenticated subscription endpoint"))

        if _PUSH_ENDPOINT_THIRD_RE.search(body):
            results.append(self._result(url, "push_api_endpoint_to_third_party", "FAIL",
                                        detail="Push subscription endpoint shared with third-party analytics — enables targeted push tracking"))

        if _PUSH_LOG_DATA_RE.search(body):
            results.append(self._result(url, "push_api_data_logged", "WARN",
                                        detail="Push payload (event.data) logged to console — sensitive push content may leak in DevTools"))

        if _PUSH_AMPLIFY_RE.search(body):
            results.append(self._result(url, "push_api_amplification", "WARN",
                                        detail="Push handler makes outbound requests with payload — potential push-to-server amplification"))

        if _PUSH_STORED_INSECURE_RE.search(body):
            results.append(self._result(url, "push_api_subscription_in_localstorage", "WARN",
                                        detail="Push subscription stored in localStorage — XSS can steal subscription endpoint"))

        if not results:
            results.append(self._result(url, "push_api_found_no_issues", "PASS",
                                        detail="Push API usage appears safe"))

        return results
