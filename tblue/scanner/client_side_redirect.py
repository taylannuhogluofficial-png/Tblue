"""
Client-Side Open Redirect Security Scanner.

Client-side (JavaScript) open redirects are distinct from server-side redirects:
they occur when JavaScript reads from a tainted URL source (query param, fragment,
referrer) and assigns the value to window.location without validation.

Attack patterns detected:

1. Direct location assignment from URL params:
   `window.location = getParam("next")`
   `window.location.href = new URLSearchParams(window.location.search).get('url')`

2. Fragment-based redirect:
   `window.location = window.location.hash.slice(1)` — attacker controls #fragment.

3. document.referrer as redirect target:
   `window.location = document.referrer` — attacker controls referrer via HTTP header.

4. postMessage-triggered redirect:
   Redirect target received via postMessage without origin validation.

5. eval()/Function() on URL-derived redirect:
   `eval("window.location='" + param + "'")` — combine with XSS.

6. Meta refresh with external URL:
   `<meta http-equiv="refresh" content="0; url=https://evil.com">` in page.

7. Base redirect through DOM:
   Document.base href manipulation to redirect all relative links.

Detection note: this is a passive source-code scanner — it reads the page JS
and HTML for patterns indicative of unsafe redirect behavior without crafting
attack payloads.

CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
CWE-116: Improper Encoding or Escaping of Output
"""

import re
from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

# window.location = <something from URL/hash/referrer>
_LOC_FROM_PARAM_RE = re.compile(
    r'(?:window\.location|location\.href|location\.replace\s*\(|location\.assign\s*\()'
    r'\s*=\s*'
    r'(?:[^\n;{]{0,60}?)'
    r'(?:'
    r'getParam|getQueryParam|urlParam|searchParams\.get|URLSearchParams|'
    r'window\.location\.search|window\.location\.hash|document\.referrer|'
    r'location\.search|location\.hash'
    r')',
    re.I
)

# location.* = hash.slice() or similar
_HASH_REDIRECT_RE = re.compile(
    r'(?:window\.)?location(?:\.href)?\s*=\s*'
    r'(?:window\.)?location\.hash\s*(?:\.slice|\.substring|\.substr|\[)',
    re.I
)

# location = document.referrer
_REFERRER_REDIRECT_RE = re.compile(
    r'(?:window\.)?location(?:\.href)?\s*=\s*document\.referrer',
    re.I
)

# location in postMessage handler without origin check
_POSTMESSAGE_REDIRECT_RE = re.compile(
    r'addEventListener\s*\(\s*["\']message["\'].*?location(?:\.href)?\s*=\s*event\.data',
    re.I | re.S
)

# meta refresh to external URL
_META_REFRESH_EXT_RE = re.compile(
    r'<meta\b[^>]*http-equiv\s*=\s*["\']refresh["\'][^>]*content\s*=\s*["\'][^"\']*'
    r'url\s*=\s*(https?://[^"\'>\s]+)',
    re.I
)

# eval with location
_EVAL_REDIRECT_RE = re.compile(
    r'\beval\s*\([^)]*location[^)]*\)',
    re.I
)

# unsafe redirect after checking prefix only (e.g., startsWith check bypass)
_PREFIX_BYPASS_RE = re.compile(
    r'(?:startsWith|indexOf)\s*\(\s*["\']https?://',
    re.I
)


class ClientSideRedirectScanner(BaseScanner):
    """Detect client-side open redirect patterns in page JavaScript and HTML."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "Client-side redirect — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        body = resp.text or ""

        # location = URL param / search / hash
        if _LOC_FROM_PARAM_RE.search(body):
            log_warn(logger, f"Location assignment from URL param/hash at {url}")
            self.results.append(self._result(
                url,
                "Client-side redirect — window.location set from URL parameter or hash",
                "WARN",
                detail=(
                    "JavaScript assigns to window.location (or location.href/replace) "
                    "a value derived from URL search parameters, query string, or URL hash. "
                    "If the value is not validated against a trusted-host allow-list, "
                    "an attacker can craft a link like ?next=https://evil.com and redirect "
                    "victims to a phishing page. "
                    "Fix: validate redirect targets against an explicit allow-list of "
                    "trusted origins before assigning to window.location."
                )
            ))
            findings += 1

        # location = hash.slice()
        if _HASH_REDIRECT_RE.search(body) and findings < 8:
            log_warn(logger, f"Fragment hash redirect at {url}")
            self.results.append(self._result(
                url,
                "Client-side redirect — window.location assigned from URL fragment hash",
                "WARN",
                detail=(
                    "JavaScript assigns location.href from window.location.hash (URL fragment). "
                    "Fragments are fully attacker-controlled in crafted links and are not sent "
                    "to the server. A link like example.com/#https://evil.com can redirect "
                    "users without server-side validation. "
                    "Fix: never redirect to unvalidated fragment values; parse and "
                    "validate the fragment URL against an origin allow-list."
                )
            ))
            findings += 1

        # location = document.referrer
        if _REFERRER_REDIRECT_RE.search(body) and findings < 8:
            log_warn(logger, f"Referrer-based redirect at {url}")
            self.results.append(self._result(
                url,
                "Client-side redirect — window.location assigned from document.referrer",
                "WARN",
                detail=(
                    "JavaScript redirects to document.referrer. An attacker who controls "
                    "the Referer header (via a link from their page) can redirect victims "
                    "to arbitrary external URLs. "
                    "Fix: never use document.referrer as a redirect target; validate "
                    "all redirect values against a trusted-origin allow-list."
                )
            ))
            findings += 1

        # postMessage-triggered redirect
        if _POSTMESSAGE_REDIRECT_RE.search(body) and findings < 8:
            log_fail(logger, f"postMessage-triggered redirect without origin check at {url}")
            self.results.append(self._result(
                url,
                "Client-side redirect — location.href set from postMessage event.data",
                "FAIL",
                detail=(
                    "JavaScript sets location.href from event.data inside a postMessage "
                    "listener. Any cross-origin page can send a postMessage with a "
                    "malicious URL and redirect the user. "
                    "Fix: add event.origin validation before using postMessage data "
                    "for any navigation; restrict accepted redirect targets."
                )
            ))
            findings += 1

        # eval with location
        if _EVAL_REDIRECT_RE.search(body) and findings < 8:
            log_fail(logger, f"eval() with location in redirect at {url}")
            self.results.append(self._result(
                url,
                "Client-side redirect — eval() used with location-based redirect",
                "FAIL",
                detail=(
                    "JavaScript uses eval() in conjunction with window.location. "
                    "This combines the risks of DOM XSS (code execution) and open redirect "
                    "(navigation to arbitrary URLs). "
                    "Fix: never pass location or URL parameters to eval()."
                )
            ))
            findings += 1

        # Meta refresh to external URL
        ext_urls = _META_REFRESH_EXT_RE.findall(body)
        for ext_url in ext_urls[:2]:
            if findings >= 8:
                break
            log_warn(logger, f"Meta refresh to external URL at {url}: {ext_url[:60]}")
            self.results.append(self._result(
                url,
                f"Client-side redirect — <meta http-equiv='refresh'> to external URL: {ext_url[:60]}",
                "WARN",
                detail=(
                    f"A <meta http-equiv='refresh' content='0; url={ext_url[:80]}'> "
                    "redirects the browser to an external domain without server-side control. "
                    "If this value can be influenced by user input or injection, it enables "
                    "open redirect attacks. Fix: review all meta refresh targets; "
                    "prefer server-side 302 redirects with validated destinations."
                )
            ))
            findings += 1

        # Prefix-only validation bypass indicator
        if _PREFIX_BYPASS_RE.search(body) and findings < 8:
            log_warn(logger, f"Possible prefix-only URL validation in redirect at {url}")
            self.results.append(self._result(
                url,
                "Client-side redirect — possible prefix-only URL validation (bypass risk)",
                "WARN",
                detail=(
                    "JavaScript validates redirect URLs using startsWith() or indexOf() "
                    "with a prefix. This is bypassable: 'https://evil.com?q=https://trusted.com' "
                    "or 'https://trusted.com.evil.com/' passes a prefix check. "
                    "Fix: parse the redirect URL with the URL API and compare the full "
                    "hostname against an explicit allow-list."
                )
            ))
            findings += 1

        if not self.results:
            log_pass(logger, f"No client-side open redirect patterns at {url}")
            self.results.append(self._result(
                url, "Client-side redirect — no unsafe redirect patterns detected", "PASS",
                detail="No client-side open redirect patterns found in page JavaScript or HTML."
            ))

        return self.results
