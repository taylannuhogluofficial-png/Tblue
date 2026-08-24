"""
BroadcastChannel Security Scanner.

The BroadcastChannel API allows same-origin tabs/workers to communicate.
Security issues arise when:

  1. Message listener lacks origin check — BroadcastChannel messages are
     always same-origin by spec, but JS code that also handles postMessage
     via the same listener without checking event.origin creates confusion.

  2. Channel name is predictable — if the channel name is a constant string
     (e.g., "updates", "auth"), other same-origin pages (including XSS
     payloads) can subscribe and receive or inject messages.

  3. Sensitive data broadcast — messages containing tokens, session IDs,
     or PII broadcast over a named channel can be intercepted by any
     same-origin page that happens to be open.

  4. BroadcastChannel used for authentication state — auth state (logged-in,
     logged-out, token refresh) communicated via BroadcastChannel is
     detectable and injectable by XSS in any same-origin page.

This scanner statically analyzes JS for BroadcastChannel usage patterns.

Read-only.

CWE-200: Exposure of Sensitive Information
CWE-346: Origin Validation Error
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_BC_NEW_RE = re.compile(
    r'new\s+BroadcastChannel\s*\(\s*["\']([^"\']+)["\']\s*\)', re.I
)
_BC_POST_RE = re.compile(
    r'\.postMessage\s*\(\s*\{[^}]*(?:token|session|auth|key|secret|password)[^}]*\}',
    re.I
)
_BC_ONMESSAGE_RE = re.compile(
    r'\.onmessage\s*=|addEventListener\s*\(\s*["\']message["\']', re.I
)
_ORIGIN_CHECK_RE = re.compile(
    r'event\.origin|e\.origin|msg\.origin', re.I
)

_AUTH_CHANNEL_NAMES = {"auth", "authentication", "session", "token", "login", "logout", "user"}

_JS_PATHS = ["/", "/js/app.js", "/static/js/main.js", "/assets/js/app.js",
             "/bundle.js", "/main.js", "/app.js"]


def _scan_body(body: str, url: str) -> List[Dict]:
    findings = []
    if not body:
        return findings

    channels = _BC_NEW_RE.findall(body)
    if not channels:
        return findings

    for ch_name in channels:
        if ch_name.lower() in _AUTH_CHANNEL_NAMES:
            findings.append({
                "type": f"broadcast-channel-auth-state-on-channel-{ch_name[:40]}",
                "status": "WARN",
                "detail": (
                    f"BroadcastChannel with sensitive name {ch_name!r} found at {url}.\n\n"
                    f"Authentication or session state broadcast over a predictable channel "
                    f"name can be intercepted or injected by any XSS payload in any "
                    f"same-origin page.\n\n"
                    f"Fix: if auth state must be synced across tabs, use a randomly "
                    f"generated channel name per session, or use storage events instead."
                ),
            })

    # Check if postMessage sends sensitive data
    if _BC_POST_RE.search(body):
        findings.append({
            "type": "broadcast-channel-sensitive-data-in-postmessage",
            "status": "WARN",
            "detail": (
                f"BroadcastChannel.postMessage call at {url} appears to broadcast "
                f"an object containing sensitive field names (token, session, auth, key, etc.).\n\n"
                f"Any same-origin page with a BroadcastChannel listener on the same "
                f"channel name can receive this data, including XSS payloads.\n\n"
                f"Fix: do not broadcast sensitive values. Use secure cookie-based "
                f"or server-side session synchronization instead."
            ),
        })

    # Message handler without origin check (likely mixed with postMessage)
    if _BC_ONMESSAGE_RE.search(body) and not _ORIGIN_CHECK_RE.search(body):
        findings.append({
            "type": "broadcast-channel-message-handler-no-origin-check",
            "status": "WARN",
            "detail": (
                f"Message event handler at {url} lacks an event.origin check.\n\n"
                f"While BroadcastChannel is same-origin by spec, JS that registers "
                f"a generic onmessage handler may also receive window.postMessage "
                f"events from cross-origin frames. Without origin validation, "
                f"injected messages may be processed.\n\n"
                f"Fix: always check event.origin in message handlers and ignore "
                f"events from unexpected origins."
            ),
        })

    return findings


class BroadcastChannelSecurityScanner(BaseScanner):
    """Checks JS for risky BroadcastChannel usage: auth channels, sensitive payloads."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        found = False
        seen_types: set = set()

        endpoints = [url] + [urljoin(base_origin, p) for p in _JS_PATHS if p != "/"]

        for ep in endpoints:
            resp = self.http.get(ep)
            if resp is None or resp.status_code not in (200, 206):
                continue
            body = resp.text or ""
            for f in _scan_body(body, ep):
                if f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    found = True
                    log_warn(logger, f"BroadcastChannel Security — {f['type']} at {ep}")
                    self.results.append(self._result(
                        ep, f["type"][:100], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"BroadcastChannel Security — no risky usage found for {url}")
            self.results.append(self._result(
                url,
                "BroadcastChannel Security — no risky BroadcastChannel patterns detected",
                "PASS",
                detail="No auth-named channels, sensitive payloads, or missing origin checks found.",
            ))

        return self.results
