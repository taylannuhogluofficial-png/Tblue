"""
Webhook Security Scanner.

Webhook endpoints receive HTTP POST requests from external services (GitHub,
Stripe, Twilio, etc.) and trigger internal actions. Security issues:

1. Webhook endpoint accessible without signature validation:
   - Responds 200/204 to GET (should return 405 — webhooks are POST-only)
   - No indication of signature verification in response (no 400/401 on bad request)
   - Missing typical webhook security headers in responses
2. Webhook endpoint at predictable/guessable path — easy to discover and probe
3. HTTP (non-TLS) webhook URLs — webhook payload sent in cleartext
4. Webhook debug/test interface exposed (Svix, Hookdeck, Ngrok dashboards)
5. Webhook replay replay protection absent — no timestamp/nonce validation evident
6. Webhook receiver echoes back payload or webhook ID in response body

All checks are passive — we only send HTTP GET requests and inspect responses.
No test POST payloads are sent.

CWE-306: Missing Authentication for Critical Function
CWE-284: Improper Access Control
"""

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_WEBHOOK_PATHS: List[Tuple[str, str]] = [
    ("/webhook",                "Generic webhook endpoint"),
    ("/webhooks",               "Generic webhook endpoint"),
    ("/webhook/",               "Generic webhook endpoint"),
    ("/hooks",                  "GitHub-style hooks endpoint"),
    ("/hook",                   "Hook endpoint"),
    ("/api/webhook",            "API webhook endpoint"),
    ("/api/webhooks",           "API webhook endpoint"),
    ("/api/v1/webhook",         "API v1 webhook endpoint"),
    ("/api/v2/webhook",         "API v2 webhook endpoint"),
    ("/callback",               "OAuth/webhook callback"),
    ("/callbacks",              "OAuth/webhook callback"),
    ("/notify",                 "Notification callback endpoint"),
    ("/events",                 "Event receiver endpoint"),
    ("/event",                  "Event receiver endpoint"),
    ("/stripe/webhook",         "Stripe webhook receiver"),
    ("/stripe/webhooks",        "Stripe webhook receiver"),
    ("/github/webhook",         "GitHub webhook receiver"),
    ("/github/webhooks",        "GitHub webhook receiver"),
    ("/twilio/webhook",         "Twilio webhook receiver"),
    ("/sendgrid/webhook",       "SendGrid event webhook"),
]

_WEBHOOK_DEBUG_PATHS: List[str] = [
    "/webhooks/debug",
    "/webhook/test",
    "/webhook/ping",
    "/hooks/debug",
    "/__webhooks",
    "/svix",
    "/hookdeck",
]

_PAYLOAD_ECHO_RE = re.compile(
    r'"(?:event|payload|body|data|webhook_id|delivery_id|x-hub-signature)"\s*:',
    re.I
)
_NGROK_RE = re.compile(r'ngrok|tunnel|hookdeck|svix-playground|webhook\.site', re.I)
_WEBHOOK_BODY_RE = re.compile(
    r'(?:webhook|hook)\s+(?:received|accepted|processed|delivered)',
    re.I
)


class WebhookSecurityScanner(BaseScanner):
    """Passively detect insecure webhook endpoint configurations."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed = urlparse(url)

        if parsed.scheme == "http":
            log_warn(logger, f"Webhook security scan on HTTP target: {url}")
            self.results.append(self._result(
                url, "Webhook security — target is HTTP (not HTTPS)", "WARN",
                detail=(
                    "The target URL uses HTTP, not HTTPS. Any webhook endpoints on this "
                    "host will receive webhook payloads in cleartext, exposing event data "
                    "and potentially HMAC secrets. Fix: enforce HTTPS for all webhook endpoints."
                )
            ))

        base = f"{parsed.scheme}://{parsed.netloc}"
        findings = 0

        for path, label in _WEBHOOK_PATHS:
            if findings >= 5:
                break

            probe_url = base + path
            try:
                resp = self.http.get(probe_url)
            except Exception:
                continue

            if resp is None:
                continue

            if resp.status_code in (200, 204):
                body = resp.text or ""
                ct = resp.headers.get("content-type", "").lower()

                if _NGROK_RE.search(body):
                    log_warn(logger, f"Webhook debug interface at {probe_url}")
                    self.results.append(self._result(
                        probe_url,
                        f"Webhook security — debug/tunnel interface exposed: {path}",
                        "WARN",
                        detail=(
                            f"GET {path} returned 200 with webhook debug/tunnel content. "
                            "Webhook inspection tools (ngrok, hookdeck, svix) should not be "
                            "accessible from the public internet. "
                            "Fix: remove or restrict access to webhook debug tooling."
                        )
                    ))
                    findings += 1
                    continue

                if _PAYLOAD_ECHO_RE.search(body):
                    log_fail(logger, f"Webhook echoes payload at {probe_url}")
                    self.results.append(self._result(
                        probe_url,
                        f"Webhook security — endpoint echoes webhook data on GET: {path}",
                        "FAIL",
                        detail=(
                            f"GET {path} returns 200 and echoes webhook payload fields in "
                            "the response body. Webhook endpoints should not accept GET "
                            "requests and should never echo event data. "
                            "Fix: return 405 Method Not Allowed for GET; process only "
                            "authenticated POST requests."
                        )
                    ))
                    findings += 1
                    continue

                if _WEBHOOK_BODY_RE.search(body):
                    log_warn(logger, f"Webhook endpoint accessible via GET at {probe_url}")
                    self.results.append(self._result(
                        probe_url,
                        f"Webhook security — {label} responds 200 to GET: {path}",
                        "WARN",
                        detail=(
                            f"GET {path} returns HTTP {resp.status_code}. Webhook receivers "
                            "should return 405 Method Not Allowed for GET requests. "
                            "Accepting GET may indicate missing method restriction, making "
                            "it easier for attackers to discover and probe the endpoint. "
                            "Fix: restrict webhook paths to POST method only."
                        )
                    ))
                    findings += 1
                    continue

                if "application/json" in ct and len(body) > 50:
                    log_warn(logger, f"Webhook JSON at {probe_url} on GET")
                    self.results.append(self._result(
                        probe_url,
                        f"Webhook security — {label} returns JSON on GET: {path}",
                        "WARN",
                        detail=(
                            f"GET {path} returns JSON with status 200. Webhook receivers "
                            "should not serve data on GET — only accept POST. "
                            "Fix: return 405 for GET requests to webhook paths."
                        )
                    ))
                    findings += 1

        for path in _WEBHOOK_DEBUG_PATHS:
            if findings >= 8:
                break
            probe_url = base + path
            try:
                resp = self.http.get(probe_url)
            except Exception:
                continue
            if resp is None:
                continue
            if resp.status_code == 200:
                log_warn(logger, f"Webhook debug path exposed at {probe_url}")
                self.results.append(self._result(
                    probe_url,
                    f"Webhook security — debug/test endpoint exposed: {path}",
                    "WARN",
                    detail=(
                        f"Webhook debug/test path {path} returns HTTP 200. "
                        "Debug webhook interfaces should not be accessible in production. "
                        "Fix: disable or restrict access to webhook debug/test endpoints."
                    )
                ))
                findings += 1

        if not self.results:
            log_pass(logger, f"No webhook security issues found at {url}")
            self.results.append(self._result(
                url, "Webhook security — no exposed webhook endpoints detected", "PASS",
                detail=(
                    "Common webhook paths are not accessible via GET, and no debug "
                    "webhook interfaces were found."
                )
            ))

        return self.results
