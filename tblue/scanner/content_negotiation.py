"""
Content Negotiation Security Scanner.

HTTP content negotiation (Accept: header) can create security issues when
servers:

  1. Reflect Accept header in Content-Type without sanitization — if a server
     echoes back whatever Content-Type was in the Accept header, an attacker
     can cause the browser to render a response as text/html, application/json
     in dangerous ways (e.g. JSON interpreted as HTML by old browsers).

  2. Serve different responses to different Accept values — this is expected,
     but when the difference is security-relevant (e.g. WAF bypass via
     Accept: application/x-www-form-urlencoded), it's a vulnerability.

  3. Type confusion via Accept: text/html on API endpoints — some APIs that
     return JSON will wrap it in an HTML <pre> if the browser asks for HTML.
     If the JSON contains user-controlled content, this is XSS.

  4. JSONP via Accept callback detection — some APIs respond to
     Accept: application/javascript with a JSONP-wrapped response.

  5. Large Accept header DoS potential — many servers crash or log-overflow
     on Accept values exceeding 8KB.

Read-only. Benign probes only — we analyze the Content-Type response, not
the content for XSS payloads.

CWE-116: Improper Encoding or Escaping of Output
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v1/users",
    "/api/v2",
    "/graphql",
    "/data",
    "/rest",
]


def _get_ct(resp) -> str:
    if resp is None:
        return ""
    ct = resp.headers.get("content-type", "")
    return ct.split(";")[0].strip().lower()


def _probe_accept(http, url: str, accept: str) -> Optional[object]:
    return http.get(url, headers={"Accept": accept})


def _check_accept_reflection(http, url: str) -> Optional[Dict]:
    """Check if server reflects back a custom Accept value as Content-Type."""
    fake_type = "application/x-tbl9z7x-probe"
    resp = _probe_accept(http, url, fake_type)
    if resp is None:
        return None
    ct = _get_ct(resp)
    if fake_type in ct:
        return {
            "type": "content-negotiation-accept-reflected",
            "status": "WARN",
            "detail": (
                f"Server at {url} reflected the Accept header value '{fake_type}' "
                f"as the Content-Type response header.\n\n"
                f"Reflecting arbitrary Accept values as Content-Type can confuse browsers "
                f"and enable MIME sniffing attacks. If an attacker can control the Accept "
                f"header (e.g. via a proxy or JS Fetch), they may force dangerous content "
                f"type interpretations.\n\n"
                f"Fix: set a fixed, correct Content-Type for each endpoint regardless of "
                f"the Accept request header value."
            ),
        }
    return None


def _check_json_rendered_as_html(http, url: str) -> Optional[Dict]:
    """Check if a JSON API endpoint wraps output in HTML when asked for text/html."""
    resp_json = _probe_accept(http, url, "application/json")
    if resp_json is None or resp_json.status_code not in (200, 201):
        return None
    ct_json = _get_ct(resp_json)
    if "json" not in ct_json:
        return None

    resp_html = _probe_accept(http, url, "text/html")
    if resp_html is None:
        return None
    ct_html = _get_ct(resp_html)
    body = (resp_html.text or "")[:4096]

    if "html" in ct_html and ("<html" in body.lower() or "<body" in body.lower()):
        return {
            "type": "content-negotiation-json-wrapped-in-html",
            "status": "WARN",
            "detail": (
                f"JSON API endpoint {url} returns text/html with HTML wrapper when "
                f"client sends Accept: text/html.\n\n"
                f"If the JSON response contains user-controlled data, wrapping it in an "
                f"HTML page may result in XSS. Browsers requesting an API URL directly "
                f"(e.g. in address bar) send Accept: text/html by default.\n\n"
                f"Fix: always return Content-Type: application/json for API endpoints "
                f"regardless of the Accept header."
            ),
        }
    return None


def _check_jsonp_via_accept(http, url: str) -> Optional[Dict]:
    """Check if endpoint returns JSONP when Accept: application/javascript."""
    resp = _probe_accept(http, url, "application/javascript")
    if resp is None or resp.status_code not in (200, 201):
        return None
    ct = _get_ct(resp)
    body = (resp.text or "")[:2048]
    if "javascript" in ct and re.search(r'\w+\s*\(', body):
        return {
            "type": "content-negotiation-jsonp-accepted",
            "status": "WARN",
            "detail": (
                f"Endpoint {url} returns application/javascript with what appears to be "
                f"a function call — possible JSONP response.\n\n"
                f"JSONP bypasses CORS and can leak sensitive data to any cross-origin page "
                f"that includes the endpoint as a script src.\n\n"
                f"Fix: use CORS headers instead of JSONP. If JSONP is needed, validate "
                f"the callback parameter strictly against an alphanumeric allowlist."
            ),
        }
    return None


class ContentNegotiationScanner(BaseScanner):
    """Checks for Accept header reflection, JSON-as-HTML, and JSONP responses."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Content Negotiation — target unreachable", "PASS",
                detail="No response; content negotiation check skipped."))
            return self.results

        parsed      = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        found       = False

        # Check root + API endpoints
        endpoints = [url] + [base_origin + p for p in _API_PATHS]

        for ep_url in endpoints:
            # Accept reflection
            f = _check_accept_reflection(self.http, ep_url)
            if f:
                found = True
                log_warn(logger, f"Content Negotiation — {f['type']} at {ep_url}")
                self.results.append(self._result(
                    ep_url, f["type"], f["status"], detail=f["detail"]))

            # JSON rendered as HTML
            f = _check_json_rendered_as_html(self.http, ep_url)
            if f:
                found = True
                log_warn(logger, f"Content Negotiation — {f['type']} at {ep_url}")
                self.results.append(self._result(
                    ep_url, f["type"], f["status"], detail=f["detail"]))

            # JSONP
            f = _check_jsonp_via_accept(self.http, ep_url)
            if f:
                found = True
                log_warn(logger, f"Content Negotiation — {f['type']} at {ep_url}")
                self.results.append(self._result(
                    ep_url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"Content Negotiation — no issues found for {url}")
            self.results.append(self._result(
                url,
                "Content Negotiation — no Accept header security issues found",
                "PASS",
                detail="No Accept reflection, JSON-as-HTML, or JSONP patterns detected.",
            ))

        return self.results
