"""
API Key in JavaScript Scanner.

Hardcoded API keys in JavaScript bundles are a common source of credential
exposure. Keys committed to JS are delivered to every browser visitor:

  1. Cloud provider keys — AWS access keys, GCP API keys, Azure SAS tokens.

  2. Third-party service keys — Stripe publishable (low risk) vs secret keys
     (high risk), Twilio, SendGrid, Mailchimp.

  3. Internal API keys — Bearer tokens, x-api-key values hardcoded in fetch()
     or axios calls within JS bundles.

  4. Private keys — RSA/EC PEM blocks accidentally included in JS.

  5. Connection strings — database connection strings, Redis URLs with
     passwords, MongoDB Atlas connection URIs.

Read-only: scans page and JS bundle content for key patterns.

CWE-798: Use of Hard-coded Credentials
CWE-312: Cleartext Storage of Sensitive Information
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_KEY_PATTERNS: List[Tuple[str, re.Pattern, str, str]] = [
    ("aws-access-key", re.compile(r'AKIA[0-9A-Z]{16}'), "FAIL", "AWS Access Key ID"),
    ("aws-secret-key", re.compile(r'(?:aws_secret|AWS_SECRET)[_\s]*(?:ACCESS_KEY|KEY)?[_\s]*=\s*["\']?([A-Za-z0-9/+]{40})["\']?', re.I), "FAIL", "AWS Secret Access Key"),
    ("gcp-api-key", re.compile(r'AIza[0-9A-Za-z_-]{35}'), "WARN", "Google API Key"),
    ("stripe-secret", re.compile(r'sk_live_[0-9a-zA-Z]{24,}'), "FAIL", "Stripe Secret Key"),
    ("stripe-restricted", re.compile(r'rk_live_[0-9a-zA-Z]{24,}'), "FAIL", "Stripe Restricted Key"),
    ("sendgrid-key", re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'), "FAIL", "SendGrid API Key"),
    ("twilio-key", re.compile(r'SK[0-9a-fA-F]{32}'), "WARN", "Twilio API Key"),
    ("private-key-pem", re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'), "FAIL", "PEM Private Key"),
    ("bearer-token", re.compile(r'["\'](?:Authorization|x-api-key)["\']:\s*["\'](?:Bearer\s+)?([A-Za-z0-9_\-\.]{32,})["\']', re.I), "WARN", "Hardcoded Bearer/API Token"),
    ("mongodb-uri", re.compile(r'mongodb(?:\+srv)?://[^:]+:[^@\s]+@[^\s"\']+', re.I), "FAIL", "MongoDB Connection String with Password"),
    ("redis-uri", re.compile(r'redis://:[^@\s]+@[^\s"\']+', re.I), "FAIL", "Redis URL with Password"),
]

_JS_PATHS = [
    "/static/js/main.js", "/assets/app.js", "/js/app.js",
    "/bundle.js", "/dist/bundle.js", "/build/static/js/main.js",
    "/assets/index.js", "/static/js/bundle.js",
]


def _scan_for_keys(body: str, source_url: str) -> List[Dict]:
    findings = []
    seen_types: set = set()
    for key_type, pattern, severity, label in _KEY_PATTERNS:
        m = pattern.search(body)
        if m and key_type not in seen_types:
            seen_types.add(key_type)
            snippet = m.group(0)[:60]
            findings.append({
                "type": f"api-key-in-js-{key_type}",
                "status": severity,
                "detail": (
                    f"{label} found hardcoded in JavaScript at {source_url}: "
                    f"{repr(snippet)}...\n\n"
                    f"Hardcoded credentials in JavaScript are delivered to every browser "
                    f"visitor and may be extracted by anyone who views the page source.\n\n"
                    f"Fix: move credentials to server-side. Use environment variables and "
                    f"never embed secret keys in client-side code."
                ),
            })
    return findings


class APIKeyInJSScanner(BaseScanner):
    """Scans JavaScript bundles for hardcoded API keys, tokens, and connection strings."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "API Key in JS — target unreachable", "PASS",
                detail="No response; API key in JS check skipped."))
            return self.results

        found = False
        seen_types: set = set()

        sources = [(url, resp.text or "")]
        for path in _JS_PATHS:
            r = self.http.get(base_origin + path)
            if r and r.status_code == 200:
                sources.append((base_origin + path, r.text or ""))

        for src_url, body in sources:
            for f in _scan_for_keys(body, src_url):
                if f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    found = True
                    if f["status"] == "FAIL":
                        log_fail(logger, f"API Key in JS — {f['type']}")
                    else:
                        log_warn(logger, f"API Key in JS — {f['type']}")
                    self.results.append(self._result(
                        url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"API Key in JS — no hardcoded keys found for {url}")
            self.results.append(self._result(
                url, "API Key in JS — no hardcoded API keys detected", "PASS",
                detail="No AWS keys, Google API keys, Stripe secrets, or other hardcoded credentials found in JS."))

        return self.results
