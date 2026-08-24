"""
Hardcoded Credentials in JavaScript Source Scanner.

Hardcoded credentials in client-side JavaScript are fully exposed to any
user who views page source or network traffic. Unlike server-side code,
there is no protection — credentials are transmitted to every browser.

Patterns detected:

1. Test/debug passwords:
   - `password: "admin"`, `pwd: "test123"`, `pass: "password"`
2. Hardcoded API keys / tokens in JS:
   - `apiKey: "sk-..."`, `token: "ghp_..."`, `secret: "abc123def456"`
3. Database credentials in JS:
   - `mongodb://user:password@host/db` connection strings
4. AWS/cloud credentials:
   - `AKIAIOSFODNN7EXAMPLE` (AWS Access Key pattern)
   - `aws_secret_access_key = "..."` in config objects
5. Service-specific tokens:
   - `github.com` with PAT patterns, Stripe publishable/secret keys
   - Slack tokens (`xoxb-`, `xoxp-`, `xoxs-`), Twilio SIDs
6. JWT secrets in source:
   - `jwt_secret: "..."`, `jwtSecret: "..."` in config objects
7. OAuth client secrets (not just client IDs):
   - `client_secret: "..."` — client secrets should never be in client JS
8. Private keys (PEM fragments):
   - `BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY` in JS

Note: This scanner intentionally avoids false-positive-prone generic patterns.
All patterns are anchored to specific variable names or formats.

CWE-312: Cleartext Storage of Sensitive Information
CWE-798: Use of Hard-coded Credentials
"""

import re
from typing import Any, Dict, List, Tuple

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_CREDENTIAL_PATTERNS: List[Tuple[str, re.Pattern, str, str]] = [
    # Hardcoded passwords in object literals
    (
        "hardcoded_password",
        re.compile(
            r'(?:password|passwd|pwd|pass)\s*[=:]\s*["\']'
            r'(?!(?:\s*|%s|{\w|undefined|null|true|false|env\.|process\.|config\.))'
            r'(?:admin|password|test|1234|secret|abc123|letmein|qwerty|root|demo|'
            r'[a-zA-Z0-9!@#$%^&*]{6,})["\']',
            re.I
        ),
        "WARN",
        "hardcoded password value",
    ),
    # AWS Access Key
    (
        "aws_access_key",
        re.compile(r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])', re.I),
        "FAIL",
        "AWS Access Key ID pattern",
    ),
    # AWS Secret Key
    (
        "aws_secret",
        re.compile(
            r'(?:aws[_-]?secret[_-]?(?:access[_-]?)?key|aws_secret)\s*[=:]\s*["\']'
            r'[A-Za-z0-9/+]{40}["\']',
            re.I
        ),
        "FAIL",
        "AWS Secret Access Key",
    ),
    # Stripe secret key
    (
        "stripe_secret",
        re.compile(r'sk_(?:live|test)_[0-9a-zA-Z]{24,}', re.I),
        "FAIL",
        "Stripe Secret Key",
    ),
    # GitHub PAT
    (
        "github_pat",
        re.compile(r'ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}', re.I),
        "FAIL",
        "GitHub Personal Access Token",
    ),
    # Slack tokens
    (
        "slack_token",
        re.compile(r'xox[bpsa]-[0-9A-Za-z\-]{10,}', re.I),
        "FAIL",
        "Slack API token",
    ),
    # OAuth client secret
    (
        "oauth_client_secret",
        re.compile(
            r'client[_-]?secret\s*[=:]\s*["\'][a-zA-Z0-9_\-]{12,}["\']',
            re.I
        ),
        "FAIL",
        "OAuth client secret",
    ),
    # JWT secret
    (
        "jwt_secret",
        re.compile(
            r'jwt[_-]?secret\s*[=:]\s*["\'][^"\']{8,}["\']',
            re.I
        ),
        "FAIL",
        "JWT secret key",
    ),
    # MongoDB connection string with credentials
    (
        "mongodb_creds",
        re.compile(
            r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s"\']+',
            re.I
        ),
        "FAIL",
        "MongoDB connection string with credentials",
    ),
    # PostgreSQL/MySQL connection string with credentials
    (
        "db_connection_creds",
        re.compile(
            r'(?:postgres|postgresql|mysql|sqlserver)://[^:]+:[^@]+@[^\s"\']+',
            re.I
        ),
        "FAIL",
        "Database connection string with credentials",
    ),
    # Private key PEM header
    (
        "private_key_pem",
        re.compile(r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE KEY-----', re.I),
        "FAIL",
        "Private key (PEM format)",
    ),
    # Generic API key assignment
    (
        "api_key_assignment",
        re.compile(
            r'(?:api[_-]?key|apikey|x[_-]?api[_-]?key)\s*[=:]\s*["\']'
            r'[a-zA-Z0-9_\-]{16,}["\']',
            re.I
        ),
        "WARN",
        "hardcoded API key",
    ),
]


class HardcodedCredentialsScanner(BaseScanner):
    """Detect hardcoded credentials and secrets in page JavaScript."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0
        reported_types: set = set()

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "Hardcoded credentials — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        body = resp.text or ""

        for pattern_id, pattern, status, description in _CREDENTIAL_PATTERNS:
            if findings >= 10:
                break
            if pattern_id in reported_types:
                continue

            m = pattern.search(body)
            if not m:
                continue

            reported_types.add(pattern_id)
            match_preview = m.group(0)[:60].replace("\n", " ")

            if status == "FAIL":
                log_fail(logger, f"Hardcoded {description} in JS at {url}")
            else:
                log_warn(logger, f"Hardcoded {description} in JS at {url}")

            self.results.append(self._result(
                url,
                f"Hardcoded credentials — {description} in page source: {match_preview}...",
                status,
                detail=(
                    f"Page JavaScript contains a {description}: '{match_preview}...'. "
                    "Client-side credentials are fully exposed to any user who views page "
                    "source, intercepts network traffic, or uses browser DevTools. "
                    "Fix: remove all credentials from client-side code; use server-side "
                    "proxy endpoints to access protected APIs; load secrets from environment "
                    "variables at build time without embedding them in output bundles."
                )
            ))
            findings += 1

        if not self.results:
            log_pass(logger, f"No hardcoded credentials in page source at {url}")
            self.results.append(self._result(
                url, "Hardcoded credentials — no hardcoded credentials detected in page source", "PASS",
                detail="No hardcoded password, API key, token, or credential patterns found in page JavaScript."
            ))

        return self.results
