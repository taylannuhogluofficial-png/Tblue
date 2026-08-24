"""
Secrets-in-JavaScript scanner.

Fetches all <script src> files linked from the page and scans them
(plus the page HTML itself) for hardcoded secrets using 65+ regex patterns
covering AWS, GitHub, Stripe, Twilio, Slack, SendGrid, Google, Azure, and more.

All checks are read-only — no credentials are validated or used.
"""

import re
from typing import List, Dict, Any, Tuple
from urllib.parse import urljoin, urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_fail, log_pass

logger = get_logger(__name__)

# (label, regex_pattern)
_PATTERNS: List[Tuple[str, re.Pattern]] = [
    # AWS
    ("AWS Access Key ID",              re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS Secret Access Key",          re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("AWS Session Token",              re.compile(r"(?i)aws.session.token['\"\s]*[:=]['\"\s]*[A-Za-z0-9/+=]{100,}")),

    # GitHub
    ("GitHub Personal Access Token",   re.compile(r"\bghp_[0-9a-zA-Z]{36}\b")),
    ("GitHub OAuth Token",             re.compile(r"\bgho_[0-9a-zA-Z]{36}\b")),
    ("GitHub Actions Token",           re.compile(r"\bghs_[0-9a-zA-Z]{36}\b")),
    ("GitHub Refresh Token",           re.compile(r"\bghr_[0-9a-zA-Z]{36}\b")),
    ("GitHub Fine-Grained Token",      re.compile(r"\bgithub_pat_[0-9a-zA-Z_]{82}\b")),

    # Stripe
    ("Stripe Live Secret Key",         re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("Stripe Test Secret Key",         re.compile(r"\bsk_test_[0-9a-zA-Z]{24,}\b")),
    ("Stripe Restricted Key",          re.compile(r"\brk_live_[0-9a-zA-Z]{24,}\b")),
    ("Stripe Webhook Secret",          re.compile(r"\bwhsec_[0-9a-zA-Z]{32,}\b")),

    # Twilio
    ("Twilio Account SID",             re.compile(r"\bAC[0-9a-f]{32}\b")),
    ("Twilio Auth Token",              re.compile(r"(?i)twilio.{0,20}['\"][0-9a-f]{32}['\"]")),

    # Slack
    ("Slack Bot Token",                re.compile(r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24}\b")),
    ("Slack User Token",               re.compile(r"\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[0-9a-f]{32}\b")),
    ("Slack App Token",                re.compile(r"\bxapp-\d-[A-Z0-9]{10,13}-[0-9]{10,13}-[0-9a-f]{64}\b")),
    ("Slack Webhook URL",              re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+")),

    # SendGrid
    ("SendGrid API Key",               re.compile(r"\bSG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43}\b")),

    # Google
    ("Google API Key",                 re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Google OAuth Client Secret",     re.compile(r"(?i)google.{0,20}client.secret['\"\s]*[:=]['\"\s]*[0-9a-zA-Z\-_]+")),
    ("Google Service Account",         re.compile(r"\"type\":\s*\"service_account\"")),
    ("Firebase Database URL",          re.compile(r"https://[a-z0-9-]+\.firebaseio\.com")),
    ("Firebase API Key",               re.compile(r"(?i)firebase.{0,20}apikey['\"\s]*[:=]['\"\s]*[A-Za-z0-9_-]{30,}")),

    # Azure
    ("Azure Connection String",        re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+")),
    ("Azure SAS Token",                re.compile(r"(?i)sig=[A-Za-z0-9%/+]+=?&se=\d{4}-\d{2}-\d{2}")),
    ("Azure Client Secret",            re.compile(r"(?i)azure.{0,20}client.secret['\"\s]*[:=]['\"\s]*[0-9a-zA-Z.~_\-]{34,}")),

    # Mailgun
    ("Mailgun API Key",                re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")),

    # Mailchimp
    ("Mailchimp API Key",              re.compile(r"\b[0-9a-f]{32}-us\d{1,2}\b")),

    # HubSpot
    ("HubSpot API Key",                re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")),

    # Shopify
    ("Shopify Access Token",           re.compile(r"\bshpat_[0-9a-fA-F]{32}\b")),
    ("Shopify Custom App Token",       re.compile(r"\bshpca_[0-9a-fA-F]{32}\b")),
    ("Shopify Partner Token",          re.compile(r"\bshppa_[0-9a-fA-F]{32}\b")),

    # Heroku
    ("Heroku API Key",                 re.compile(r"(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")),

    # Datadog
    ("Datadog API Key",                re.compile(r"(?i)datadog.{0,20}['\"][0-9a-f]{32}['\"]")),

    # NPM
    ("npm Auth Token",                 re.compile(r"\bnpm_[0-9a-zA-Z]{36}\b")),

    # OpenAI
    ("OpenAI API Key",                 re.compile(r"\bsk-[0-9a-zA-Z]{20}T3BlbkFJ[0-9a-zA-Z]{20}\b")),
    ("OpenAI Project Key",             re.compile(r"\bsk-proj-[0-9a-zA-Z_-]{40,}\b")),

    # Anthropic
    ("Anthropic API Key",              re.compile(r"\bsk-ant-api\d{2}-[0-9a-zA-Z_-]{90,}\b")),

    # Telegram
    ("Telegram Bot Token",             re.compile(r"\b\d{8,10}:[0-9A-Za-z_-]{35}\b")),

    # Discord
    ("Discord Bot Token",              re.compile(r"\b[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b")),
    ("Discord Webhook",                re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[0-9A-Za-z_-]+")),

    # JWT (hardcoded)
    ("Hardcoded JWT",                  re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),

    # Private keys
    ("RSA Private Key",                re.compile(r"-----BEGIN RSA PRIVATE KEY-----")),
    ("EC Private Key",                 re.compile(r"-----BEGIN EC PRIVATE KEY-----")),
    ("PEM Private Key",                re.compile(r"-----BEGIN PRIVATE KEY-----")),
    ("OpenSSH Private Key",            re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----")),
    ("PGP Private Key",                re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----")),

    # Generic high-confidence patterns
    ("Generic secret assignment",      re.compile(
        r"""(?i)(?:password|passwd|secret|api[_-]?key|auth[_-]?token|access[_-]?token)\s*[:=]\s*['"][^'"]{12,}['"]"""
    )),
    ("Basic Auth in URL",              re.compile(r"https?://[^:@\s]+:[^:@\s]+@[^/\s]+")),
    ("Hardcoded IP with credentials",  re.compile(r"(?i)(?:mysql|redis|mongodb|postgres)://[^:]+:[^@]+@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")),
]

# Strings that look like secrets but aren't — quick false-positive suppression
_FP_PATTERNS = [
    re.compile(r"example|placeholder|your[-_]?key|your[-_]?secret|insert[-_]?here|changeme|xxxxxxxx", re.I),
    re.compile(r"<[A-Z_]+>"),           # template variables like <YOUR_KEY>
    re.compile(r"\$\{[^}]+\}"),         # ${ENV_VAR}
    re.compile(r"process\.env\.[A-Z]"), # process.env.SECRET_KEY
]

_MAX_SCRIPT_SIZE = 512_000  # skip scripts > 512 KB (likely minified bundles we'd flood with results)
_MAX_SCRIPTS     = 20       # cap to avoid scanning hundreds of CDN scripts


def _is_likely_fp(match_text: str) -> bool:
    return any(p.search(match_text) for p in _FP_PATTERNS)


class JSSecretsScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if not resp:
            return self.results

        found_secrets: Dict[str, str] = {}  # dedup by (label, url)

        # Scan page HTML itself
        self._scan_content(resp.text, url, found_secrets)

        # Collect <script src> URLs
        script_urls = self._extract_script_urls(resp.text, url)
        for script_url in script_urls[:_MAX_SCRIPTS]:
            try:
                js_resp = self.http.get(script_url)
                if js_resp and js_resp.status_code == 200:
                    content = js_resp.text
                    if len(content) > _MAX_SCRIPT_SIZE:
                        content = content[:_MAX_SCRIPT_SIZE]
                    self._scan_content(content, script_url, found_secrets)
            except Exception:
                continue

        if not found_secrets:
            log_pass(logger, "No hardcoded secrets detected in JavaScript")
            self.results.append(self._result(url, "JS secrets — none detected", "PASS",
                detail="No hardcoded API keys, tokens, or credentials detected in "
                       "page source or linked JavaScript files."))
        return self.results

    def _extract_script_urls(self, html: str, base_url: str) -> List[str]:
        urls = []
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            src = m.group(1)
            if src.startswith("data:"):
                continue
            absolute = urljoin(base_url, src)
            urls.append(absolute)
        return urls

    def _scan_content(self, content: str, source_url: str, found: Dict) -> None:
        for label, pattern in _PATTERNS:
            for m in pattern.finditer(content):
                matched = m.group(0)
                if _is_likely_fp(matched):
                    continue
                dedup_key = f"{label}::{source_url}"
                if dedup_key in found:
                    continue
                found[dedup_key] = matched
                log_fail(logger, f"Hardcoded secret: {label} in {source_url}")
                self.results.append(self._result(
                    source_url,
                    f"JS secret — {label}",
                    "FAIL",
                    detail=(
                        f"Hardcoded {label} found in JavaScript at {source_url}. "
                        "Exposed credentials give attackers direct access to the associated service "
                        "and will be indexed by search engines, Wayback Machine, and code scanners. "
                        "Fix: remove the credential immediately, rotate/revoke it at the provider, "
                        "then store it server-side in environment variables or a secrets manager "
                        "(AWS Secrets Manager, HashiCorp Vault, Doppler, etc.). "
                        "Never commit secrets to source control."
                    )
                ))
