"""
Leaked data in HTML comments scanner.

Scans HTML <!-- comment --> blocks for credentials, internal paths,
debug information, TODO/FIXME notes with sensitive context, internal
IP addresses, and hardcoded configuration values that should never
reach production.
"""

import re
from typing import List, Dict, Any, Set

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

# Extract all HTML comments (including multi-line)
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)

# (label, pattern, severity)
_COMMENT_PATTERNS: List[tuple] = [
    # Credentials and secrets
    ("password/credential",     re.compile(r"\b(?:password|passwd|pwd|secret|credentials?)\s*[:=]\s*\S+", re.I), "FAIL"),
    ("API key in comment",      re.compile(r"\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\s*[:=]\s*\S+", re.I), "FAIL"),
    ("AWS key pattern",         re.compile(r"AKIA[0-9A-Z]{16}", re.I), "FAIL"),
    ("database connection",     re.compile(r"(?:mysql|postgres|mongodb|redis|jdbc)://[^\s<>\"']+", re.I), "FAIL"),

    # Internal infrastructure
    ("internal IP address",     re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"), "WARN"),
    ("localhost reference",     re.compile(r"\blocalhost\b|\b127\.0\.0\.\d+\b", re.I), "WARN"),
    ("internal hostname",       re.compile(r"\b[a-z0-9-]+\.(?:internal|corp|local|lan|intranet)\b", re.I), "WARN"),
    ("UNC/network path",        re.compile(r"\\\\[a-z0-9_-]+\\[a-z0-9_$\\-]+", re.I), "WARN"),

    # Debug artifacts
    ("debug flag",              re.compile(r"\b(?:debug|verbose)\s*[=:]\s*(?:true|1|on|yes)\b", re.I), "WARN"),
    ("stack trace fragment",    re.compile(r"(?:Traceback|at\s+[A-Z][a-zA-Z.]+\.[a-zA-Z]+\(|Exception in thread)", re.I), "WARN"),
    ("TODO with sensitive hint",re.compile(r"\bTODO\b.*?\b(?:password|auth|secret|key|token|admin|cred)\b", re.I), "WARN"),
    ("FIXME with sensitive hint",re.compile(r"\bFIXME\b.*?\b(?:password|auth|secret|key|token|admin|cred)\b", re.I), "WARN"),
    ("disabled security check", re.compile(r"(?:disable[ds]?|bypass|skip|workaround)\s+(?:csrf|auth|ssl|tls|security|validation|check)", re.I), "WARN"),

    # Version / config disclosure
    ("version string",          re.compile(r"\bv(?:er(?:sion)?)?\s*[=:]?\s*\d+\.\d+\.\d+\b", re.I), "WARN"),
    ("server path disclosure",  re.compile(r"(?:/var/www|/home/[a-z]+/|C:\\(?:inetpub|Users|wamp|xampp)\\)", re.I), "WARN"),
]

# Minimum comment length to bother checking (skip empty <!-- --> or <!-- copyright --> lines)
_MIN_COMMENT_LEN = 8

# Deduplicate by label + snippet to avoid 100 identical findings for repeated footer comments
_MAX_PER_LABEL = 3


class HTMLCommentsScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        try:
            resp = self.http.get(url)
            if resp is None or resp.status_code != 200:
                return self.results
        except Exception:
            return self.results

        html     = resp.text or ""
        comments = _COMMENT_RE.findall(html)

        if not comments:
            self._pass(url, "no HTML comments found")
            return self.results

        findings: List[Dict] = []
        seen: Set[str]       = set()
        label_counts: dict   = {}

        for comment in comments:
            comment = comment.strip()
            if len(comment) < _MIN_COMMENT_LEN:
                continue
            for label, pattern, severity in _COMMENT_PATTERNS:
                if label_counts.get(label, 0) >= _MAX_PER_LABEL:
                    continue
                m = pattern.search(comment)
                if not m:
                    continue
                snippet  = m.group(0)[:120]
                dedup_key = f"{label}::{snippet.lower()}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                label_counts[label] = label_counts.get(label, 0) + 1
                preview = comment[:200].replace("\n", " ").strip()
                if severity == "FAIL":
                    log_fail(logger, f"Sensitive data in HTML comment ({label}): {snippet[:60]}")
                else:
                    log_warn(logger, f"Noteworthy HTML comment ({label}): {snippet[:60]}")
                findings.append(self._result(url,
                    f"HTML comment — {label}",
                    severity,
                    detail=(
                        f"Found {label} pattern inside an HTML comment. "
                        f"Snippet: «{snippet}». "
                        f"Full comment preview: «{preview}». "
                        "HTML comments are visible to anyone who views page source. "
                        "Remove sensitive data from templates and build pipelines — "
                        "use server-side rendering guards or a comment-stripping build step."
                    )))

        if findings:
            self.results.extend(findings)
        else:
            self._pass(url, f"{len(comments)} HTML comment(s) found, none contain sensitive patterns")
        return self.results

    def _pass(self, url: str, detail_suffix: str) -> None:
        log_pass(logger, f"HTML comments clean: {detail_suffix}")
        self.results.append(self._result(url,
            "HTML comments — no sensitive data found",
            "PASS",
            detail=f"Scanned all HTML comments: {detail_suffix}."))
