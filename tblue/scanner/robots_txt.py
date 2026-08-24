"""
robots.txt security scanner.

Checks robots.txt for:
- Sensitive paths disclosed in Disallow directives (admin, backup, API, config)
- Wildcard allow-all (Disallow: nothing — legitimate but noted)
- Full site disallow (Disallow: / — may hide but doesn't protect)
- Sitemap URL extraction (for attack surface enumeration)
- Presence and accessibility of the file itself
"""

import re
from typing import List, Dict, Any, Set
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_SENSITIVE_PATH_PATTERNS: List[tuple] = [
    # (label, compiled regex, severity)
    ("admin interface path",    re.compile(r"^/(?:admin|administrator|manage|management|backend|control|panel|dashboard)", re.I), "WARN"),
    ("backup/archive path",     re.compile(r"^/(?:backup|bak|backups|archive|archives|old|dump)", re.I), "WARN"),
    ("database dump path",      re.compile(r"^/(?:db|database|sql|dump|export)[\s/]", re.I), "WARN"),
    ("config/environment path", re.compile(r"^/(?:config|conf|configuration|settings|env|\.env)", re.I), "WARN"),
    ("API endpoint path",       re.compile(r"^/(?:api/|v\d+/|rest/|graphql|swagger|openapi)", re.I), "WARN"),
    ("authentication path",     re.compile(r"^/(?:login|signin|auth|oauth|sso|saml|password|forgot|reset)", re.I), "WARN"),
    ("user data path",          re.compile(r"^/(?:user|users|account|accounts|profile|customer|member)", re.I), "WARN"),
    ("development artifact",    re.compile(r"^/(?:dev|staging|test|debug|phpmyadmin|adminer|wp-admin)", re.I), "WARN"),
    ("financial/payment path",  re.compile(r"^/(?:payment|billing|invoice|checkout|order|cart|purchase)", re.I), "WARN"),
    ("upload/file path",        re.compile(r"^/(?:upload|uploads|files|media|documents|attachments)", re.I), "WARN"),
    ("Git/VCS artifact",        re.compile(r"^/\.git|^/\.svn|^/\.hg|^/CVS", re.I), "FAIL"),
    ("private key/cert",        re.compile(r"^/(?:.*\.pem|.*\.key|.*\.crt|.*\.p12|.*\.pfx)$", re.I), "FAIL"),
    ("internal tool",           re.compile(r"^/(?:jenkins|travis|circleci|ansible|puppet|chef|terraform)", re.I), "WARN"),
]

_SITEMAP_RE = re.compile(r"^Sitemap:\s*(\S+)", re.I | re.M)
_DISALLOW_RE = re.compile(r"^Disallow:\s*(\S*)", re.I | re.M)
_ALLOW_RE    = re.compile(r"^Allow:\s*(\S*)", re.I | re.M)


class RobotsSecurityScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed    = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

        try:
            resp = self.http.get(robots_url)
        except Exception:
            return self.results

        if resp is None or resp.status_code == 404:
            log_warn(logger, "robots.txt not found")
            self.results.append(self._result(url,
                "robots.txt — file not found",
                "WARN",
                detail=(
                    "No robots.txt found at /robots.txt. "
                    "While robots.txt is advisory (security through obscurity), its absence "
                    "means search engines may index everything, and its presence can serve "
                    "as an inventory of interesting paths for defenders. "
                    "Consider adding robots.txt to control crawler behaviour."
                )))
            return self.results

        if resp.status_code != 200:
            return self.results

        content = resp.text or ""
        self._check_sensitive_disallows(content, url, robots_url)
        self._check_full_allow(content, url)
        self._check_sitemaps(content, url)
        return self.results

    def _check_sensitive_disallows(self, content: str, url: str, robots_url: str) -> None:
        disallowed = [m.group(1).strip() for m in _DISALLOW_RE.finditer(content)
                      if m.group(1).strip()]

        sensitive_found: List[tuple] = []
        seen: Set[str] = set()

        for path in disallowed:
            for label, pattern, severity in _SENSITIVE_PATH_PATTERNS:
                if pattern.match(path) and path not in seen:
                    seen.add(path)
                    sensitive_found.append((path, label, severity))

        if sensitive_found:
            fails = [(p, l) for p, l, s in sensitive_found if s == "FAIL"]
            warns = [(p, l) for p, l, s in sensitive_found if s == "WARN"]

            if fails:
                fail_paths = ", ".join(p for p, _ in fails[:5])
                log_fail(logger, f"Critical paths in robots.txt Disallow: {fail_paths}")
                self.results.append(self._result(url,
                    "robots.txt — critical paths disclosed in Disallow",
                    "FAIL",
                    detail=(
                        f"robots.txt reveals high-risk paths: {fail_paths}. "
                        "robots.txt is world-readable and indexed by tools like Shodan. "
                        "These paths tell attackers exactly where to look. "
                        "Fix: remove these entries and protect the paths with proper access control. "
                        "robots.txt is advisory — it does NOT prevent access."
                    )))

            if warns:
                warn_paths = ", ".join(p for p, _ in warns[:10])
                log_warn(logger, f"Sensitive paths in robots.txt Disallow: {warn_paths}")
                self.results.append(self._result(url,
                    "robots.txt — sensitive paths disclosed in Disallow",
                    "WARN",
                    detail=(
                        f"robots.txt disallows {len(warns)} potentially sensitive path(s): "
                        f"{warn_paths}. "
                        "Disallow entries serve as a map of interesting paths for attackers. "
                        "Review whether these paths truly need to be listed — if they require "
                        "authentication, listing them in robots.txt adds no security benefit."
                    )))
        else:
            log_pass(logger, "No sensitive paths exposed in robots.txt")
            self.results.append(self._result(url,
                "robots.txt — no sensitive paths in Disallow rules",
                "PASS",
                detail=f"robots.txt has {len(disallowed)} Disallow rule(s) — "
                       "none match known sensitive path patterns."))

    def _check_full_allow(self, content: str, url: str) -> None:
        disallowed = [m.group(1).strip() for m in _DISALLOW_RE.finditer(content)]
        # Disallow: / for * = full crawl block
        has_full_block = any(d == "/" for d in disallowed)
        has_empty      = any(d == "" for d in disallowed)

        if has_full_block:
            log_warn(logger, "robots.txt blocks all crawlers from everything")
            self.results.append(self._result(url,
                "robots.txt — full site blocked from crawlers (Disallow: /)",
                "WARN",
                detail=(
                    "robots.txt disallows all crawling (Disallow: /). "
                    "This prevents search engine indexing which may be intentional for staging/internal sites. "
                    "Note: this does NOT protect content — malicious crawlers ignore robots.txt. "
                    "If this is a public-facing site, verify the full block is intentional."
                )))

    def _check_sitemaps(self, content: str, url: str) -> None:
        sitemaps = _SITEMAP_RE.findall(content)
        if sitemaps:
            log_pass(logger, f"Sitemap(s) declared in robots.txt: {sitemaps}")
            self.results.append(self._result(url,
                f"robots.txt — {len(sitemaps)} sitemap(s) declared",
                "PASS",
                detail=(
                    f"robots.txt declares {len(sitemaps)} sitemap(s): "
                    f"{', '.join(sitemaps[:3])}{'…' if len(sitemaps) > 3 else ''}. "
                    "Sitemaps help search engines discover content and are a security-neutral indicator."
                )))
