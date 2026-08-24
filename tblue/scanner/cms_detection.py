"""
CMS / framework fingerprinting.

Identifies WordPress, Drupal, Joomla, Magento, Shopify, Ghost, Django,
Laravel, Ruby on Rails, and Next.js via HTML patterns, meta tags, path
probes, and HTTP headers. When a version is detected, checks for known
CVEs via the OSV.dev free API.
"""

import re
import json
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_OSV_URL = "https://api.osv.dev/v1/query"
_OSV_TIMEOUT = 10

# (cms_name, ecosystem_for_osv, package_name_for_osv, version_regex, probe_paths, body_patterns)
_CMS_SIGNATURES: List[Dict] = [
    {
        "name": "WordPress",
        "ecosystem": "npm",
        "osv_package": None,  # check via wp-specific CVE list
        "version_regex": re.compile(
            r'<meta name=["\']generator["\'] content=["\']WordPress ([0-9.]+)', re.I
        ),
        "version_path": "/wp-login.php",
        "version_path_regex": re.compile(r'ver=([0-9.]+)', re.I),
        "body_patterns": [
            re.compile(r'/wp-content/', re.I),
            re.compile(r'/wp-includes/', re.I),
            re.compile(r'wordpress', re.I),
        ],
        "header_patterns": [],
        "category": "CMS",
    },
    {
        "name": "Drupal",
        "ecosystem": None,
        "osv_package": None,
        "version_regex": re.compile(
            r'<meta name=["\']generator["\'] content=["\']Drupal ([0-9.]+)', re.I
        ),
        "body_patterns": [
            re.compile(r'/sites/default/files/', re.I),
            re.compile(r'Drupal\.settings', re.I),
            re.compile(r'/misc/drupal\.js', re.I),
        ],
        "header_patterns": [re.compile(r'X-Generator: Drupal', re.I)],
        "category": "CMS",
    },
    {
        "name": "Joomla",
        "ecosystem": None,
        "osv_package": None,
        "version_regex": re.compile(
            r'<meta name=["\']generator["\'] content=["\']Joomla!?\s*([0-9.]*)', re.I
        ),
        "body_patterns": [
            re.compile(r'/media/jui/', re.I),
            re.compile(r'/templates/[^/]+/css/', re.I),
            re.compile(r'Joomla!', re.I),
        ],
        "header_patterns": [],
        "category": "CMS",
    },
    {
        "name": "Magento",
        "ecosystem": None,
        "osv_package": None,
        "version_regex": re.compile(r'Magento[/ ]([0-9.]+)', re.I),
        "body_patterns": [
            re.compile(r'/skin/frontend/', re.I),
            re.compile(r'Mage\.Cookies', re.I),
            re.compile(r'/js/mage/', re.I),
        ],
        "header_patterns": [re.compile(r'X-Magento-', re.I)],
        "category": "Ecommerce",
    },
    {
        "name": "Shopify",
        "ecosystem": None,
        "osv_package": None,
        "version_regex": None,
        "body_patterns": [
            re.compile(r'cdn\.shopify\.com', re.I),
            re.compile(r'Shopify\.theme', re.I),
        ],
        "header_patterns": [re.compile(r'X-ShopId', re.I)],
        "category": "Ecommerce",
    },
    {
        "name": "Ghost",
        "ecosystem": "npm",
        "osv_package": "ghost",
        "version_regex": re.compile(
            r'<meta name=["\']generator["\'] content=["\']Ghost ([0-9.]+)', re.I
        ),
        "body_patterns": [re.compile(r'ghost-url', re.I)],
        "header_patterns": [re.compile(r'X-Ghost-Cache', re.I)],
        "category": "CMS",
    },
    {
        "name": "Django",
        "ecosystem": "PyPI",
        "osv_package": "django",
        "version_regex": None,
        "body_patterns": [re.compile(r'csrfmiddlewaretoken', re.I)],
        "header_patterns": [
            re.compile(r'X-Frame-Options: SAMEORIGIN', re.I),
        ],
        "category": "Framework",
    },
    {
        "name": "Laravel",
        "ecosystem": "Packagist",
        "osv_package": "laravel/framework",
        "version_regex": re.compile(r'Laravel v?([0-9.]+)', re.I),
        "body_patterns": [
            re.compile(r'laravel_session', re.I),
            re.compile(r'XSRF-TOKEN', re.I),
        ],
        "header_patterns": [],
        "category": "Framework",
    },
    {
        "name": "Next.js",
        "ecosystem": "npm",
        "osv_package": "next",
        "version_regex": re.compile(r'"next":\s*"([0-9.^~]+)"', re.I),
        "body_patterns": [
            re.compile(r'__NEXT_DATA__', re.I),
            re.compile(r'/_next/static/', re.I),
        ],
        "header_patterns": [re.compile(r'X-Powered-By: Next\.js', re.I)],
        "category": "Framework",
    },
    {
        "name": "Ruby on Rails",
        "ecosystem": "RubyGems",
        "osv_package": "rails",
        "version_regex": None,
        "body_patterns": [
            re.compile(r'authenticity_token', re.I),
            re.compile(r'data-turbolinks', re.I),
        ],
        "header_patterns": [re.compile(r'X-Powered-By: Phusion Passenger', re.I)],
        "category": "Framework",
    },
]


class CMSDetectionScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        try:
            resp = self.http.get(url)
            if resp is None:
                return self.results
        except Exception:
            return self.results

        html          = resp.text
        resp_headers  = resp.headers
        header_str    = "\n".join(f"{k}: {v}" for k, v in resp_headers.items())
        detected      = []

        for sig in _CMS_SIGNATURES:
            if self._matches(sig, html, header_str):
                version = self._extract_version(sig, html, url)
                detected.append((sig, version))

        if not detected:
            self.results.append(self._result(url, "CMS detection — not identified", "PASS",
                detail="No known CMS or framework fingerprints detected. "
                       "This limits automated targeting by opportunistic attackers."))
            return self.results

        for sig, version in detected:
            name     = sig["name"]
            category = sig["category"]
            if version:
                vulns = self._check_osv(sig, version)
                if vulns:
                    cve_list = ", ".join(v.get("id", "?") for v in vulns[:5])
                    more = f" (+ {len(vulns) - 5} more)" if len(vulns) > 5 else ""
                    log_fail(logger, f"{name} {version} has {len(vulns)} known vulnerabilities")
                    self.results.append(self._result(url,
                        f"CMS — {name} {version} has known CVEs",
                        "FAIL",
                        detail=(
                            f"Detected {name} version {version} with {len(vulns)} known "
                            f"vulnerability/ies: {cve_list}{more}. "
                            f"Fix: update {name} to the latest stable version immediately. "
                            "Also suppress version disclosure by removing generator meta tags "
                            "and X-Powered-By headers."
                        ),
                        extra={"cms": name, "cms_version": version, "cves": [v.get("id") for v in vulns]}
                    ))
                else:
                    log_warn(logger, f"Detected {name} {version} (no known CVEs)")
                    self.results.append(self._result(url,
                        f"CMS — {name} {version} detected",
                        "WARN",
                        detail=(
                            f"Detected {name} version {version}. No known CVEs at this time. "
                            "Version disclosure helps attackers target platform-specific exploits. "
                            "Fix: remove the generator meta tag and X-Powered-By headers."
                        ),
                        extra={"cms": name, "cms_version": version}
                    ))
            else:
                log_warn(logger, f"Detected {name} (version unknown)")
                self.results.append(self._result(url,
                    f"CMS — {name} detected",
                    "WARN",
                    detail=(
                        f"Detected {name} but could not determine the version. "
                        "Ensure you are running the latest stable version and that "
                        "version disclosure is suppressed."
                    ),
                    extra={"cms": name}
                ))

        return self.results

    def _matches(self, sig: Dict, html: str, header_str: str) -> bool:
        for pat in sig.get("body_patterns", []):
            if pat.search(html):
                return True
        for pat in sig.get("header_patterns", []):
            if pat.search(header_str):
                return True
        if sig.get("version_regex") and sig["version_regex"].search(html):
            return True
        return False

    def _extract_version(self, sig: Dict, html: str, url: str) -> Optional[str]:
        vr = sig.get("version_regex")
        if vr:
            m = vr.search(html)
            if m:
                return m.group(1) if m.lastindex else None
        return None

    def _check_osv(self, sig: Dict, version: str) -> List[dict]:
        eco = sig.get("ecosystem")
        pkg = sig.get("osv_package")
        if not eco or not pkg:
            return []
        try:
            resp = self.http.session.post(
                _OSV_URL,
                json={"version": version, "package": {"name": pkg, "ecosystem": eco}},
                timeout=_OSV_TIMEOUT,
            )
            if resp and resp.status_code == 200:
                return resp.json().get("vulns", [])
        except Exception as e:
            logger.debug(f"OSV query failed for {pkg}: {e}")
        return []

    def _result(self, url, result_type, status, detail="", extra=None):
        r = super()._result(url, result_type, status, detail=detail)
        if extra:
            r.update(extra)
        return r
