"""
Subdomain takeover / dangling DNS detector.

For each live subdomain found (from DNS scan or CT logs), follows the CNAME
chain and checks if the ultimate destination shows signs of being unclaimed.
Uses an embedded fingerprint list based on the open-source
EdOverflow/can-i-take-over-xyz project — no external API calls.
"""

import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

# (service_name, cname_pattern, response_body_fingerprint, severity)
# cname_pattern matches on the final CNAME target; body_fp matches on HTTP response body.
_FINGERPRINTS: List[Dict] = [
    {"service": "GitHub Pages",
     "cname":   r"github\.io$",
     "body":    "There isn't a GitHub Pages site here.",
     "severity": "HIGH"},
    {"service": "Heroku",
     "cname":   r"herokudns\.com$|herokuapp\.com$",
     "body":    "No such app",
     "severity": "HIGH"},
    {"service": "AWS S3",
     "cname":   r"s3\.amazonaws\.com$|s3-[a-z0-9-]+\.amazonaws\.com$",
     "body":    "NoSuchBucket",
     "severity": "CRITICAL"},
    {"service": "AWS Elastic Beanstalk",
     "cname":   r"elasticbeanstalk\.com$",
     "body":    "NXDOMAIN",
     "severity": "HIGH"},
    {"service": "Azure",
     "cname":   r"azurewebsites\.net$|cloudapp\.azure\.com$|trafficmanager\.net$",
     "body":    "404 Web Site not found",
     "severity": "HIGH"},
    {"service": "Fastly",
     "cname":   r"fastly\.net$",
     "body":    "Fastly error: unknown domain",
     "severity": "HIGH"},
    {"service": "Shopify",
     "cname":   r"myshopify\.com$",
     "body":    "Sorry, this shop is currently unavailable.",
     "severity": "MEDIUM"},
    {"service": "Tumblr",
     "cname":   r"tumblr\.com$",
     "body":    "There's nothing here.",
     "severity": "MEDIUM"},
    {"service": "Pantheon",
     "cname":   r"pantheonsite\.io$",
     "body":    "The gods are wise, but do not know of the site which you seek.",
     "severity": "HIGH"},
    {"service": "Ghost",
     "cname":   r"ghost\.io$",
     "body":    "The thing you were looking for is no longer here",
     "severity": "MEDIUM"},
    {"service": "Zendesk",
     "cname":   r"zendesk\.com$",
     "body":    "Help Center Closed",
     "severity": "MEDIUM"},
    {"service": "Unbounce",
     "cname":   r"unbouncepages\.com$",
     "body":    "The requested URL was not found on this server.",
     "severity": "MEDIUM"},
    {"service": "Statuspage.io",
     "cname":   r"statuspage\.io$",
     "body":    "Better Status Communication",
     "severity": "LOW"},
    {"service": "Surge.sh",
     "cname":   r"surge\.sh$",
     "body":    "project not found",
     "severity": "HIGH"},
    {"service": "Netlify",
     "cname":   r"netlify\.app$|netlify\.com$",
     "body":    "Not found - Request ID",
     "severity": "HIGH"},
    {"service": "Vercel",
     "cname":   r"vercel\.app$",
     "body":    "The deployment you requested does not exist",
     "severity": "HIGH"},
    {"service": "WP Engine",
     "cname":   r"wpengine\.com$",
     "body":    "The site you were looking for couldn't be found.",
     "severity": "HIGH"},
    {"service": "Webflow",
     "cname":   r"proxy\.webflow\.com$",
     "body":    "Page Not Found",
     "severity": "MEDIUM"},
    {"service": "Intercom",
     "cname":   r"custom\.intercom\.help$",
     "body":    "This page is reserved for artistic dogs.",
     "severity": "MEDIUM"},
]


def _import_dns():
    try:
        import dns.resolver
        return dns.resolver
    except ImportError:
        return None


def _follow_cname(resolver, name: str, depth: int = 0) -> Optional[str]:
    if depth > 10:
        return None
    try:
        answers = resolver.resolve(name, "CNAME")
        target  = str(answers[0].target).rstrip(".")
        return _follow_cname(resolver, target, depth + 1) or target
    except Exception:
        return name  # no more CNAMEs — return current name


class SubdomainTakeoverScanner(BaseScanner):

    def scan_subdomains(self, subdomains: List[str], base_url: str) -> List[Dict[str, Any]]:
        self.results = []
        resolver = _import_dns()
        if resolver is None:
            return self.results

        vulnerable  = 0
        checked     = 0
        for sub in subdomains[:50]:  # cap at 50 to avoid long scan times
            checked += 1
            result  = self._check_subdomain(sub, resolver)
            if result:
                self.results.append(result)
                if result["status"] in ("FAIL", "WARN"):
                    vulnerable += 1

        if checked > 0 and vulnerable == 0:
            self.results.append(self._result(base_url,
                "Subdomain takeover — no vulnerable subdomains detected",
                "PASS",
                detail=f"Checked {checked} subdomains against {len(_FINGERPRINTS)} takeover "
                       "fingerprints — none appear vulnerable."))
        return self.results

    def scan(self, url: str) -> List[Dict[str, Any]]:
        # Called with no pre-discovered subdomains — return empty (needs input from dns/crt_sh)
        return []

    def _check_subdomain(self, sub: str, resolver) -> Optional[Dict[str, Any]]:
        cname_target = _follow_cname(resolver, sub)
        if not cname_target:
            return None

        for fp in _FINGERPRINTS:
            if not re.search(fp["cname"], cname_target, re.I):
                continue
            # CNAME points to this service — probe HTTP to confirm unclaimed
            try:
                resp = self.http.get(f"http://{sub}")
                if resp and fp["body"].lower() in resp.text.lower():
                    sev = fp["severity"]
                    status = "FAIL" if sev in ("CRITICAL", "HIGH") else "WARN"
                    log_fail(logger, f"Subdomain takeover: {sub} → {fp['service']}")
                    return self._result(
                        f"http://{sub}",
                        f"Subdomain takeover — {fp['service']} ({sub})",
                        status,
                        detail=(
                            f"Subdomain {sub} has a CNAME pointing to {cname_target} "
                            f"({fp['service']}) but the target resource does not exist — "
                            "this subdomain can be claimed by an attacker. "
                            f"An attacker can register {fp['service'].lower()} and serve "
                            "malicious content (phishing, malware, credential harvesting) "
                            "on your subdomain with your domain's trust. "
                            "Fix: either point the DNS record to a resource you own, "
                            "or remove the DNS record entirely."
                        )
                    )
            except Exception:
                pass
        return None
