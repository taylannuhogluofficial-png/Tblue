"""
WAF / CDN detection scanner.

Checks response headers and cookies for fingerprints of known web application
firewalls and CDN providers. A detected WAF is a PASS (positive security signal).
No WAF detected is a WARN — the site has no additional protective layer.

Providers detected: Cloudflare, AWS WAF / CloudFront, Akamai, Imperva/Incapsula,
Sucuri, Fastly, Azure Front Door, Google Cloud Armor, Barracuda, F5 BIG-IP,
Radware, ModSecurity, Wordfence.

Detection is confidence-based: each signal adds to a score; ≥ 1 signal = detected.
"""

import re
from typing import List, Dict, Any, Optional, Tuple
from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)


# Each entry: (header_name, value_pattern_or_None, provider_name)
# value_pattern=None means presence of the header alone is the signal.
_HEADER_SIGNALS: List[Tuple[str, Optional[re.Pattern], str]] = [
    # Cloudflare
    ("server",             re.compile(r"cloudflare", re.I),                     "Cloudflare"),
    ("cf-ray",             None,                                                  "Cloudflare"),
    ("cf-cache-status",    None,                                                  "Cloudflare"),
    ("cf-request-id",      None,                                                  "Cloudflare"),

    # AWS CloudFront / WAF
    ("x-amz-cf-id",        None,                                                  "AWS CloudFront"),
    ("x-amzn-requestid",   None,                                                  "AWS (API Gateway / WAF)"),
    ("x-amzn-trace-id",    None,                                                  "AWS (API Gateway / WAF)"),
    ("x-amz-id-2",         None,                                                  "AWS S3 / CloudFront"),
    ("via",                re.compile(r"(cloudfront|1\.1 amazon)", re.I),         "AWS CloudFront"),

    # Akamai
    ("x-akamai-request-id", None,                                                 "Akamai"),
    ("x-akamai-ssl-client-sid", None,                                             "Akamai"),
    ("x-check-cacheable", None,                                                   "Akamai"),
    ("server",             re.compile(r"akamaighost", re.I),                      "Akamai"),
    ("x-akamai-transformed", None,                                                "Akamai"),

    # Imperva / Incapsula
    ("x-iinfo",            None,                                                  "Imperva/Incapsula"),
    ("x-cdn",              re.compile(r"incapsula", re.I),                        "Imperva/Incapsula"),
    ("x-sigsci-requestid", None,                                                  "Signal Sciences (Imperva)"),

    # Sucuri
    ("x-sucuri-id",        None,                                                  "Sucuri"),
    ("x-sucuri-cache",     None,                                                  "Sucuri"),
    ("server",             re.compile(r"sucuri", re.I),                           "Sucuri"),

    # Fastly
    ("x-fastly-request-id", None,                                                 "Fastly"),
    ("fastly-restarts",    None,                                                   "Fastly"),
    ("via",                re.compile(r"varnish", re.I),                           "Fastly/Varnish"),
    ("x-served-by",        re.compile(r"cache-", re.I),                           "Fastly"),

    # Azure Front Door / CDN
    ("x-azure-ref",        None,                                                   "Azure Front Door"),
    ("x-ms-ref",           None,                                                   "Azure Front Door"),
    ("x-fd-healthprobe",   None,                                                   "Azure Front Door"),

    # Google Cloud Armor / GFE
    ("server",             re.compile(r"(gws|google front end|gfe)", re.I),        "Google Cloud / GFE"),
    ("x-goog-generation",  None,                                                   "Google Cloud CDN"),

    # F5 BIG-IP
    ("server",             re.compile(r"big-?ip", re.I),                           "F5 BIG-IP"),
    ("x-waf-status",       None,                                                   "F5 BIG-IP WAF"),
    ("x-wa-info",          None,                                                   "F5 WAF"),

    # Barracuda
    ("x-barracuda-connect", None,                                                  "Barracuda"),

    # Radware
    ("x-rdwr-ip",          None,                                                   "Radware"),

    # ModSecurity (generic, often server: Apache + headers)
    ("x-mod-security-message", None,                                               "ModSecurity"),

    # Wordfence (WordPress WAF)
    ("x-wf-sid",           None,                                                   "Wordfence"),
]

# Cookie name prefixes that indicate WAF presence
_COOKIE_SIGNALS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"^__cfduid$|^cf_clearance$|^__cf_bm$", re.I),  "Cloudflare"),
    (re.compile(r"^incap_ses_|^visid_incap_", re.I),             "Imperva/Incapsula"),
    (re.compile(r"^sucuri_cloudproxy_", re.I),                    "Sucuri"),
    (re.compile(r"^bm_sv$|^bm_sz$|^_abck$", re.I),              "Akamai Bot Manager"),
]


class WAFScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url, allow_redirects=True)
        if not resp:
            return self.results

        provider, signals = self._detect(resp)

        if provider:
            sig_list = "; ".join(signals[:5])
            log_pass(logger, f"WAF/CDN detected: {provider} — {url}")
            self.results.append(self._result(
                url, f"WAF/CDN — {provider} detected", "PASS",
                detail=(
                    f"{provider} was detected as the WAF/CDN provider protecting {url}. "
                    f"Detection signals: {sig_list}. "
                    "Having a WAF layer provides DDoS mitigation, bot filtering, "
                    "and virtual patching for known vulnerabilities."
                )
            ))
        else:
            log_warn(logger, f"No WAF/CDN detected — {url}")
            self.results.append(self._result(
                url, "WAF/CDN — none detected", "WARN",
                detail=(
                    f"No WAF or CDN fingerprints were found in the response from {url}. "
                    "This does not mean the site is unprotected — WAFs can be transparent "
                    "or use non-standard headers. However, if no WAF is intentionally in place, "
                    "consider adding one. "
                    "Options: Cloudflare (free tier), AWS WAF + CloudFront, Azure Front Door, "
                    "Akamai, or a self-hosted ModSecurity/Nginx WAF."
                )
            ))

        return self.results

    def _detect(self, resp) -> Tuple[Optional[str], List[str]]:
        provider_scores: Dict[str, List[str]] = {}

        # Header signals
        for header_name, pattern, provider in _HEADER_SIGNALS:
            val = resp.headers.get(header_name, "")
            if not val:
                continue
            if pattern is None or pattern.search(val):
                provider_scores.setdefault(provider, []).append(
                    f"{header_name}: {val[:60]}"
                )

        # Cookie signals
        try:
            raw_cookies = resp.raw.headers.getlist("set-cookie") \
                if hasattr(resp.raw.headers, "getlist") else []
        except Exception:
            raw_cookies = []

        for cookie_str in raw_cookies:
            name = cookie_str.split("=")[0].strip()
            for pattern, provider in _COOKIE_SIGNALS:
                if pattern.match(name):
                    provider_scores.setdefault(provider, []).append(
                        f"cookie: {name}"
                    )

        if not provider_scores:
            return None, []

        # Pick highest-confidence provider (most signals)
        best = max(provider_scores, key=lambda p: len(provider_scores[p]))
        return best, provider_scores[best]
