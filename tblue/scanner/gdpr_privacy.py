"""
GDPR / privacy compliance indicators.

Checks for:
1. Cookie consent banner — OneTrust, Cookiebot, CookieYes, TrustArc, Osano,
   iubenda, Termly, Complianz, Civic, CC Banner, generic patterns
2. Privacy policy page link (required by GDPR Art.13, CCPA, etc.)
3. Cookies set on first load before any consent interaction
4. Third-party tracking scripts loaded before consent
5. Google Analytics / Facebook Pixel / LinkedIn Insight without consent wrapper

All checks are read-only (single GET request). Intended for blue teams to
quickly identify missing consent infrastructure.
"""

import re
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

# Consent management platform signatures (HTML body / script src)
_CMP_PATTERNS = [
    (re.compile(r'cookiebot\.com|CookieBotSettings|Cookiebot', re.I), "Cookiebot"),
    (re.compile(r'onetrust|optanon|OneTrustActiveGroups|cookielaw\.org|otSDKStub', re.I), "OneTrust"),
    (re.compile(r'cookieyes|cookie-law-info|CookieYes', re.I), "CookieYes"),
    (re.compile(r'trustarc|truste\.com|TrustArcCookiePref', re.I), "TrustArc"),
    (re.compile(r'osano\.com|Osano\.cm', re.I), "Osano"),
    (re.compile(r'iubenda\.com|iubendaConsent', re.I), "iubenda"),
    (re.compile(r'termly\.io|termlyConsent', re.I), "Termly"),
    (re.compile(r'complianz|cmplz', re.I), "Complianz"),
    (re.compile(r'civic\.cookie|CookieControl', re.I), "Civic"),
    (re.compile(r'cookieconsent|cc-window|cc-banner|cc-compliance', re.I), "Cookie Consent (generic)"),
    (re.compile(r'gdpr.?consent|consent.?gdpr|cookie.?notice|cookie.?banner|cookie.?popup', re.I), "GDPR consent banner (generic)"),
    (re.compile(r'data-consent|consentManager|ConsentString', re.I), "Consent manager (generic)"),
]

# Privacy policy link patterns
_PRIVACY_LINK_RE = re.compile(
    r'href=["\'][^"\']*(?:privacy|datenschutz|confidentialite|privacidad|'
    r'privacybeleid|privatumo|gizlilik|privatnost|privatnost|'
    r'politique-de-confidentialite|termini-e-condizioni|rodo|'
    r'privacy.?policy|legal.?notice|data.?protection)[^"\']*["\']',
    re.I
)

# Third-party tracking scripts that require consent under GDPR
_TRACKING_SCRIPTS = [
    (re.compile(r'google-analytics\.com/analytics\.js|googletagmanager\.com/gtag|gtag\(', re.I), "Google Analytics"),
    (re.compile(r'connect\.facebook\.net|fbq\(|facebook\.com/tr', re.I), "Facebook Pixel"),
    (re.compile(r'snap\.licdn\.com|linkedin\.com/insight', re.I), "LinkedIn Insight Tag"),
    (re.compile(r'static\.hotjar\.com|hj\(', re.I), "Hotjar"),
    (re.compile(r'cdn\.heapanalytics\.com|heap\.track', re.I), "Heap Analytics"),
    (re.compile(r'fullstory\.com/s/fs\.js|FullStory', re.I), "FullStory"),
    (re.compile(r'cdn\.segment\.com|analytics\.track\(', re.I), "Segment"),
    (re.compile(r'mc\.yandex\.ru|yaCounter', re.I), "Yandex Metrica"),
    (re.compile(r'clarity\.ms|microsoft.*clarity', re.I), "Microsoft Clarity"),
    (re.compile(r'bat\.bing\.com|uetq\.push', re.I), "Bing Universal Event Tracking"),
    (re.compile(r'ads\.twitter\.com|twq\(', re.I), "Twitter/X Pixel"),
    (re.compile(r'tiktok\.com/i18n/pixel', re.I), "TikTok Pixel"),
    (re.compile(r'cdn\.amplitude\.com|amplitude\.getInstance', re.I), "Amplitude"),
    (re.compile(r'mixpanel\.com/lib|mixpanel\.track', re.I), "Mixpanel"),
]


class GDPRPrivacyScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        try:
            resp = self.http.get(url)
        except Exception:
            return self.results
        if resp is None:
            return self.results

        html = resp.text or ""
        cookies_on_first_load = list(resp.cookies) if hasattr(resp, "cookies") else []

        self._check_consent_banner(url, html)
        self._check_privacy_policy(url, html)
        self._check_tracking_scripts(url, html)
        self._check_cookies_before_consent(url, resp)
        return self.results

    def _check_consent_banner(self, url: str, html: str) -> None:
        for pattern, name in _CMP_PATTERNS:
            if pattern.search(html):
                log_pass(logger, f"Cookie consent manager detected: {name}")
                self.results.append(self._result(url,
                    f"GDPR — cookie consent management platform detected ({name})",
                    "PASS",
                    detail=(
                        f"{name} consent management platform was detected in the page. "
                        f"Ensure it is correctly configured: categories must map to actual "
                        f"cookies/scripts, and analytics/marketing must not load until "
                        f"consent is granted."
                    )))
                return

        log_warn(logger, "No cookie consent management platform detected")
        self.results.append(self._result(url,
            "GDPR — no cookie consent banner detected",
            "WARN",
            detail=(
                "No known cookie consent management platform (OneTrust, Cookiebot, "
                "CookieYes, TrustArc, Osano, iubenda, etc.) was detected on the page. "
                "Under GDPR (Art. 7), PECR, and ePrivacy Directive, consent is required "
                "before setting non-essential cookies (analytics, marketing, preferences). "
                "Fix: implement a CMP or build your own consent gate that blocks tracking "
                "scripts until the user actively accepts."
            )))

    def _check_privacy_policy(self, url: str, html: str) -> None:
        if _PRIVACY_LINK_RE.search(html):
            log_pass(logger, "Privacy policy link found")
            self.results.append(self._result(url,
                "GDPR — privacy policy link present",
                "PASS",
                detail="A privacy policy link was found in the page HTML. "
                       "Ensure it is accessible from every page and covers required "
                       "disclosures: data controller identity, purposes, legal basis, "
                       "retention periods, data subject rights (Art. 13/14 GDPR)."))
        else:
            log_warn(logger, "No privacy policy link found")
            self.results.append(self._result(url,
                "GDPR — no privacy policy link detected",
                "WARN",
                detail=(
                    "No privacy policy link was found on the page. GDPR Art. 13 requires "
                    "a privacy notice to be provided at the point of data collection. "
                    "CCPA (Cal. Civ. Code §1798.100) requires a link in your site footer. "
                    "Fix: add a clearly labelled Privacy Policy link to your site header "
                    "or footer on every page."
                )))

    def _check_tracking_scripts(self, url: str, html: str) -> None:
        found = []
        for pattern, name in _TRACKING_SCRIPTS:
            if pattern.search(html):
                found.append(name)

        if not found:
            log_pass(logger, "No unconsented tracking scripts detected")
            self.results.append(self._result(url,
                "GDPR — no tracking scripts detected on first load",
                "PASS",
                detail="No known analytics or advertising tracking scripts were found "
                       "loading on the initial page load. If you use analytics, "
                       "confirm they are gated behind consent in your CMP configuration."))
        else:
            for name in found:
                log_warn(logger, f"Tracking script detected on first load: {name}")
                self.results.append(self._result(url,
                    f"GDPR — tracking script loaded on first load ({name})",
                    "WARN",
                    detail=(
                        f"{name} tracking script was detected in the page HTML on first load "
                        f"(before any user interaction). Under GDPR, analytics and marketing "
                        f"trackers require prior informed consent (Recital 32, Art. 7). "
                        f"Fix: move the {name} script load to inside your CMP's 'accepted' "
                        f"callback, so it only runs after the user clicks Accept."
                    )))

    def _check_cookies_before_consent(self, url: str, resp: Any) -> None:
        try:
            cookie_header = resp.headers.get("Set-Cookie", "")
        except Exception:
            return

        if not cookie_header:
            try:
                cookies = dict(resp.cookies)
                if not cookies:
                    return
                cookie_names = list(cookies.keys())
            except Exception:
                return
        else:
            # Extract cookie names from Set-Cookie header value
            cookie_names = [cookie_header.split("=")[0].strip()]

        # Filter out obviously session/security cookies
        _ESSENTIAL_RE = re.compile(
            r'^(csrf|xsrf|_session|laravel_session|rack\.session|'
            r'PHPSESSID|JSESSIONID|ASP\.NET_SessionId|__cf_bm|__cfduid|'
            r'_dd_s|cf_clearance)$',
            re.I
        )
        non_essential = [n for n in cookie_names if not _ESSENTIAL_RE.match(n)]

        if non_essential:
            log_warn(logger, f"Non-essential cookies set on first load: {non_essential}")
            self.results.append(self._result(url,
                "GDPR — cookies set on first load before consent",
                "WARN",
                detail=(
                    f"Cookies were set on the initial response before any consent interaction: "
                    f"{', '.join(non_essential[:5])}. "
                    f"Under GDPR/ePrivacy Directive, non-essential cookies (analytics, "
                    f"marketing, preferences) must not be set until the user grants consent. "
                    f"Fix: ensure non-essential cookies are only set after the CMP fires "
                    f"the consent event."
                )))
