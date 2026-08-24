"""
Privacy Sandbox API Security Scanner.

Google's Privacy Sandbox is a set of browser APIs meant to replace third-party
cookies. From a blue-team perspective, these APIs can expose user tracking
infrastructure, reveal ad-tech data flows, and indicate compliance risks:

1. Topics API (`document.browsingTopics()`):
   - `Sec-Browsing-Topics` request header sent when Topics API is active
   - `Observe-Browsing-Topics: ?1` response header enables topic collection
   - Sites that observe browsing topics collect cross-site interest categories
2. Attribution Reporting API:
   - `Attribution-Reporting-Register-Source` response header registers ad impressions
   - `Attribution-Reporting-Register-Trigger` registers ad conversions
   - `Attribution-Reporting-Eligible` request header indicates API availability
3. Privacy Budget (deprecated but headers may linger):
   - `Sec-Privacy-Budget-Metadata` — fingerprinting budget tracking
4. Fenced Frames / FLEDGE / Protected Audience API:
   - `Sec-Auction-Result` — indicates Protected Audience API participation
5. Shared Storage:
   - `Shared-Storage-Write` response header enables writing to shared storage
   - `Sec-Shared-Storage-Data-Origin` request header
6. Private State Tokens (formerly Trust Tokens):
   - `Sec-Private-State-Token` request header indicates redemption
   - `Private-State-Token` response header issues tokens

These APIs have privacy implications for users and compliance implications
under GDPR/CCPA — consent may be required before engaging these APIs.

CWE-359: Exposure of Private Personal Information to Unauthorized Actor
"""

import re
from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_TOPICS_OBSERVE_RE         = re.compile(r'observe-browsing-topics', re.I)
_ATTRIBUTION_SOURCE_RE     = re.compile(r'attribution-reporting-register-source', re.I)
_ATTRIBUTION_TRIGGER_RE    = re.compile(r'attribution-reporting-register-trigger', re.I)
_SHARED_STORAGE_WRITE_RE   = re.compile(r'shared-storage-write', re.I)
_PRIVATE_STATE_TOKEN_RE    = re.compile(r'private-state-token', re.I)
_FLEDGE_AUCTION_RE         = re.compile(r'sec-auction-result|ad-auction-result', re.I)
_INTEREST_GROUP_JOIN_JS_RE = re.compile(
    r'navigator\.joinAdInterestGroup\s*\(',
    re.I
)
_TOPICS_JS_RE              = re.compile(r'document\.browsingTopics\s*\(', re.I)
_SHARED_STORAGE_JS_RE      = re.compile(r'window\.sharedStorage\s*\.', re.I)

_PRIVACY_BUDGET_RE = re.compile(r'privacy-budget', re.I)


class PrivacySandboxAPIsScanner(BaseScanner):
    """Detect Privacy Sandbox API usage and associated compliance risks."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "Privacy Sandbox APIs — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        body = resp.text or ""
        h    = resp.headers

        self._check_topics_api(url, h, body)
        self._check_attribution_reporting(url, h)
        self._check_shared_storage(url, h, body)
        self._check_private_state_tokens(url, h)
        self._check_fledge(url, h, body)

        if not self.results:
            log_pass(logger, f"No Privacy Sandbox API usage at {url}")
            self.results.append(self._result(
                url, "Privacy Sandbox APIs — no Privacy Sandbox API usage detected", "PASS",
                detail=(
                    "No Topics API, Attribution Reporting, Shared Storage, Private State Tokens, "
                    "or FLEDGE/Protected Audience API indicators found in headers or page source."
                )
            ))

        return self.results

    def _check_topics_api(self, url: str, h, body: str) -> None:
        observe = h.get("observe-browsing-topics", "")
        if observe and observe.strip() == "?1":
            log_warn(logger, f"Topics API observation active at {url}")
            self.results.append(self._result(
                url,
                "Privacy Sandbox — Topics API: Observe-Browsing-Topics: ?1",
                "WARN",
                detail=(
                    "The response header 'Observe-Browsing-Topics: ?1' enables the browser "
                    "to record this page as a topic observation for the user. This means the "
                    "site is actively participating in Chrome's Topics API interest tracking. "
                    "Under GDPR/CCPA, user consent may be required before collecting browsing "
                    "topics. Fix: only set Observe-Browsing-Topics after explicit user consent."
                )
            ))

        if _TOPICS_JS_RE.search(body):
            log_warn(logger, f"document.browsingTopics() in page source at {url}")
            self.results.append(self._result(
                url,
                "Privacy Sandbox — Topics API: document.browsingTopics() in page source",
                "WARN",
                detail=(
                    "The page calls document.browsingTopics(), reading the user's interest "
                    "categories from Chrome's Topics API. These categories represent inferred "
                    "browsing history. Ensure this usage complies with privacy regulations "
                    "and that consent is obtained before accessing Topics."
                )
            ))

    def _check_attribution_reporting(self, url: str, h) -> None:
        if _ATTRIBUTION_SOURCE_RE.search(str(list(h.keys()))):
            source_val = h.get("attribution-reporting-register-source", "")
            log_warn(logger, f"Attribution Reporting source registration at {url}")
            self.results.append(self._result(
                url,
                "Privacy Sandbox — Attribution Reporting: impression source registered",
                "WARN",
                detail=(
                    f"Response header 'Attribution-Reporting-Register-Source' is present: "
                    f"'{source_val[:120]}'. This registers this page/resource as an ad "
                    "impression source for the Attribution Reporting API, enabling cross-site "
                    "attribution without third-party cookies. Verify this is intentional ad "
                    "infrastructure and that GDPR consent covers attribution reporting."
                )
            ))

        if _ATTRIBUTION_TRIGGER_RE.search(str(list(h.keys()))):
            log_warn(logger, f"Attribution Reporting trigger registration at {url}")
            self.results.append(self._result(
                url,
                "Privacy Sandbox — Attribution Reporting: conversion trigger registered",
                "WARN",
                detail=(
                    "Response header 'Attribution-Reporting-Register-Trigger' is present. "
                    "This registers a conversion event for the Attribution Reporting API. "
                    "Ensure conversion reporting is covered by your privacy consent flows."
                )
            ))

    def _check_shared_storage(self, url: str, h, body: str) -> None:
        sw_header = ""
        for k in h.keys() if hasattr(h, "keys") else []:
            if k.lower() == "shared-storage-write":
                sw_header = h.get(k, "")
                break

        if sw_header:
            log_warn(logger, f"Shared Storage write at {url}")
            self.results.append(self._result(
                url,
                "Privacy Sandbox — Shared Storage: Shared-Storage-Write header present",
                "WARN",
                detail=(
                    f"Response header 'Shared-Storage-Write' is present: '{sw_header[:120]}'. "
                    "This writes data to Shared Storage, a Privacy Sandbox API that allows "
                    "cross-site data persistence without third-party cookies. Data stored here "
                    "can be read across sites via worklets. Ensure consent is obtained before "
                    "writing to Shared Storage."
                )
            ))

        if _SHARED_STORAGE_JS_RE.search(body):
            log_warn(logger, f"Shared Storage API used in JS at {url}")
            self.results.append(self._result(
                url,
                "Privacy Sandbox — Shared Storage: window.sharedStorage used in page source",
                "WARN",
                detail=(
                    "The page uses window.sharedStorage, the Shared Storage API. "
                    "This enables cross-site data persistence. Audit whether the data "
                    "written/read contains PII or behavioral data requiring consent."
                )
            ))

    def _check_private_state_tokens(self, url: str, h) -> None:
        for k in h.keys() if hasattr(h, "keys") else []:
            if k.lower() == "private-state-token":
                pst = h.get(k, "")
                log_warn(logger, f"Private State Token issued at {url}")
                self.results.append(self._result(
                    url,
                    "Privacy Sandbox — Private State Tokens: token issuance header present",
                    "WARN",
                    detail=(
                        f"Response header 'Private-State-Token' is present: '{pst[:120]}'. "
                        "This issues a cryptographic trust token to the browser for anti-fraud "
                        "purposes. While less privacy-invasive than cookies, PST issuance "
                        "represents a cross-site tracking infrastructure — document in your "
                        "privacy policy and obtain consent where required."
                    )
                ))
                break

    def _check_fledge(self, url: str, h, body: str) -> None:
        for k in h.keys() if hasattr(h, "keys") else []:
            if k.lower() in ("sec-auction-result", "ad-auction-result"):
                log_warn(logger, f"Protected Audience API auction result at {url}")
                self.results.append(self._result(
                    url,
                    "Privacy Sandbox — Protected Audience (FLEDGE): auction result header",
                    "WARN",
                    detail=(
                        "A Protected Audience API (formerly FLEDGE) auction result header "
                        "is present. This indicates the page is participating in on-device "
                        "ad auctions. Ensure this is intentional ad infrastructure and is "
                        "disclosed in privacy documentation."
                    )
                ))
                break

        if _INTEREST_GROUP_JOIN_JS_RE.search(body):
            log_warn(logger, f"navigator.joinAdInterestGroup() in JS at {url}")
            self.results.append(self._result(
                url,
                "Privacy Sandbox — Protected Audience: navigator.joinAdInterestGroup() in source",
                "WARN",
                detail=(
                    "The page calls navigator.joinAdInterestGroup(), adding the user to an "
                    "interest group for the Protected Audience API. This enables cross-site "
                    "behavioral targeting. Under GDPR, adding users to interest groups "
                    "may require explicit consent."
                )
            ))
