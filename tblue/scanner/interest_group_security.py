"""Protected Audience (FLEDGE) interest group security scanner — passive ad profiling detection."""
import re
from .base import BaseScanner

_IG_ANY_RE = re.compile(
    r'(?:joinAdInterestGroup\b|leaveAdInterestGroup\b|runAdAuction\b|InterestGroup\b|adInterestGroup)',
    re.I,
)

_IG_PII_IN_GROUP_RE = re.compile(
    r'joinAdInterestGroup\s*\([^)]*(?:email|userId|phone|name|account)[^)]*\)',
    re.I,
)

_IG_GROUP_NAME_FROM_PARAM_RE = re.compile(
    r'joinAdInterestGroup\s*\([^)]*(?:searchParams|location\.hash)[^)]*\)',
    re.I,
)

_IG_BIDDING_FROM_PARAM_RE = re.compile(
    r'biddingLogicURL\s*:[^;]{0,100}(?:searchParams|location\.hash)',
    re.I,
)

_IG_AUCTION_EXFIL_RE = re.compile(
    r'runAdAuction\s*\([^)]*\)[^;]{0,200}(?:fetch|sendBeacon|analytics)',
    re.I,
)


class InterestGroupSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "interest_group_not_used", "PASS")]

        body = resp.text

        if not _IG_ANY_RE.search(body):
            return [self._result(url, "interest_group_not_used", "PASS")]

        findings = []

        if _IG_PII_IN_GROUP_RE.search(body):
            findings.append(self._result(
                url, "interest_group_pii_in_membership", "FAIL",
                detail="joinAdInterestGroup() includes PII (email/userId) — user identification in ad targeting data.",
            ))

        if _IG_GROUP_NAME_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "interest_group_name_from_url_param", "WARN",
                detail="Interest group name sourced from URL parameter — attacker-controlled ad targeting group membership.",
            ))

        if _IG_BIDDING_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "interest_group_bidding_url_from_param", "FAIL",
                detail="biddingLogicURL sourced from URL parameter — attacker-controlled bidding script injection.",
            ))

        if _IG_AUCTION_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "interest_group_auction_result_exfil", "WARN",
                detail="runAdAuction() result transmitted to external endpoint — ad auction outcome surveillance.",
            ))

        return findings or [self._result(url, "interest_group_safe", "PASS")]
