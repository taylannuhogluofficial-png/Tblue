"""Broken Object Level Authorization scanner — passive detection of BOLA/IDOR patterns in API responses."""
import re
from .base import BaseScanner

_BOLA_ANY_RE = re.compile(
    r'(?:/api/|/v\d+/|userId|user_id|accountId|account_id|'
    r'recordId|record_id|objectId|object_id|'
    r'ownerId|owner_id)',
    re.I,
)

_BOLA_ID_IN_PATH_RE = re.compile(
    r'/(?:users?|accounts?|orders?|records?|documents?|files?|profiles?)'
    r'/\d{1,15}(?:[/?#]|$)',
    re.I,
)

_BOLA_SENSITIVE_DATA_IN_RESPONSE_RE = re.compile(
    r'"(?:password|secret|token|api_key|ssn|credit_card|card_number|'
    r'bank_account|social_security|private_key)"\s*:\s*"[^"]{1,200}"',
    re.I,
)

_BOLA_ALL_RECORDS_RE = re.compile(
    r'"(?:total|count|all_records|total_count)"\s*:\s*\d{3,}',
    re.I,
)

_BOLA_CROSS_USER_FIELD_RE = re.compile(
    r'"(?:user_?id|account_?id|owner_?id|created_?by)"\s*:\s*(?:\d+|"[^"]{1,50}")',
    re.I,
)

_BOLA_MISSING_AUTH_HEADER_RE = re.compile(
    r'(?:/api/|/v\d+/)(?:users?|accounts?|orders?)/\d+',
    re.I,
)


class BrokenObjectLevelAuthScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "bola_not_used", "PASS")]

        body = resp.text
        headers_str = ' '.join(f'{k}: {v}' for k, v in resp.headers.items())

        if not _BOLA_ANY_RE.search(url) and not _BOLA_ANY_RE.search(body):
            return [self._result(url, "bola_not_used", "PASS")]

        findings = []

        if _BOLA_ID_IN_PATH_RE.search(url):
            has_auth = bool(re.search(r'authorization\s*:', headers_str, re.I))
            if not has_auth:
                findings.append(self._result(
                    url, "bola_object_id_in_path_no_auth_header", "WARN",
                    detail="Numeric object ID in API path (/users/123, /orders/456) with no Authorization header observed — if the server doesn't verify object ownership per request, changing the ID grants access to other users' objects (BOLA/IDOR).",
                ))

        if _BOLA_SENSITIVE_DATA_IN_RESPONSE_RE.search(body):
            findings.append(self._result(
                url, "bola_sensitive_field_in_response", "FAIL",
                detail="Sensitive field (password, secret, token, SSN, credit card) found in JSON API response body — if this response is returned without per-object authorization check, BOLA gives any authenticated user access to all records.",
            ))

        if _BOLA_ALL_RECORDS_RE.search(body) and _BOLA_ID_IN_PATH_RE.search(url):
            findings.append(self._result(
                url, "bola_mass_enumeration_indicator", "WARN",
                detail="API response includes total/count field with 3+ digit count alongside object-ID path — suggests a listing endpoint that may return all records without ownership filtering; enumerate IDs from 1 to total.",
            ))

        if _BOLA_CROSS_USER_FIELD_RE.search(body):
            findings.append(self._result(
                url, "bola_cross_user_id_exposed", "WARN",
                detail="API response includes user_id, account_id, or owner_id of another entity — if this ID can be substituted in the request path, the endpoint is likely vulnerable to BOLA (object-level authorization bypass).",
            ))

        return findings or [self._result(url, "bola_safe", "PASS")]
