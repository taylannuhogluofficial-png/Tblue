"""Timing Attack Passive scanner — passive detection of timing oracle and timing side-channel indicators."""
import re
from .base import BaseScanner

_TA_ANY_RE = re.compile(
    r'(?:hmac|digest|compare|bcrypt|pbkdf2|scrypt|argon2|'
    r'timing|constant.time|safe.compare|'
    r'crypto\.createHmac|hashlib|'
    r'token\s*===|secret\s*===|hash\s*===|signature\s*===|'
    r'\.equals\s*\(|strcmp\s*\()',
    re.I,
)

_TA_NAIVE_COMPARE_RE = re.compile(
    r'(?:token\s*===\s*|password\s*===\s*|secret\s*===\s*|'
    r'hash\s*===\s*|signature\s*===\s*|apikey\s*===\s*)',
    re.I,
)

_TA_STRING_COMPARE_RE = re.compile(
    r'(?:\.equals\s*\(\s*[^)]{0,50}(?:token|password|secret|hash|signature)|'
    r'(?:token|password|secret|hash|signature)[^.]{0,50}\.equals\s*\(|'
    r'strcmp\s*\(\s*\$(?:token|password|secret|hash)|'
    r'str\.compare\s*\()',
    re.I,
)

_TA_EARLY_RETURN_RE = re.compile(
    r'if\s*\(\s*(?:token|password|secret|apiKey)\s*(?:!==|!=|===|==)\s*'
    r'[^)]{1,200}\)\s*(?:return|throw|res\.send)',
    re.I,
)

_TA_HMAC_WITHOUT_CONSTANT_RE = re.compile(
    r'(?:crypto\.createHmac|hmac\.new|hashlib\.new)\s*\([^;]{0,200}'
    r'(?:\.digest|\.hexdigest)',
    re.I,
)

_TA_SLEEP_IN_AUTH_RE = re.compile(
    r'(?:setTimeout|sleep|time\.sleep)\s*\([^)]{0,100}\)'
    r'[^;]{0,200}(?:token|password|login|auth)',
    re.I,
)

_TA_RESPONSE_TIME_DISCLOSURE_RE = re.compile(
    r'(?:X-Response-Time|X-Runtime|X-Request-Duration)\s*:\s*\d',
    re.I,
)


class TimingAttackPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "timing_attack_not_used", "PASS")]

        body = resp.text
        headers_str = ' '.join(f'{k}: {v}' for k, v in resp.headers.items())

        if not _TA_ANY_RE.search(body) and not _TA_ANY_RE.search(headers_str):
            return [self._result(url, "timing_attack_not_used", "PASS")]

        findings = []

        if _TA_NAIVE_COMPARE_RE.search(body):
            findings.append(self._result(
                url, "timing_attack_naive_equality_compare", "FAIL",
                detail="Direct equality comparison (===, ==) on token/password/secret — JavaScript string comparison short-circuits on first differing character; timing difference reveals how many leading characters match, enabling character-by-character brute force of secrets.",
            ))

        if _TA_STRING_COMPARE_RE.search(body):
            findings.append(self._result(
                url, "timing_attack_string_compare", "FAIL",
                detail=".equals() or strcmp() on token/password/secret — these functions are not constant-time; network-measurable timing differences allow offline oracle attacks against HMAC tokens and API keys.",
            ))

        if _TA_EARLY_RETURN_RE.search(body):
            findings.append(self._result(
                url, "timing_attack_early_return_on_mismatch", "WARN",
                detail="Early return/throw on credential mismatch — function exits faster on wrong credentials than on correct; timing difference reveals whether submitted credential prefix matched, reducing brute-force search space.",
            ))

        if _TA_RESPONSE_TIME_DISCLOSURE_RE.search(headers_str):
            findings.append(self._result(
                url, "timing_attack_response_time_header", "WARN",
                detail="X-Response-Time or X-Runtime header discloses server-side processing time — per-request timing data enables statistical timing oracle attacks; attackers average many requests to detect microsecond differences in credential validation.",
            ))

        return findings or [self._result(url, "timing_attack_safe", "PASS")]
