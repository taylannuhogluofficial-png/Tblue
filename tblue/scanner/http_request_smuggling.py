"""HTTP Request Smuggling scanner — passive detection of desync/smuggling indicators."""
import re
from .base import BaseScanner

_HRS_ANY_RE = re.compile(
    r'(?:Transfer-Encoding\b|Content-Length\b|'
    r'chunked\b|keep-alive\b|'
    r'HTTP/1\.1\b|Connection\s*:\s*keep-alive)',
    re.I,
)

_HRS_DOUBLE_ENCODING_RE = re.compile(
    r'Transfer-Encoding\b[^;]{0,300}'
    r'(?:chunked[^;]{0,200}Content-Length\b|'
    r'Content-Length\b[^;]{0,200}Transfer-Encoding\b)',
    re.I,
)

_HRS_OBFUSCATED_TE_RE = re.compile(
    r'Transfer-Encoding\s*:\s*["\']?\s*(?:identity\s*,\s*chunked|'
    r'chunked\s*,\s*identity|xchunked|'
    r'Transfer-Encoding\s*:\s*chunked\s*\x00)',
    re.I,
)

_HRS_FRONTEND_PROXY_MISMATCH_RE = re.compile(
    r'(?:X-Forwarded-For\b[^;]{0,300}Transfer-Encoding\b|'
    r'Via\b[^;]{0,300}Transfer-Encoding\b)',
    re.I,
)

_HRS_CONTENT_LENGTH_MISMATCH_RE = re.compile(
    r'Content-Length\s*:\s*(\d+)[^;]{0,300}'
    r'Content-Length\s*:\s*(\d+)',
    re.I,
)


class HTTPRequestSmugglingScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "http_smuggling_not_used", "PASS")]

        body = resp.text
        headers_str = str(resp.headers)
        combined = headers_str + "\n" + body

        if not _HRS_ANY_RE.search(combined):
            return [self._result(url, "http_smuggling_not_used", "PASS")]

        findings = []

        if _HRS_DOUBLE_ENCODING_RE.search(combined):
            findings.append(self._result(
                url, "http_smuggling_te_cl_conflict", "FAIL",
                detail="Both Transfer-Encoding and Content-Length headers present — TE/CL or CL/TE conflict enables HTTP request smuggling between frontend proxy and backend server.",
            ))

        if _HRS_OBFUSCATED_TE_RE.search(combined):
            findings.append(self._result(
                url, "http_smuggling_obfuscated_te", "FAIL",
                detail="Transfer-Encoding: xchunked or identity,chunked in response — obfuscated TE header exploits parser discrepancies between frontend/backend to smuggle requests.",
            ))

        if _HRS_FRONTEND_PROXY_MISMATCH_RE.search(combined):
            findings.append(self._result(
                url, "http_smuggling_proxy_te_mismatch", "WARN",
                detail="X-Forwarded-For/Via proxy headers combined with Transfer-Encoding — proxy-behind-server topology with TE headers suggests potential TE.CL desync attack surface.",
            ))

        if _HRS_CONTENT_LENGTH_MISMATCH_RE.search(combined):
            findings.append(self._result(
                url, "http_smuggling_duplicate_content_length", "WARN",
                detail="Duplicate Content-Length headers in response — conflicting Content-Length values exploited in CL.CL smuggling attacks to poison request boundaries.",
            ))

        return findings or [self._result(url, "http_smuggling_safe", "PASS")]
