"""
ETag Fingerprinting Scanner.

ETag (Entity Tag) headers are used for HTTP caching but can inadvertently
expose internal implementation details:

  1. Apache httpd (pre-2.4) generated ETags as inode:size:mtime — this leaks
     the filesystem inode number, which can enable inode-based SSRF on some
     configurations and reveals that a specific file hasn't changed since a
     specific time.

  2. Sequential numeric ETags reveal how many resources exist and change
     frequency, enabling enumeration.

  3. ETags that look like UUIDs may reveal internal object/document IDs that
     are otherwise not exposed through the API surface.

  4. ETags identical across different resources indicate the application
     uses a global counter/hash rather than per-resource tracking — both
     a correctness bug and an information leak.

  5. ETags with user-specific values (session tokens embedded) can allow
     session fixation or cache-key poisoning attacks.

This scanner:
  - Fetches 3+ responses and analyzes ETag values
  - Detects Apache-style inode:size:mtime pattern (hex triplet)
  - Detects sequential numeric patterns
  - Detects ETags that are identical across semantically different URLs
  - Checks ETag disclosure on 404 responses (common mistake)

CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
"""

import re
from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

# Apache mod_negotiation style: "inode-size-mtime" all hex
_APACHE_ETAG_RE = re.compile(r'^"?([0-9a-f]+)-([0-9a-f]+)-([0-9a-f]+)"?$', re.I)

# Sequential numeric ETag (just digits, possibly with quotes)
_NUMERIC_ETAG_RE = re.compile(r'^"?(\d+)"?$')

# UUID-like ETag
_UUID_ETAG_RE = re.compile(r'^"?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"?$', re.I)

# Weak ETag prefix
_WEAK_ETAG_RE = re.compile(r'^W/"', re.I)

_PROBE_PATHS = [
    "",       # root
    "/robots.txt",
    "/favicon.ico",
    "/sitemap.xml",
    "/this-does-not-exist-tbl9z7x",  # 404 path
]


def _normalize_etag(etag: str) -> str:
    """Strip W/ prefix and quotes for comparison."""
    return re.sub(r'^W/', '', etag).strip('"')


class ETagFingerprintingScanner(BaseScanner):
    """Analyzes ETag headers for information disclosure and fingerprinting risks."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        base = url.rstrip("/")
        etags_seen: Dict[str, str] = {}  # path → normalized_etag

        for path in _PROBE_PATHS:
            probe_url = base + path if path else url
            resp = self.http.get(probe_url)
            if resp is None:
                continue

            etag_raw = (resp.headers or {}).get("etag", "") or \
                       (resp.headers or {}).get("ETag", "") or ""
            if not etag_raw:
                continue

            etag_raw = etag_raw.strip()
            normalized = _normalize_etag(etag_raw)
            status_code = resp.status_code

            logger.info(f"ETag: {probe_url} → {etag_raw!r} (HTTP {status_code})")
            etags_seen[probe_url] = normalized

            self._analyze_etag(url, probe_url, etag_raw, normalized, status_code)

        # Cross-URL analysis: same ETag on different paths
        if len(etags_seen) >= 2:
            self._check_cross_url_duplicates(url, etags_seen)

        if not self.results:
            if not etags_seen:
                log_pass(logger, f"ETag Fingerprinting — no ETag headers found on {url}")
                self.results.append(self._result(
                    url, "ETag Fingerprinting — no ETag headers present", "PASS",
                    detail="No ETag headers were returned on any probed URL. "
                           "ETags are optional and their absence is fine from a security standpoint."))
            else:
                log_pass(logger, "ETag Fingerprinting — no fingerprinting patterns detected")
                sample = list(etags_seen.values())[0]
                self.results.append(self._result(
                    url,
                    "ETag Fingerprinting — ETags present but no fingerprinting patterns detected",
                    "PASS",
                    detail=(
                        f"ETag headers are present but do not appear to follow Apache inode "
                        f"format, sequential numbering, or other fingerprinting patterns.\n"
                        f"Example ETag: {sample!r}"
                    ),
                ))

        return self.results

    def _analyze_etag(
        self, page_url: str, probe_url: str, etag_raw: str, normalized: str, status: int
    ) -> None:
        # Apache inode:size:mtime pattern
        m = _APACHE_ETAG_RE.match(normalized)
        if m and not _UUID_ETAG_RE.match(normalized):
            inode_hex, size_hex, mtime_hex = m.group(1), m.group(2), m.group(3)
            log_warn(logger, f"ETag Fingerprinting — Apache inode-based ETag at {probe_url}: {etag_raw!r}")
            self.results.append(self._result(
                page_url,
                "ETag Fingerprinting — Apache inode-based ETag leaks filesystem metadata",
                "WARN",
                detail=(
                    f"ETag: {etag_raw}\n\n"
                    f"This ETag follows the Apache httpd format: inode-size-mtime (all hex).\n"
                    f"  Inode: 0x{inode_hex} = {int(inode_hex, 16)}\n"
                    f"  Size: 0x{size_hex} = {int(size_hex, 16)} bytes\n"
                    f"  Mtime: 0x{mtime_hex}\n\n"
                    f"The inode number can be used in inode-based file descriptor attacks "
                    f"on some server configurations. The modification time reveals when the "
                    f"file was last changed, enabling targeted cache invalidation by attackers.\n\n"
                    f"Fix: Disable inode-based ETags in Apache:\n"
                    f"  FileETag MTime Size\n"
                    f"Or configure a different ETag strategy in nginx/other servers."
                ),
            ))

        # Sequential numeric ETag
        elif _NUMERIC_ETAG_RE.match(normalized):
            log_warn(logger, f"ETag Fingerprinting — sequential numeric ETag: {etag_raw!r}")
            self.results.append(self._result(
                page_url,
                "ETag Fingerprinting — sequential numeric ETag reveals resource counter",
                "WARN",
                detail=(
                    f"ETag: {etag_raw}\n\n"
                    f"This ETag is a plain integer. Sequential numeric ETags reveal:\n"
                    f"  - The total number of tracked resources\n"
                    f"  - Whether content has changed (attacker can poll)\n"
                    f"  - How frequently resources change\n\n"
                    f"Fix: Use a hash-based ETag (e.g., SHA-256 of content) rather than "
                    f"a sequential counter."
                ),
            ))

        # ETag on 404 response (information leak about 404 handling)
        if status == 404 and normalized:
            log_warn(logger, f"ETag Fingerprinting — ETag present on 404 response: {probe_url}")
            self.results.append(self._result(
                page_url,
                "ETag Fingerprinting — ETag header present on 404 Not Found response",
                "WARN",
                detail=(
                    f"The server returns an ETag header on 404 responses.\n"
                    f"URL: {probe_url}\n"
                    f"ETag: {etag_raw}\n\n"
                    f"404 responses with ETags indicate the server is tracking error page "
                    f"versions. In some frameworks, this reveals the error template's "
                    f"modification time or an internal cache key."
                ),
            ))

    def _check_cross_url_duplicates(self, page_url: str, etags: Dict[str, str]) -> None:
        """Check if different paths return identical ETags (global hash or wrong implementation)."""
        # Exclude the 404 path from this check
        real_paths = {k: v for k, v in etags.items()
                      if "tbl9z7x" not in k and v}
        if len(real_paths) < 2:
            return

        values = list(real_paths.values())
        urls = list(real_paths.keys())

        # Find duplicates
        for i in range(len(values)):
            for j in range(i + 1, len(values)):
                if values[i] == values[j] and values[i]:
                    log_warn(logger, f"ETag Fingerprinting — identical ETags on different paths: {urls[i]} and {urls[j]}")
                    self.results.append(self._result(
                        page_url,
                        "ETag Fingerprinting — identical ETags on different resources",
                        "WARN",
                        detail=(
                            f"These semantically different URLs return the same ETag value:\n"
                            f"  {urls[i]}\n"
                            f"  {urls[j]}\n"
                            f"  ETag: {values[i]!r}\n\n"
                            f"This indicates the application uses a global hash or counter "
                            f"rather than per-resource ETags. Caching will break (clients "
                            f"will incorrectly assume resources are the same content), and "
                            f"it may reveal that the same backing store serves both paths."
                        ),
                    ))
                    return  # Report at most one duplicate pair
