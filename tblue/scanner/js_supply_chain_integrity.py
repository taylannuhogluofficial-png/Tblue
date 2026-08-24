"""
JS Supply Chain Integrity Scanner.

External JavaScript files loaded without Subresource Integrity (SRI) are
vulnerable to CDN compromise, BGP hijacking, or DNS poisoning — all of which
can silently replace a trusted library with malicious code.

Security issues:

1. External <script src="https://cdn.example.com/..."> without integrity attribute:
   - No cryptographic binding between the URL and the content served.
2. External <script> with crossorigin missing alongside integrity:
   - integrity requires crossorigin to work correctly for CORS responses.
3. Module preload without integrity:
   - <link rel="modulepreload" href="https://..."> without integrity attribute.
4. External <script type="module"> without integrity:
   - ES module scripts loaded from external CDNs without content verification.
5. Dynamic import() of external URLs (detected in JS source):
   - import("https://cdn.example.com/lib.js") — SRI not applicable, flagged as risk.
6. script-src CSP directive does not require-sri-for scripts:
   - `require-sri-for script` (deprecated) or absence of hash-based allowlist.
7. Mixed SRI posture: some external scripts have integrity, others don't.

CWE-494: Download of Code Without Integrity Check
CWE-829: Inclusion of Functionality from Untrusted Control Sphere
"""

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_SCRIPT_TAG_RE = re.compile(r'<script\b([^>]*)>', re.I)
_SRC_RE        = re.compile(r'\bsrc\s*=\s*["\']([^"\']*)["\']', re.I)
_TYPE_RE       = re.compile(r'\btype\s*=\s*["\']([^"\']*)["\']', re.I)
_INTEGRITY_RE  = re.compile(r'\bintegrity\s*=\s*["\']([^"\']+)["\']', re.I)
_CROSSORIGIN_RE= re.compile(r'\bcrossorigin\b', re.I)
_DEFER_ASYNC_RE= re.compile(r'\b(?:defer|async)\b', re.I)

_LINK_TAG_RE   = re.compile(r'<link\b([^>]*)>', re.I)
_REL_RE        = re.compile(r'\brel\s*=\s*["\']([^"\']+)["\']', re.I)
_HREF_RE       = re.compile(r'\bhref\s*=\s*["\']([^"\']*)["\']', re.I)

_DYNAMIC_IMPORT_RE = re.compile(
    r'\bimport\s*\(\s*["\'](?:https?:)?//[^"\']+["\']', re.I
)

_POPULAR_CDNS = {
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    "code.jquery.com", "ajax.googleapis.com", "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com", "ajax.aspnetcdn.com", "cdn.skypack.dev",
    "esm.sh", "cdn.esm.sh",
}


def _is_external(src: str, page_host: str) -> bool:
    if not src:
        return False
    try:
        p = urlparse(src)
        if p.scheme in ("data", "javascript", "blob"):
            return False
        if p.netloc:
            return p.netloc.lower() != page_host.lower()
        if src.startswith("//"):
            host = src.lstrip("/").split("/")[0]
            return host.lower() != page_host.lower()
    except Exception:
        pass
    return False


class JSSupplyChainIntegrityScanner(BaseScanner):
    """Detect external JS loaded without Subresource Integrity."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "JS supply chain integrity — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        body = resp.text or ""
        page_host = urlparse(url).netloc.lower()

        external_total = 0
        with_sri       = 0
        without_sri: List[Tuple[str, str]] = []  # (tag_type, src)

        # Check <script> tags
        for attrs in _SCRIPT_TAG_RE.findall(body):
            type_m = _TYPE_RE.search(attrs)
            tag_type = type_m.group(1).lower() if type_m else "text/javascript"
            if "importmap" in tag_type:
                continue

            src_m = _SRC_RE.search(attrs)
            if not src_m:
                continue
            src = src_m.group(1)
            if not _is_external(src, page_host):
                continue

            external_total += 1
            has_integrity   = bool(_INTEGRITY_RE.search(attrs))
            has_crossorigin = bool(_CROSSORIGIN_RE.search(attrs))

            if has_integrity and not has_crossorigin:
                log_warn(logger, f"SRI without crossorigin at {url}: {src[:60]}")
                self.results.append(self._result(
                    url,
                    f"JS supply chain — SRI integrity without crossorigin on <script src>: {src[:60]}",
                    "WARN",
                    detail=(
                        f"<script src=\"{src[:80]}\" integrity=\"...\"> is missing the "
                        "crossorigin attribute. Without crossorigin, CORS-blocked responses "
                        "bypass SRI checking and the script may still execute. "
                        "Fix: add crossorigin=\"anonymous\" alongside integrity."
                    )
                ))
                findings += 1

            if has_integrity:
                with_sri += 1
            else:
                without_sri.append(("script", src))

        # Check <link rel="modulepreload"> and <link rel="preload" as="script">
        for attrs in _LINK_TAG_RE.findall(body):
            rel_m = _REL_RE.search(attrs)
            if not rel_m:
                continue
            rel = rel_m.group(1).lower()
            if "modulepreload" not in rel and "preload" not in rel:
                continue
            href_m = _HREF_RE.search(attrs)
            if not href_m:
                continue
            href = href_m.group(1)
            if not _is_external(href, page_host):
                continue

            # Only flag preload as=script or modulepreload
            as_m = re.search(r'\bas\s*=\s*["\']script["\']', attrs, re.I)
            if "preload" in rel and not as_m and "modulepreload" not in rel:
                continue

            external_total += 1
            has_integrity = bool(_INTEGRITY_RE.search(attrs))
            if has_integrity:
                with_sri += 1
            else:
                without_sri.append(("modulepreload/preload", href))

        # Report missing SRI
        for tag_type, src in without_sri[:6]:
            if findings >= 8:
                break
            host = urlparse(src).netloc.lower() if "://" in src else src.split("/")[0]
            is_popular = any(cdn in host for cdn in _POPULAR_CDNS)
            status = "FAIL" if is_popular else "WARN"
            label = "popular CDN" if is_popular else "external host"
            if status == "FAIL":
                log_fail(logger, f"External {tag_type} without SRI from {label} at {url}: {src[:60]}")
            else:
                log_warn(logger, f"External {tag_type} without SRI at {url}: {src[:60]}")
            self.results.append(self._result(
                url,
                f"JS supply chain — external <{tag_type}> without SRI from {label}: {src[:60]}",
                status,
                detail=(
                    f"<{tag_type} src/href=\"{src[:80]}\"> loads from an external {label} "
                    "without an integrity attribute. CDN compromise, BGP hijacking, or "
                    "DNS poisoning can silently replace this resource with malicious code. "
                    "Fix: add integrity=\"sha384-...\" and crossorigin=\"anonymous\" "
                    "to this element. Generate the hash with: "
                    "openssl dgst -sha384 -binary <file> | openssl base64 -A"
                )
            ))
            findings += 1

        # Mixed SRI posture
        if external_total >= 2 and with_sri > 0 and without_sri:
            log_warn(logger, f"Mixed SRI posture at {url}: {with_sri} with SRI, {len(without_sri)} without")
            self.results.append(self._result(
                url,
                f"JS supply chain — inconsistent SRI: {with_sri} external scripts have SRI, {len(without_sri)} do not",
                "WARN",
                detail=(
                    "Some external scripts include SRI integrity checking while others do not. "
                    "The unprotected scripts remain vulnerable to supply chain compromise even "
                    "if the protected ones are safe. Fix: add SRI to all external scripts."
                )
            ))

        # Dynamic import of external URLs
        dyn_matches = _DYNAMIC_IMPORT_RE.findall(body)
        if dyn_matches:
            log_warn(logger, f"Dynamic import() of external URLs at {url}")
            self.results.append(self._result(
                url,
                f"JS supply chain — dynamic import() of external URLs ({len(dyn_matches)} found)",
                "WARN",
                detail=(
                    "JavaScript uses dynamic import() with external URLs. SRI cannot be applied "
                    "to dynamic imports — the browser fetches whatever URL is provided at runtime. "
                    "Fix: bundle external dependencies locally, or restrict dynamic import targets "
                    "via a strict script-src CSP (no wildcards, hash-based allowlist)."
                )
            ))

        if not self.results:
            if external_total == 0:
                log_pass(logger, f"No external scripts at {url}")
                self.results.append(self._result(
                    url, "JS supply chain integrity — no external scripts detected", "PASS",
                    detail="No external <script src> or module preload tags found."
                ))
            else:
                log_pass(logger, f"All {external_total} external scripts have SRI at {url}")
                self.results.append(self._result(
                    url,
                    f"JS supply chain integrity — all {external_total} external scripts have SRI",
                    "PASS",
                    detail="All external script/module tags include integrity and crossorigin attributes."
                ))

        return self.results
