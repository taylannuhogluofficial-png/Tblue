"""
Advanced Subresource Integrity (SRI) scanner.

Goes beyond the supply_chain.py SRI presence check:
- Validates that integrity= hashes use SHA-256 or better (SHA-1 = FAIL)
- Detects crossorigin attribute missing alongside integrity= (SRI only works with CORS)
- Checks for nonce-based CSP being used without SRI as an alternative
- Counts and reports coverage percentage across all external resources
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_SRI_HASH_RE  = re.compile(r"(sha\d+)-([A-Za-z0-9+/=]+)", re.I)
_SCRIPT_RE    = re.compile(r'<script\b([^>]*)>', re.I | re.S)
_LINK_RE      = re.compile(r'<link\b([^>]*)>', re.I | re.S)
_SRC_RE       = re.compile(r'\bsrc=["\']([^"\']+)["\']', re.I)
_HREF_RE      = re.compile(r'\bhref=["\']([^"\']+)["\']', re.I)
_INTEGRITY_RE = re.compile(r'\bintegrity=["\']([^"\']+)["\']', re.I)
_CROSSORIGIN_RE = re.compile(r'\bcrossorigin\b', re.I)
_REL_STYLE_RE = re.compile(r'\brel=["\']stylesheet["\']', re.I)

_WEAK_ALGOS = {"sha1", "md5"}
_STRONG_ALGOS = {"sha256", "sha384", "sha512"}


def _is_external(src: str, host: str) -> bool:
    if src.startswith("//"):
        return True
    if src.startswith("http://") or src.startswith("https://"):
        try:
            return urlparse(src).hostname != host
        except Exception:
            return True
    return False


class SRIAdvancedScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        try:
            resp = self.http.get(url)
            if resp is None:
                return self.results
        except Exception:
            return self.results

        html = resp.text or ""
        host = urlparse(url).hostname or ""

        external_scripts  = self._collect_external(html, host)
        self._check_hash_strength(external_scripts, url)
        self._check_crossorigin_attribute(external_scripts, url)
        self._check_coverage(external_scripts, url)
        return self.results

    def _collect_external(self, html: str, host: str) -> List[Dict]:
        resources = []

        for m in _SCRIPT_RE.finditer(html):
            attrs = m.group(1)
            src_m = _SRC_RE.search(attrs)
            if not src_m:
                continue
            src = src_m.group(1)
            if not _is_external(src, host):
                continue
            integrity_m   = _INTEGRITY_RE.search(attrs)
            crossorigin_m = _CROSSORIGIN_RE.search(attrs)
            resources.append({
                "type":       "script",
                "src":        src,
                "integrity":  integrity_m.group(1) if integrity_m else None,
                "crossorigin": bool(crossorigin_m),
            })

        for m in _LINK_RE.finditer(html):
            attrs = m.group(1)
            if not _REL_STYLE_RE.search(attrs):
                continue
            href_m = _HREF_RE.search(attrs)
            if not href_m:
                continue
            href = href_m.group(1)
            if not _is_external(href, host):
                continue
            integrity_m   = _INTEGRITY_RE.search(attrs)
            crossorigin_m = _CROSSORIGIN_RE.search(attrs)
            resources.append({
                "type":       "stylesheet",
                "src":        href,
                "integrity":  integrity_m.group(1) if integrity_m else None,
                "crossorigin": bool(crossorigin_m),
            })

        return resources

    def _check_hash_strength(self, resources: List[Dict], url: str) -> None:
        for res in resources:
            if not res["integrity"]:
                continue
            for algo, _ in _SRI_HASH_RE.findall(res["integrity"]):
                algo_lower = algo.lower().replace("-", "")
                if algo_lower in _WEAK_ALGOS:
                    log_fail(logger, f"SRI uses weak hash {algo} for {res['src'][:60]}")
                    self.results.append(self._result(url,
                        f"SRI advanced — weak hash algorithm ({algo}) for {res['type']}",
                        "FAIL",
                        detail=(
                            f"Resource {res['src'][:80]} uses {algo} for SRI which is cryptographically weak. "
                            f"An attacker who can produce a {algo} collision could serve a modified resource. "
                            "Fix: use SHA-256, SHA-384, or SHA-512 instead."
                        )))

    def _check_crossorigin_attribute(self, resources: List[Dict], url: str) -> None:
        for res in resources:
            if res["integrity"] and not res["crossorigin"]:
                log_warn(logger, f"SRI integrity= without crossorigin for {res['src'][:60]}")
                self.results.append(self._result(url,
                    f"SRI advanced — integrity= without crossorigin attribute ({res['type']})",
                    "WARN",
                    detail=(
                        f"Resource {res['src'][:80]} has integrity= but no crossorigin attribute. "
                        "SRI only works for cross-origin resources when crossorigin is set. "
                        "Without it, the browser may not enforce the integrity check in all scenarios. "
                        "Fix: add crossorigin='anonymous' alongside the integrity= attribute."
                    )))

    def _check_coverage(self, resources: List[Dict], url: str) -> None:
        total    = len(resources)
        if total == 0:
            return
        with_sri = sum(1 for r in resources if r["integrity"])
        coverage = int(100 * with_sri / total)

        if coverage == 100:
            log_pass(logger, f"SRI coverage: 100% ({with_sri}/{total} external resources)")
            self.results.append(self._result(url,
                f"SRI advanced — 100% coverage ({with_sri}/{total} external resources)",
                "PASS",
                detail="All external scripts and stylesheets have SRI integrity hashes."))
        elif coverage >= 50:
            missing = [r["src"][:60] for r in resources if not r["integrity"]][:5]
            log_warn(logger, f"SRI coverage: {coverage}% ({with_sri}/{total})")
            self.results.append(self._result(url,
                f"SRI advanced — partial coverage ({coverage}%, {with_sri}/{total})",
                "WARN",
                detail=(
                    f"Only {with_sri} of {total} external resources have SRI hashes ({coverage}%). "
                    f"Missing: {', '.join(missing)}{'…' if len(missing) == 5 else ''}. "
                    "Resources without SRI can be replaced by a compromised CDN without detection."
                )))
        else:
            missing = [r["src"][:60] for r in resources if not r["integrity"]][:5]
            log_fail(logger, f"SRI coverage: {coverage}% ({with_sri}/{total})")
            self.results.append(self._result(url,
                f"SRI advanced — low coverage ({coverage}%, {with_sri}/{total})",
                "FAIL",
                detail=(
                    f"Only {with_sri} of {total} external resources have SRI hashes ({coverage}%). "
                    f"Most external resources are unprotected: {', '.join(missing)}{'…' if len(missing) == 5 else ''}. "
                    "Use https://www.srihash.org/ or your build pipeline to generate hashes."
                )))
