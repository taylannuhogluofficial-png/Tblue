"""
WebAssembly (WASM) Security Scanner.

WebAssembly binaries are increasingly used in production web applications
(crypto, gaming, media processing, obfuscated logic). They introduce
unique security risks:

  1. WASM binaries may contain hardcoded credentials or secrets
     extracted from the original source (no minification removes them)
  2. WASM can export functions that are callable from JS — an attacker
     reading the binary can understand the application's internal API
  3. Large WASM files deployed without integrity (SRI) checks can be
     replaced by supply chain attackers
  4. WASM binaries may import functions that can be used for SSRF
     or memory corruption if memory is shared with the host

This scanner:
  - Detects WASM files linked from the page (script src=*.wasm, fetch calls, import())
  - Downloads the binary and inspects the string table for secrets
  - Checks for SRI integrity attribute on <script> tags loading WASM
  - Checks Content-Type header (should be application/wasm)

CWE-312: Cleartext Storage of Sensitive Information
CWE-829: Inclusion of Functionality from Untrusted Control Sphere
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Detect WASM file references
_WASM_SRC_RE = re.compile(r"""(?:src|href|url)\s*=\s*["']([^"']*\.wasm(?:\?[^"']*)?)["']""", re.I)
_WASM_FETCH_RE = re.compile(r"""fetch\s*\(\s*["']([^"']*\.wasm[^"']*)["']""", re.I)
_WASM_IMPORT_RE = re.compile(r"""import\s*\(\s*["']([^"']*\.wasm[^"']*)["']""", re.I)
_WASM_INSTANTIATE_RE = re.compile(r"""WebAssembly\.instantiate(?:Streaming)?\s*\(\s*fetch\s*\(\s*["']([^"']*\.wasm[^"']*)["']""", re.I)

# WASM magic bytes: \0asm\1\0\0\0
_WASM_MAGIC = b"\x00asm"

# Secret patterns to scan for in WASM string table
_SECRET_PATTERNS = [
    (re.compile(rb"(?i)password\s*[:=]\s*\S+"), "password"),
    (re.compile(rb"(?i)secret\s*[:=]\s*\S+"), "secret"),
    (re.compile(rb"(?i)api[_-]?key\s*[:=]\s*\S+"), "api_key"),
    (re.compile(rb"(?i)token\s*[:=]\s*\S+"), "token"),
    (re.compile(rb"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(rb"sk-[a-zA-Z0-9]{32,}"), "OpenAI key"),
    (re.compile(rb"ghp_[a-zA-Z0-9]{36}"), "GitHub token"),
    (re.compile(rb"-----BEGIN [A-Z ]{1,30}PRIVATE KEY-----"), "private key"),
    (re.compile(rb"(?i)authorization:\s*bearer\s+\S+"), "Authorization header"),
]

# SRI integrity pattern
_INTEGRITY_RE = re.compile(r"""integrity\s*=\s*["'][^"']+["']""", re.I)

_MAX_WASM_SIZE = 5 * 1024 * 1024  # 5 MB max download
_MAX_BODY_SCAN = 256 * 1024


def _extract_printable_strings(data: bytes, min_len: int = 6) -> List[bytes]:
    """Extract null-terminated or length-delimited printable strings from binary."""
    result = []
    current = bytearray()
    for b in data:
        if 0x20 <= b <= 0x7e:
            current.append(b)
        else:
            if len(current) >= min_len:
                result.append(bytes(current))
            current = bytearray()
    if len(current) >= min_len:
        result.append(bytes(current))
    return result


def _scan_for_secrets(data: bytes) -> List[Dict[str, str]]:
    findings = []
    seen = set()
    for pattern, label in _SECRET_PATTERNS:
        for m in pattern.finditer(data):
            snippet = m.group(0)[:80].decode("latin-1", errors="replace")
            key = (label, snippet[:20])
            if key not in seen:
                seen.add(key)
                findings.append({"label": label, "snippet": snippet})
    return findings


class WASMSecurityScanner(BaseScanner):
    """Detects WebAssembly usage and scans WASM binaries for secrets and misconfigs."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "WASM Security — target unreachable", "PASS",
                detail="No response; WASM security scan skipped."))
            return self.results

        body = (resp.text or "")[:_MAX_BODY_SCAN]

        # Find all WASM URLs referenced on the page
        wasm_urls = []
        for pattern in (_WASM_SRC_RE, _WASM_FETCH_RE, _WASM_IMPORT_RE, _WASM_INSTANTIATE_RE):
            for m in pattern.finditer(body):
                raw = m.group(1)
                absolute = urljoin(url, raw)
                if absolute not in wasm_urls:
                    wasm_urls.append(absolute)

        if not wasm_urls:
            log_pass(logger, f"WASM Security — no WebAssembly files detected on {url}")
            self.results.append(self._result(
                url, "WASM Security — no WebAssembly files detected", "PASS",
                detail="No .wasm files were referenced in the page source. This scanner "
                       "checks for WASM binary secrets and SRI coverage."))
            return self.results

        logger.info(f"WASM Security: found {len(wasm_urls)} WASM file(s): {wasm_urls[:3]}")

        for wasm_url in wasm_urls[:5]:  # cap at 5 files
            self._scan_wasm_file(url, wasm_url, body)

        return self.results

    def _scan_wasm_file(self, page_url: str, wasm_url: str, page_body: str) -> None:
        # Check SRI for this WASM
        fname = wasm_url.split("/")[-1].split("?")[0]
        sri_in_page = bool(_INTEGRITY_RE.search(page_body)) and fname in page_body
        if not sri_in_page:
            log_warn(logger, f"WASM Security — no SRI integrity for {wasm_url}")
            self.results.append(self._result(
                page_url,
                f"WASM Security — no SRI integrity attribute for {fname}",
                "WARN",
                detail=(
                    f"The WebAssembly file {wasm_url} is loaded without a Subresource Integrity "
                    f"(integrity=\"sha384-...\") attribute. An attacker who controls the CDN or "
                    f"network path could replace the WASM binary to exfiltrate data or execute "
                    f"arbitrary logic in your application's memory space.\n\n"
                    f"Fix: add integrity + crossorigin attributes to the <script> or fetch() call."
                ),
            ))

        # Download the WASM binary
        parsed = urlparse(wasm_url)
        is_same_origin = urlparse(page_url).netloc == parsed.netloc
        if not is_same_origin:
            log_warn(logger, f"WASM Security — cross-origin WASM from {parsed.netloc}")
            self.results.append(self._result(
                page_url,
                f"WASM Security — cross-origin WASM from {parsed.netloc}",
                "WARN",
                detail=(
                    f"The WebAssembly binary is loaded from a third-party domain: {parsed.netloc}. "
                    f"Any compromise of that domain gives the attacker code execution in your "
                    f"application. If SRI is not present, this is especially dangerous."
                ),
            ))

        # Fetch binary
        wasm_resp = self.http.get(wasm_url)
        if wasm_resp is None:
            return

        # Check Content-Type
        ct = (wasm_resp.headers or {}).get("content-type", "") or ""
        if wasm_resp.content and not ct.startswith("application/wasm"):
            log_warn(logger, f"WASM Security — wrong Content-Type for {fname}: {ct!r}")
            self.results.append(self._result(
                page_url,
                f"WASM Security — wrong Content-Type for {fname} ({ct!r})",
                "WARN",
                detail=(
                    f"WASM files should be served with Content-Type: application/wasm for "
                    f"streaming compilation performance and to signal browser intent. "
                    f"Current type: {ct!r}"
                ),
            ))

        # Get binary content
        content = getattr(wasm_resp, "content", None)
        if content is None:
            # Fall back to text bytes
            text = wasm_resp.text or ""
            content = text.encode("latin-1", errors="replace")

        if len(content) > _MAX_WASM_SIZE:
            logger.info(f"WASM Security: {fname} too large ({len(content)} bytes), scanning first 5MB")
            content = content[:_MAX_WASM_SIZE]

        # Validate magic bytes
        if not content.startswith(_WASM_MAGIC):
            return

        # Scan string table for secrets
        secrets = _scan_for_secrets(content)
        if secrets:
            for s in secrets[:5]:
                log_fail(logger, f"WASM Security — {s['label']} found in WASM binary: {fname}")
                self.results.append(self._result(
                    page_url,
                    f"WASM Security — {s['label']} hardcoded in {fname}",
                    "FAIL",
                    detail=(
                        f"A potential {s['label']} was found in the printable string table of "
                        f"the WASM binary {fname}. Unlike JavaScript, WASM binaries are not "
                        f"minified in the same way, so credential strings from source code can "
                        f"survive compilation verbatim.\n\n"
                        f"Matched text: {s['snippet']!r}\n\n"
                        f"Fix: never embed credentials in WASM binaries. Use runtime injection "
                        f"from the JS host or environment-based configuration."
                    ),
                ))
        else:
            log_pass(logger, f"WASM Security — no secrets found in {fname}")
            self.results.append(self._result(
                page_url,
                f"WASM Security — no hardcoded secrets detected in {fname}",
                "PASS",
                detail=f"Scanned {len(content):,} bytes of {fname}; no credential patterns found in string table.",
            ))
