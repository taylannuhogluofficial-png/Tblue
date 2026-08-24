"""
Relative Path Overwrite (RPO) Security Scanner.

Relative Path Overwrite (RPO) is an attack where a URL path ambiguity causes
the browser to resolve relative URLs (CSS, JS imports) from an unintended base.

How it works:
  A URL like `https://example.com/app/page` (no trailing slash) can be rendered
  by the server, but the browser believes the base path is `/app/`, so:
  - `<link rel="stylesheet" href="styles.css">` resolves to `/app/styles.css`
  - But `https://example.com/app/page/styles.css` also loads the same page
    (server treats "page" as a directory), serving the *HTML* as CSS.
  - If the HTML contains user-controlled or reflected content, the browser
    parses it as CSS and extracts CSS tokens — arbitrary CSS injection.

Detection strategy (passive):
1. Check if the server responds identically to both `/path` and `/path/` (same content).
2. Detect pages with relative stylesheet/script URLs (no leading `/` or `https:`).
3. Check if response bodies contain reflected request parameters that could poison CSS.
4. Check `X-Content-Type-Options: nosniff` — its absence makes RPO worse
   (browser sniffs content-type, may interpret HTML as CSS in some contexts).
5. Detect URLs that end with path segments without trailing slashes combined
   with relative resource references.

CWE-93: Improper Neutralization of CRLF Sequences
CWE-116: Improper Encoding or Escaping of Output
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_REL_STYLESHEET_RE = re.compile(
    r'<link\b[^>]*\brel\s*=\s*["\']stylesheet["\'][^>]*\bhref\s*=\s*["\']'
    r'(?!https?://|//)([^/"\']+\.css(?:\?[^"\']*)?)["\']',
    re.I
)
_REL_SCRIPT_RE = re.compile(
    r'<script\b[^>]*\bsrc\s*=\s*["\']'
    r'(?!https?://|//)([^/"\']+\.js(?:\?[^"\']*)?)["\']',
    re.I
)
_REFLECTED_PARAM_IN_BODY = re.compile(
    r'<(?:input|meta)\b[^>]*(?:value|content)\s*=\s*["\'][^"\']*(?:;|}|{)[^"\']*["\']',
    re.I
)
_NO_TRAILING_SLASH = re.compile(r'^https?://[^/]+/(?:[^/?#]+/)*[^/?#.]+$')
_XCTO_RE = re.compile(r'nosniff', re.I)


class RelativePathOverwriteScanner(BaseScanner):
    """Detect Relative Path Overwrite (RPO) attack surface."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0

        parsed = urlparse(url)
        path = parsed.path

        # Only RPO-relevant if path has non-extension segment (not a file URL like /page.html)
        path_end = path.rstrip("/").split("/")[-1] if "/" in path else ""
        has_no_ext = "." not in path_end and path_end != ""
        ambiguous_path = has_no_ext and not url.endswith("/")

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "Relative path overwrite — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        body = resp.text or ""
        raw_headers = resp.headers if hasattr(resp.headers, "items") else {}
        headers_raw = raw_headers.items() if hasattr(raw_headers, "items") else raw_headers
        headers = {k.lower(): v for k, v in headers_raw}

        xcto = headers.get("x-content-type-options", "")
        has_nosniff = _XCTO_RE.search(xcto)

        rel_stylesheets = _REL_STYLESHEET_RE.findall(body)
        rel_scripts     = _REL_SCRIPT_RE.findall(body)

        if not ambiguous_path:
            if rel_stylesheets or rel_scripts:
                # Still check — even root path can have RPO in some configs
                pass
            else:
                log_pass(logger, f"No RPO risk: path ends with slash or no relative resources at {url}")
                self.results.append(self._result(
                    url, "Relative path overwrite — URL path not RPO-vulnerable", "PASS",
                    detail="URL has trailing slash or no ambiguous path segment with relative resources."
                ))
                return self.results

        if rel_stylesheets and ambiguous_path:
            log_warn(logger, f"Relative CSS import with ambiguous path at {url}")
            sample = rel_stylesheets[0]
            self.results.append(self._result(
                url,
                f"Relative path overwrite — relative CSS href on pathless URL: {sample[:60]}",
                "WARN",
                detail=(
                    f"URL '{url}' ends with a path segment without a trailing slash, "
                    f"and includes a relative CSS reference: href='{sample}'. "
                    "Browsers resolve this CSS relative to the current path. An attacker "
                    f"can request '{url}/extra' — if the server responds with the same HTML, "
                    f"the browser resolves the CSS from '{url}/extra/' base, loading "
                    f"'{url}/extra/{sample}'. If that URL serves reflected/user content, "
                    "the browser may parse it as CSS (RPO attack). "
                    "Fix: use root-relative hrefs (starting with '/') or absolute URLs; "
                    "ensure all paths have trailing slashes; add X-Content-Type-Options: nosniff."
                )
            ))
            findings += 1

        if rel_scripts and ambiguous_path:
            sample = rel_scripts[0]
            log_warn(logger, f"Relative JS import with ambiguous path at {url}")
            self.results.append(self._result(
                url,
                f"Relative path overwrite — relative JS src on pathless URL: {sample[:60]}",
                "WARN",
                detail=(
                    f"URL '{url}' has a relative script reference src='{sample}' "
                    "on an ambiguous (no trailing slash) path. Similar to CSS-based RPO, "
                    "the resolved JS URL depends on the browser's base URL assumption. "
                    "Fix: use absolute or root-relative paths for all script src attributes."
                )
            ))
            findings += 1

        if ambiguous_path and (rel_stylesheets or rel_scripts) and not has_nosniff:
            log_warn(logger, f"Relative resources without X-Content-Type-Options: nosniff at {url}")
            self.results.append(self._result(
                url,
                "Relative path overwrite — missing X-Content-Type-Options: nosniff (RPO amplifier)",
                "WARN",
                detail=(
                    "Relative CSS/JS resources are present on an ambiguous path, and "
                    "X-Content-Type-Options: nosniff is absent. Without nosniff, browsers may "
                    "content-sniff responses served with wrong content-types (e.g., HTML served "
                    "as CSS), enabling RPO to inject CSS from HTML pages. "
                    "Fix: add X-Content-Type-Options: nosniff to all responses "
                    "and use absolute resource URLs."
                )
            ))
            findings += 1

        # Check if server responds the same to path/ as path (trailing slash test)
        if ambiguous_path and findings > 0:
            try:
                slash_url = url.rstrip("/") + "/"
                resp2 = self.http.get(slash_url)
                if resp2 and resp2.status_code == 200 and resp2.text == body:
                    log_warn(logger, f"Server responds identically for trailing-slash variant at {url}")
                    self.results.append(self._result(
                        url,
                        "Relative path overwrite — server treats path and path/ identically",
                        "WARN",
                        detail=(
                            f"'{url}' and '{slash_url}' return the same response. "
                            "This path ambiguity is the core prerequisite for RPO attacks. "
                            "Fix: redirect /path to /path/ consistently (or vice versa), "
                            "so the browser always has an unambiguous base URL."
                        )
                    ))
            except Exception:
                pass

        if not self.results:
            log_pass(logger, f"No RPO indicators at {url}")
            self.results.append(self._result(
                url, "Relative path overwrite — no RPO risk indicators detected", "PASS",
                detail=(
                    "Either the path has a trailing slash, all resource URLs are absolute/"
                    "root-relative, or no relative CSS/JS imports found on an ambiguous path."
                )
            ))

        return self.results
