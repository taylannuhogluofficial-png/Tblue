"""
Path Traversal / LFI Parameter Indicator Scanner.

Passively detects URL parameters and form fields whose names suggest
Local File Inclusion (LFI) or path traversal vulnerabilities, and checks
whether current values contain traversal sequences.

Categories:
  HIGH_RISK — param names strongly associated with file inclusion
    (file, filename, filepath, path, include, load, template, view, page,
     src, source, doc, document, resource, content, module, component)

  MEDIUM_RISK — param names that sometimes indicate file operations
    (dir, directory, folder, base, root, prefix, suffix, lang, locale,
     config, conf, setting, layout, theme, style, skin)

  TRAVERSAL_VALUES — values containing path traversal sequences
    (../../, ..\\.., /etc/, C:\\, /proc/, /var/log/, windows\\system32)

This scanner complements ssrf_params.py (which focuses on URL-valued params).
Here we focus on file/path-valued params and traversal sequence detection.

All checks are passive — no probing with crafted payloads.
"""

import re
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlparse, parse_qs, unquote

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Parameter names strongly associated with file inclusion / path traversal
_HIGH_RISK: frozenset = frozenset({
    "file", "filename", "filepath", "file_path", "file_name",
    "path", "pathname", "filepath", "file-path",
    "include", "inc", "incl",
    "load", "loader",
    "template", "tmpl", "tpl",
    "view", "viewer",
    "page", "pagename", "page_name",
    "document", "doc",
    "source", "src",
    "resource", "res",
    "content", "contents",
    "module", "mod",
    "component", "comp",
    "require", "fetch",
    "read", "get",
    "display", "show",
    "open", "render",
    "layout", "frame",
})

# Parameter names with moderate association to file operations
_MEDIUM_RISK: frozenset = frozenset({
    "dir", "directory", "folder",
    "base", "basedir", "base_dir", "basepath", "base_path",
    "root", "rootdir",
    "prefix", "suffix",
    "lang", "language", "locale",
    "config", "conf", "configuration",
    "setting", "settings",
    "theme", "skin", "style",
    "type", "format",
    "section", "chapter",
    "action", "cmd", "command",
})

# Path traversal sequences in parameter values
_TRAVERSAL_VALUE_RE = re.compile(
    r"""
    \.\.[\\/]|             # ../  or ..\
    \.\.%2[fF]|            # URL-encoded ../
    \.\.%5[cC]|            # URL-encoded ..\
    %2e%2e[\\/]|           # double-encoded ../
    \.\.;[\\/]|            # Tomcat path bypass ../;/
    /etc/|                 # Linux sensitive dirs
    /proc/self/|
    /var/log/|
    /var/www/|
    /home/[^/]+/\.|        # home directory dotfiles
    [Cc]:\\[Ww]indows|     # Windows system paths
    [Cc]:\\[Uu]sers|
    \bweb\.config\b|       # .NET config files
    \bweb\.xml\b|          # Java web config
    /WEB-INF/|
    /META-INF/|
    boot\.ini              # Windows boot config
    """,
    re.I | re.X,
)

# File extension targets that suggest LFI probe attempts
_SENSITIVE_EXTENSION_RE = re.compile(
    r"\.(php|inc|conf|cfg|ini|env|key|pem|crt|log|bak|sql|db|sqlite|mdb)\b",
    re.I,
)


def _classify(name: str) -> str:
    name_lower = name.lower().replace("-", "_")
    if name_lower in _HIGH_RISK:
        return "high"
    if name_lower in _MEDIUM_RISK:
        return "medium"
    return "none"


class PathTraversalScanner(BaseScanner):
    """Detect path traversal / LFI indicator parameters through passive analysis."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if not resp:
            return self.results

        body = resp.text or ""
        soup = BeautifulSoup(body, "html.parser")

        high_risk_params: List[Tuple[str, str]] = []
        medium_risk_params: List[Tuple[str, str]] = []
        traversal_values: List[Tuple[str, str, str]] = []

        # ── URL query string analysis ─────────────────────────────────────────
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for name, values in qs.items():
                risk = _classify(name)
                for val in values:
                    decoded = unquote(val)
                    if _TRAVERSAL_VALUE_RE.search(decoded):
                        traversal_values.append((name, decoded[:60], "URL query"))
                    elif _SENSITIVE_EXTENSION_RE.search(decoded):
                        traversal_values.append((name, decoded[:60], "URL query (sensitive ext)"))

                if risk == "high":
                    high_risk_params.append((name, "URL query"))
                elif risk == "medium":
                    medium_risk_params.append((name, "URL query"))
        except Exception:
            pass

        # ── Form fields analysis ──────────────────────────────────────────────
        for form in soup.find_all("form"):
            for inp in form.find_all(["input", "select", "textarea"]):
                name = inp.attrs.get("name", "")
                if not name:
                    continue
                risk = _classify(name)
                value = inp.attrs.get("value", "")
                decoded = unquote(value)

                if decoded and _TRAVERSAL_VALUE_RE.search(decoded):
                    traversal_values.append((name, decoded[:60], "form field"))
                elif decoded and _SENSITIVE_EXTENSION_RE.search(decoded):
                    traversal_values.append((name, decoded[:60], "form field (sensitive ext)"))

                form_action = form.attrs.get("action", url)
                if risk == "high":
                    high_risk_params.append((name, f"form field ({form_action[:60]})"))
                elif risk == "medium":
                    medium_risk_params.append((name, f"form field ({form_action[:60]})"))

        # ── Linked URLs in page ───────────────────────────────────────────────
        for tag in soup.find_all(["a", "link", "script", "iframe"]):
            href = tag.attrs.get("href", "") or tag.attrs.get("src", "")
            if not href or not href.startswith("http") and "?" not in href:
                continue
            try:
                linked_parsed = urlparse(href)
                linked_qs = parse_qs(linked_parsed.query)
                for name, values in linked_qs.items():
                    risk = _classify(name)
                    for val in values:
                        decoded = unquote(val)
                        if _TRAVERSAL_VALUE_RE.search(decoded):
                            traversal_values.append((name, decoded[:60], f"link href ({href[:50]})"))
                    if risk == "high" and (name, "linked URL") not in high_risk_params:
                        high_risk_params.append((name, "linked URL"))
            except Exception:
                continue

        # ── Emit findings ──────────────────────────────────────────────────────
        # Traversal sequences take priority
        for name, value, location in traversal_values[:5]:
            log_fail(logger, f"Traversal sequence in param '{name}': {value} ({location})")
            self.results.append(self._result(
                url,
                f"Path traversal — traversal sequence in parameter '{name}'",
                "FAIL",
                detail=(
                    f"Parameter '{name}' in {location} contains a path traversal sequence: "
                    f"'{value}'. "
                    "Path traversal (LFI) allows attackers to read arbitrary files outside "
                    "the web root, including /etc/passwd, web.config, application source code, "
                    "and credentials. "
                    "Fix: validate that file paths resolve within an allowed base directory "
                    "(use realpath() and startswith() checks); never pass user input directly "
                    "to file system functions; use a whitelist of allowed file names."
                )
            ))

        # High-risk param names (without traversal sequences — just structural risk)
        seen_high: Set[str] = {t[0] for t in traversal_values}
        for name, location in high_risk_params[:5]:
            if name in seen_high:
                continue
            log_warn(logger, f"High-risk path param '{name}' ({location})")
            self.results.append(self._result(
                url,
                f"Path traversal — high-risk file/path parameter name '{name}'",
                "WARN",
                detail=(
                    f"Parameter '{name}' in {location} is commonly used for file inclusion. "
                    "If this parameter accepts user input and is passed to file system "
                    "or template loading functions without validation, it is vulnerable "
                    "to Local File Inclusion (LFI) or path traversal. "
                    "Fix: validate the parameter against an explicit allowlist of permitted "
                    "values; never allow user-controlled file paths."
                )
            ))

        # Medium-risk param names — only report if no high-risk found
        if not high_risk_params and not traversal_values:
            for name, location in medium_risk_params[:3]:
                log_warn(logger, f"Medium-risk path param '{name}' ({location})")
                self.results.append(self._result(
                    url,
                    f"Path traversal — medium-risk directory/path parameter '{name}'",
                    "WARN",
                    detail=(
                        f"Parameter '{name}' in {location} may be used for file or "
                        "directory operations. Verify it is validated against an allowlist."
                    )
                ))

        if not self.results:
            log_pass(logger, f"No path traversal indicator parameters found on {url}")
            self.results.append(self._result(
                url, "Path traversal — no LFI/traversal parameters detected", "PASS",
                detail="No high-risk file/path parameter names or traversal sequences found."
            ))

        return self.results
