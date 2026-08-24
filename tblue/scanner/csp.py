"""
CSP deep analyzer.
Reads the existing Content-Security-Policy header and performs
detailed analysis of every directive — no active probing.
"""

import re
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn, log_head

logger = get_logger(__name__)

IMPORTANT_DIRECTIVES = [
    "default-src",
    "script-src",
    "style-src",
    "img-src",
    "connect-src",
    "font-src",
    "frame-ancestors",
    "base-uri",
    "form-action",
]

# Extra directives that should be explicitly set
EXTRA_DIRECTIVES = ["object-src", "worker-src", "manifest-src"]

DANGEROUS_VALUES = [
    ("'unsafe-inline'", "Allows inline scripts/styles — major XSS risk"),
    ("'unsafe-eval'",   "Allows eval() — allows arbitrary JS execution"),
    ("*",               "Wildcard allows any source — defeats CSP purpose"),
    ("data:",           "data: URI scheme can be used to inject scripts"),
    ("http:",           "http: allows loading resources over insecure HTTP"),
]

# CDN hosts known to host JSONP endpoints or Angular/jQuery that bypass CSP
BYPASS_CDN_SOURCES = [
    ("ajax.googleapis.com",  "Google AJAX CDN — known JSONP bypass host"),
    ("*.googleapis.com",     "Google APIs CDN — may host JSONP bypass endpoints"),
    ("cdnjs.cloudflare.com", "CDNJS — hosts many libraries, some with JSONP"),
    ("*.cloudflare.com",     "Cloudflare CDN — may host CSP-bypass libraries"),
    ("*.google.com",         "Google — broad wildcard with known JSONP/callback endpoints"),
    ("*.microsoft.com",      "Microsoft CDN — broad wildcard, known bypass host"),
    ("*.jquery.com",         "jQuery CDN — may host outdated versions with bypass gadgets"),
]

_NONCE_PATTERN  = re.compile(r"'nonce-([A-Za-z0-9+/=_-]+)'")
_STATIC_NONCE   = re.compile(r"^[a-z0-9]{1,16}$", re.I)  # suspiciously simple nonce


class CSPScanner(BaseScanner):
    """
    Deep analyzer for Content-Security-Policy headers.
    Reads and analyzes the existing CSP — no active probing.
    Checks every directive for dangerous values and missing protections.
    """

    def scan(self, url: str) -> List[Dict[str, Any]]:
        """
        Fetch the URL and deeply analyze its CSP header.

        Args:
            url: target URL

        Returns:
            List of result dicts — one per CSP finding
        """
        self.results = []
        resp = self.http.get(url, allow_redirects=True)
        if not resp:
            return self.results

        csp = resp.headers.get("content-security-policy", "")

        if not csp:
            log_fail(logger, f"No Content-Security-Policy header on {url}")
            self.results.append(self._result(
                url, "CSP — missing", "FAIL",
                detail=(
                    "No Content-Security-Policy header found. "
                    "Fix: add a CSP header that defines trusted sources. "
                    "Start with: Content-Security-Policy: default-src 'self'"
                )
            ))
            self._check_meta_csp(url, resp.text)
            return self.results

        log_head(logger, f"Analyzing CSP on {url}")
        directives = self._parse_csp(csp)

        self._check_dangerous_values(url, csp, directives)
        self._check_missing_directives(url, directives)
        self._check_extra_directives(url, directives)
        self._check_frame_ancestors(url, directives)
        self._check_base_uri(url, directives)
        self._check_form_action(url, directives)
        self._check_nonce_quality(url, directives)
        self._check_reporting(url, directives)
        self._check_bypass_sources(url, directives)
        self._check_meta_csp(url, resp.text)
        self._summarize(url, csp, directives)

        return self.results

    def _parse_csp(self, csp: str) -> Dict[str, List[str]]:
        """
        Parse a CSP header string into a dict of directive -> values.

        Args:
            csp: raw CSP header string

        Returns:
            Dict mapping directive name to list of values
        """
        directives: Dict[str, List[str]] = {}
        for part in csp.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens:
                name   = tokens[0].lower()
                values = tokens[1:]
                directives[name] = values
        return directives

    def _check_dangerous_values(
        self,
        url: str,
        csp: str,
        directives: Dict[str, List[str]],
    ) -> None:
        """Check every directive for known dangerous values."""
        for directive, values in directives.items():
            for val in values:
                for dangerous, reason in DANGEROUS_VALUES:
                    if val.lower() == dangerous.lower() or (
                        dangerous == "*" and val == "*"
                    ):
                        log_fail(logger, f"CSP '{directive}' contains {dangerous}: {reason}")
                        self.results.append(self._result(
                            url,
                            f"CSP — dangerous value in {directive}",
                            "FAIL",
                            detail=f"'{dangerous}' in {directive}: {reason} Fix: remove or restrict this value."
                        ))

    def _check_missing_directives(
        self,
        url: str,
        directives: Dict[str, List[str]],
    ) -> None:
        """Check for missing important directives."""
        has_default = "default-src" in directives

        for directive in IMPORTANT_DIRECTIVES:
            if directive not in directives:
                if has_default and directive not in ("base-uri", "form-action", "frame-ancestors"):
                    # default-src covers most directives
                    continue
                severity = "FAIL" if directive in ("default-src", "script-src") else "WARN"
                if severity == "FAIL":
                    log_fail(logger, f"CSP missing critical directive: {directive}")
                else:
                    log_warn(logger, f"CSP missing directive: {directive}")
                self.results.append(self._result(
                    url,
                    f"CSP — missing directive: {directive}",
                    severity,
                    detail=(
                        f"'{directive}' directive is missing. "
                        f"Fix: add '{directive}' to your CSP to explicitly control this resource type."
                    )
                ))

    def _check_frame_ancestors(
        self,
        url: str,
        directives: Dict[str, List[str]],
    ) -> None:
        """Check frame-ancestors directive for clickjacking protection."""
        if "frame-ancestors" not in directives:
            log_warn(logger, f"CSP missing frame-ancestors on {url}")
            self.results.append(self._result(
                url, "CSP — frame-ancestors missing", "WARN",
                detail=(
                    "Missing 'frame-ancestors' directive — site can be embedded in iframes. "
                    "Fix: add frame-ancestors 'self' or frame-ancestors 'none' to prevent clickjacking."
                )
            ))
        else:
            values = directives["frame-ancestors"]
            if "*" in values:
                log_fail(logger, f"CSP frame-ancestors is wildcard on {url}")
                self.results.append(self._result(
                    url, "CSP — frame-ancestors wildcard", "FAIL",
                    detail="frame-ancestors * allows any site to embed this page. Fix: use 'none' or 'self'."
                ))
            else:
                log_pass(logger, f"CSP frame-ancestors configured on {url}")
                self.results.append(self._result(
                    url, "CSP — frame-ancestors", "PASS",
                    detail=f"frame-ancestors set to: {' '.join(values)}"
                ))

    def _check_base_uri(
        self,
        url: str,
        directives: Dict[str, List[str]],
    ) -> None:
        """Check base-uri directive to prevent base tag injection."""
        if "base-uri" not in directives:
            log_warn(logger, f"CSP missing base-uri on {url}")
            self.results.append(self._result(
                url, "CSP — base-uri missing", "WARN",
                detail=(
                    "Missing 'base-uri' directive — attackers could inject a base tag "
                    "to redirect relative URLs. Fix: add base-uri 'self' or base-uri 'none'."
                )
            ))
        else:
            log_pass(logger, f"CSP base-uri configured on {url}")
            self.results.append(self._result(
                url, "CSP — base-uri", "PASS",
            ))

    def _check_form_action(
        self,
        url: str,
        directives: Dict[str, List[str]],
    ) -> None:
        """Check form-action directive to control where forms can submit."""
        if "form-action" not in directives:
            log_warn(logger, f"CSP missing form-action on {url}")
            self.results.append(self._result(
                url, "CSP — form-action missing", "WARN",
                detail=(
                    "Missing 'form-action' directive — form submissions not restricted. "
                    "Fix: add form-action 'self' to restrict forms to your own domain."
                )
            ))
        else:
            log_pass(logger, f"CSP form-action configured on {url}")
            self.results.append(self._result(
                url, "CSP — form-action", "PASS",
            ))

    def _check_extra_directives(
        self,
        url: str,
        directives: Dict[str, List[str]],
    ) -> None:
        """Check object-src, worker-src, manifest-src — often left unset."""
        has_default = "default-src" in directives
        for directive in EXTRA_DIRECTIVES:
            if directive not in directives:
                if has_default:
                    # default-src covers it but note that object-src 'none' is still best practice
                    if directive == "object-src":
                        log_warn(logger, f"CSP object-src not explicit on {url}")
                        self.results.append(self._result(
                            url, "CSP — object-src not explicit", "WARN",
                            detail=(
                                "object-src is not explicitly set. "
                                "Even with default-src, explicitly setting object-src 'none' "
                                "prevents Flash and plugin-based attacks. "
                                "Fix: add object-src 'none' to your CSP."
                            )
                        ))
                else:
                    log_warn(logger, f"CSP missing {directive}")
                    self.results.append(self._result(
                        url, f"CSP — missing directive: {directive}", "WARN",
                        detail=(
                            f"'{directive}' is not set and there is no default-src fallback. "
                            f"Fix: add '{directive}' to your CSP to explicitly control this resource type."
                        )
                    ))

    def _check_nonce_quality(
        self,
        url: str,
        directives: Dict[str, List[str]],
    ) -> None:
        """If nonces are used, check they look sufficiently random."""
        script_values = directives.get("script-src", directives.get("default-src", []))
        nonces = _NONCE_PATTERN.findall(" ".join(script_values))

        if not nonces:
            return

        static = [n for n in nonces if _STATIC_NONCE.match(n)]
        if static:
            log_fail(logger, f"CSP nonce looks static/weak on {url}: {static[0]}")
            self.results.append(self._result(
                url, "CSP — static or weak nonce", "FAIL",
                detail=(
                    f"Nonce value '{static[0]}' appears to be static or too short. "
                    "A static nonce can be extracted from old responses and reused to bypass CSP. "
                    "Fix: generate a cryptographically random 128-bit nonce per request "
                    "(e.g. base64url(os.urandom(16)) in Python)."
                )
            ))
        else:
            log_pass(logger, f"CSP nonces look random on {url}")
            self.results.append(self._result(
                url, "CSP — nonce quality", "PASS",
                detail="Nonce values appear sufficiently random."
            ))

    def _check_reporting(
        self,
        url: str,
        directives: Dict[str, List[str]],
    ) -> None:
        """Check if CSP violation reporting is configured."""
        has_report_uri = "report-uri" in directives
        has_report_to  = "report-to" in directives

        if not has_report_uri and not has_report_to:
            log_warn(logger, f"CSP has no violation reporting on {url}")
            self.results.append(self._result(
                url, "CSP — no violation reporting", "WARN",
                detail=(
                    "Neither report-uri nor report-to is configured. "
                    "Without reporting you will not know when your CSP is violated or bypassed. "
                    "Fix: add report-to with a Report-To endpoint, or report-uri /csp-report "
                    "to receive violation notifications."
                )
            ))
        else:
            log_pass(logger, f"CSP violation reporting configured on {url}")
            self.results.append(self._result(
                url, "CSP — violation reporting", "PASS",
                detail="CSP violation reporting is configured."
            ))

    def _check_bypass_sources(
        self,
        url: str,
        directives: Dict[str, List[str]],
    ) -> None:
        """Flag known CDN sources in script-src that can be used to bypass CSP."""
        script_values = directives.get("script-src", directives.get("default-src", []))
        src_str       = " ".join(script_values).lower()

        for cdn_host, reason in BYPASS_CDN_SOURCES:
            if cdn_host.lower().lstrip("*. ") in src_str.replace("*.", "").replace("*", ""):
                if cdn_host.lower() in src_str or cdn_host.lstrip("*.") in src_str:
                    log_warn(logger, f"CSP bypass source in script-src on {url}: {cdn_host}")
                    self.results.append(self._result(
                        url, f"CSP — potential bypass source: {cdn_host}", "WARN",
                        detail=(
                            f"'{cdn_host}' is whitelisted in script-src. {reason}. "
                            "An attacker who can load content from this host may bypass your CSP. "
                            "Fix: remove broad CDN wildcards and use specific script hashes or nonces instead."
                        )
                    ))

    def _check_meta_csp(self, url: str, html: str) -> None:
        """Detect CSP delivered via an HTML meta tag instead of an HTTP header."""
        soup     = BeautifulSoup(html, "html.parser")
        meta_csp = soup.find("meta", attrs={"http-equiv": lambda v: v and v.lower() == "content-security-policy"})

        if meta_csp:
            log_warn(logger, f"CSP set via meta tag (weaker than HTTP header) on {url}")
            self.results.append(self._result(
                url, "CSP — delivered via meta tag", "WARN",
                detail=(
                    "Content-Security-Policy is set via an HTML <meta> tag. "
                    "Meta-tag CSP is weaker than HTTP header CSP: it cannot use "
                    "frame-ancestors, report-uri, or sandbox directives, and can be "
                    "bypassed by injecting content before the meta tag is parsed. "
                    "Fix: move CSP to an HTTP response header."
                )
            ))

    def _summarize(
        self,
        url: str,
        csp: str,
        directives: Dict[str, List[str]],
    ) -> None:
        """Add a summary result with the raw CSP value for the report."""
        fails = sum(1 for r in self.results if r["status"] == "FAIL")
        warns = sum(1 for r in self.results if r["status"] == "WARN")

        if fails == 0 and warns == 0:
            log_pass(logger, f"CSP looks strong on {url}")
            strength = "Strong"
        elif fails == 0:
            strength = "Moderate"
        else:
            strength = "Weak"

        self.results.append({
            "url":      url,
            "type":     "CSP — summary",
            "status":   "PASS" if strength == "Strong" else "WARN" if strength == "Moderate" else "FAIL",
            "method":   "GET",
            "fields":   list(directives.keys()),
            "detail":   f"CSP strength: {strength}. Directives found: {len(directives)}. Raw value: {csp[:200]}",
        })
