"""
Information disclosure scanner.
Checks response headers, meta tags, HTML comments, sensitive paths,
error pages, internal IPs, emails, API keys, and source maps.
"""

import re
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup, Comment
from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

VERSION_PATTERN = re.compile(r"\d+\.\d+")

DISCLOSURE_HEADERS = [
    {
        "key": "x-powered-by", "name": "X-Powered-By", "severity": "FAIL",
        "desc": "Reveals backend language and version (e.g. PHP/7.2, ASP.NET)",
        "fix": "Remove X-Powered-By. In PHP: expose_php=Off. In Express: app.disable('x-powered-by')",
    },
    {
        "key": "x-aspnet-version", "name": "X-AspNet-Version", "severity": "FAIL",
        "desc": "Reveals ASP.NET version",
        "fix": "Add <httpRuntime enableVersionHeader='false'/> to web.config",
    },
    {
        "key": "x-aspnetmvc-version", "name": "X-AspNetMvc-Version", "severity": "FAIL",
        "desc": "Reveals ASP.NET MVC version",
        "fix": "Disable in Global.asax: MvcHandler.DisableMvcResponseHeader = true",
    },
    {
        "key": "server", "name": "Server", "severity": "WARN",
        "desc": "Reveals web server software and version",
        "fix": "Configure server to return a generic value or remove this header entirely.",
    },
    {
        "key": "x-generator", "name": "X-Generator", "severity": "WARN",
        "desc": "Reveals CMS or framework used",
        "fix": "Remove or suppress this header in your CMS or framework settings.",
    },
    {
        "key": "x-drupal-cache", "name": "X-Drupal-Cache", "severity": "WARN",
        "desc": "Reveals Drupal CMS usage",
        "fix": "Configure Drupal to suppress this header.",
    },
    {
        "key": "x-runtime", "name": "X-Runtime", "severity": "WARN",
        "desc": "Reveals server processing time",
        "fix": "Disable X-Runtime in your framework configuration.",
    },
    {
        "key": "x-version", "name": "X-Version", "severity": "WARN",
        "desc": "Reveals application version",
        "fix": "Remove this header from your application responses.",
    },
]

SENSITIVE_COMMENT_PATTERNS = [
    re.compile(r"todo",              re.I),
    re.compile(r"fixme",             re.I),
    re.compile(r"hack",              re.I),
    re.compile(r"password",          re.I),
    re.compile(r"secret",            re.I),
    re.compile(r"api.?key",          re.I),
    re.compile(r"token",             re.I),
    re.compile(r"version\s*[:=]\s*\d", re.I),
    re.compile(r"debug",             re.I),
    re.compile(r"localhost",         re.I),
    re.compile(r"192\.168\.",        re.I),
    re.compile(r"10\.0\.",           re.I),
]

# Paths that should never be publicly accessible
SENSITIVE_PATHS = [
    ("/.git/HEAD",          "Git repository — HEAD file",    "FAIL",
     "Exposes git history and source code. Fix: block /.git/ access in your web server config."),
    ("/.git/config",        "Git repository — config file",  "FAIL",
     "Exposes git remote URLs and config. Fix: block /.git/ access in your web server config."),
    ("/.env",               ".env file",                     "FAIL",
     "Exposes environment variables and secrets. Fix: move .env outside webroot or block access."),
    ("/.env.local",         ".env.local file",               "FAIL",
     "Exposes local environment secrets. Fix: block .env* files via server config."),
    ("/.env.production",    ".env.production file",          "FAIL",
     "Exposes production secrets. Fix: block .env* files via server config."),
    ("/.env.backup",        ".env backup file",              "FAIL",
     "Exposes backed-up secrets. Fix: delete backup files and block .env* access."),
    ("/.htpasswd",          ".htpasswd credentials file",    "FAIL",
     "Exposes hashed credentials. Fix: move .htpasswd outside webroot."),
    ("/wp-config.php.bak",  "WordPress config backup",       "FAIL",
     "Exposes WordPress database credentials. Fix: delete backup files immediately."),
    ("/config.php.bak",     "PHP config backup",             "FAIL",
     "Exposes application configuration. Fix: delete backup files and block .bak access."),
    ("/web.config.bak",     "web.config backup",             "FAIL",
     "Exposes IIS configuration. Fix: delete backup files."),
    ("/backup.sql",         "SQL database dump",             "FAIL",
     "Exposes database contents. Fix: delete SQL dumps from webroot immediately."),
    ("/dump.sql",           "SQL database dump",             "FAIL",
     "Exposes database contents. Fix: delete SQL dumps from webroot immediately."),
    ("/database.sql",       "SQL database dump",             "FAIL",
     "Exposes database contents. Fix: delete SQL dumps from webroot immediately."),
    ("/index.php.bak",      "PHP index backup",              "WARN",
     "Exposes PHP source code. Fix: delete backup files and block .bak access."),
    ("/index.html.bak",     "HTML index backup",             "WARN",
     "Exposes HTML source. Fix: delete backup files."),
]

DIRECTORY_LISTING_MARKERS = [
    "<title>Index of ",
    "Index of /",
    "[PARENTDIR]",
    "Directory listing for ",
    "<h1>Directory listing",
    "To navigate to a file, click",
]

STACK_TRACE_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\)", re.I),
    re.compile(r"at [A-Za-z_$][A-Za-z0-9_$.]*\.[A-Za-z_$][A-Za-z0-9_$]*\([^)]*\)", re.I),
    re.compile(r"Exception in thread", re.I),
    re.compile(r"Fatal error:", re.I),
    re.compile(r"Parse error:", re.I),
    re.compile(r"Stack trace:", re.I),
    re.compile(r"org\.springframework\.", re.I),
    re.compile(r"com\.mysql\.jdbc", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"Microsoft OLE DB", re.I),
    re.compile(r"SQLSTATE\[", re.I),
    re.compile(r"PDOException", re.I),
    re.compile(r"ActiveRecord::", re.I),
    re.compile(r"in (?:/[\w/. -]+\.php) on line \d+", re.I),
    re.compile(r"django\.core\.exceptions", re.I),
    re.compile(r"ActionController::RoutingError", re.I),
    re.compile(r"OperationalError at /", re.I),
]

PRIVATE_IP_PATTERN = re.compile(
    r"\b(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r")\b"
)

EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PUBLIC_EMAIL_DOMAINS = frozenset({"example.com", "example.org", "test.com", "w3.org", "schema.org", "sentry.io"})

# ── PII patterns ─────────────────────────────────────────────────────────────

# Phone numbers: international (+1 555 555 5555), US (555-555-5555), and (555) 555-5555
PHONE_PATTERN = re.compile(
    r"(?<!\d)(?:"
    r"\+\d{1,3}[\s\-.]?\(?\d{1,4}\)?[\s\-.]?\d{2,4}[\s\-.]?\d{4}"  # +x (xx) xxxx-xxxx
    r"|\(\d{3}\)[\s\-.]?\d{3}[\s\-.]?\d{4}"                          # (555) 555-5555
    r"|\b\d{3}[\-\.]\d{3}[\-\.]\d{4}\b"                              # 555-555-5555
    r")(?!\d)",
    re.ASCII,
)

# Credit card patterns — known BIN prefixes with optional spacing/dashes
CREDIT_CARD_PATTERN = re.compile(
    r"(?<!\d)(?:"
    r"4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}"   # Visa 16-digit
    r"|5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}"  # MasterCard
    r"|3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}"              # Amex 15-digit
    r"|6011[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}"        # Discover
    r")(?!\d)"
)

API_KEY_PATTERNS = [
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),                     "Google API key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                           "AWS access key ID"),
    (re.compile(r"\bghp_[a-zA-Z0-9]{36}\b"),                        "GitHub personal access token"),
    (re.compile(r"\bgho_[a-zA-Z0-9]{36}\b"),                        "GitHub OAuth token"),
    (re.compile(r"\bsk_live_[a-zA-Z0-9]{24,}\b"),                   "Stripe live secret key"),
    (re.compile(r"\bpk_live_[a-zA-Z0-9]{24,}\b"),                   "Stripe live publishable key"),
    (re.compile(r"\bxox[baprs]-[0-9a-zA-Z\-]{10,}\b"),              "Slack token"),
    (re.compile(r"\bEAACEdEose[0-9a-zA-Z]+\b"),                     "Facebook access token"),
    (re.compile(
        r'(?:api[_\-]?key|apikey|api[_\-]?secret|access[_\-]?token)\s*[:=]\s*[\'"]([a-zA-Z0-9_\-]{20,})[\'"]',
        re.I
    ), "Generic API key assignment"),
]


class InfoDisclosureScanner(BaseScanner):
    """
    Checks for information disclosure via:
    - Response headers leaking software versions
    - HTML meta tags revealing CMS
    - HTML comments containing sensitive information
    - Sensitive path exposure (.git, .env, backups, SQL dumps)
    - Error page stack traces
    - Directory listing
    - Internal IP addresses in headers/HTML
    - Developer email addresses in HTML
    - API key patterns in page source
    - JavaScript source map exposure
    """

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        resp = self.http.get(url, allow_redirects=True)
        if not resp:
            return self.results

        self._check_headers(url, resp)
        self._check_meta_tags(url, resp.text)
        self._check_html_comments(url, resp.text)
        self._check_internal_ip_disclosure(url, resp)
        self._check_email_disclosure(url, resp.text)
        self._check_api_key_patterns(url, resp.text)
        self._check_pii_disclosure(url, resp.text)
        self._check_source_maps(url, resp.text)
        self._check_sensitive_paths(url)
        self._check_error_pages(url)
        self._check_directory_listing(url, resp)
        return self.results

    # ── Existing checks ───────────────────────────────────────────────────────

    def _check_headers(self, url: str, resp) -> None:
        for h in DISCLOSURE_HEADERS:
            val = resp.headers.get(h["key"], "")
            if val:
                has_version = bool(VERSION_PATTERN.search(val))
                severity    = "FAIL" if (h["severity"] == "FAIL" or has_version) else "WARN"
                if severity == "FAIL":
                    log_fail(logger, f"Info disclosure: {h['name']}: {val}")
                else:
                    log_warn(logger, f"Info disclosure: {h['name']}: {val}")
                self.results.append(self._result(
                    url, f"Info disclosure — {h['name']}", severity,
                    detail=f"{h['desc']}. Value: '{val}'. Fix: {h['fix']}"
                ))
            else:
                log_pass(logger, f"No {h['name']} disclosure")
                self.results.append(self._result(
                    url, f"Info disclosure — {h['name']}", "PASS"
                ))

    def _check_meta_tags(self, url: str, html: str) -> None:
        soup      = BeautifulSoup(html, "html.parser")
        generator = soup.find("meta", {"name": re.compile(r"generator", re.I)})

        if generator:
            content = generator.attrs.get("content", "")
            log_warn(logger, f"Meta generator tag reveals: {content}")
            self.results.append(self._result(
                url, "Info disclosure — meta generator", "WARN",
                detail=(
                    f"Meta generator tag reveals CMS/framework: '{content}'. "
                    "Fix: remove the generator meta tag from your HTML output. "
                    "In WordPress: add remove_action('wp_head', 'wp_generator') to functions.php"
                )
            ))
        else:
            log_pass(logger, "No meta generator tag found")
            self.results.append(self._result(
                url, "Info disclosure — meta generator", "PASS",
                detail="No meta generator tag found."
            ))

        for meta in soup.find_all("meta"):
            content = meta.attrs.get("content", "")
            if VERSION_PATTERN.search(content) and len(content) < 50:
                name = meta.attrs.get("name", meta.attrs.get("property", "unknown"))
                if name.lower() not in ("viewport", "og:url", "og:image"):
                    log_warn(logger, f"Meta tag '{name}' may leak version: {content}")
                    self.results.append(self._result(
                        url, f"Info disclosure — meta '{name}'", "WARN",
                        detail=f"Meta tag '{name}' contains version-like value: '{content}'."
                    ))

    def _check_html_comments(self, url: str, html: str) -> None:
        soup     = BeautifulSoup(html, "html.parser")
        comments = soup.find_all(string=lambda t: isinstance(t, Comment))

        sensitive_found = []
        for comment in comments:
            comment_text = str(comment).strip()
            if not comment_text:
                continue
            for pattern in SENSITIVE_COMMENT_PATTERNS:
                if pattern.search(comment_text):
                    preview = comment_text[:100].replace("\n", " ")
                    sensitive_found.append(preview)
                    break

        if sensitive_found:
            log_warn(logger, f"Sensitive HTML comments found on {url}: {len(sensitive_found)}")
            self.results.append(self._result(
                url, "Info disclosure — HTML comments", "WARN",
                detail=(
                    f"Found {len(sensitive_found)} HTML comment(s) with potentially sensitive content. "
                    f"Preview: '{sensitive_found[0]}'. "
                    "Fix: remove all developer comments before deploying to production."
                )
            ))
        else:
            log_pass(logger, "No sensitive HTML comments found")
            self.results.append(self._result(
                url, "Info disclosure — HTML comments", "PASS",
                detail="No sensitive content found in HTML comments."
            ))

    # ── New checks ────────────────────────────────────────────────────────────

    def _check_internal_ip_disclosure(self, url: str, resp) -> None:
        """Check response headers and HTML body for private/internal IP addresses."""
        found_ips = set()

        # Check headers
        for header_val in resp.headers.values():
            for ip in PRIVATE_IP_PATTERN.findall(str(header_val)):
                found_ips.add(ip)

        # Check HTML body
        for ip in PRIVATE_IP_PATTERN.findall(resp.text):
            found_ips.add(ip)

        if found_ips:
            ip_list = ", ".join(sorted(found_ips)[:5])
            log_warn(logger, f"Internal IPs disclosed on {url}: {ip_list}")
            self.results.append(self._result(
                url, "Info disclosure — internal IP addresses", "WARN",
                detail=(
                    f"Internal IP address(es) found in response: {ip_list}. "
                    "These may reveal network topology. "
                    "Fix: remove internal IPs from all response headers (Via, X-Forwarded-For) "
                    "and from error messages or HTML output."
                )
            ))
        else:
            log_pass(logger, f"No internal IPs disclosed on {url}")
            self.results.append(self._result(
                url, "Info disclosure — internal IP addresses", "PASS",
                detail="No internal IP addresses found in response headers or body."
            ))

    def _check_email_disclosure(self, url: str, html: str) -> None:
        """Check HTML source for developer or internal email addresses."""
        emails = set(EMAIL_PATTERN.findall(html))
        # Filter obviously public/placeholder domains
        dev_emails = {
            e for e in emails
            if e.split("@")[-1].lower() not in _PUBLIC_EMAIL_DOMAINS
        }

        if dev_emails:
            preview = ", ".join(sorted(dev_emails)[:3])
            log_warn(logger, f"Email addresses found on {url}: {preview}")
            self.results.append(self._result(
                url, "Info disclosure — email addresses", "WARN",
                detail=(
                    f"Email address(es) found in page source: {preview}. "
                    "Developer emails can be harvested for phishing or targeted attacks. "
                    "Fix: use contact forms instead of plain email addresses, or obfuscate them."
                )
            ))
        else:
            log_pass(logger, f"No internal email addresses found on {url}")
            self.results.append(self._result(
                url, "Info disclosure — email addresses", "PASS",
                detail="No developer email addresses found in page source."
            ))

    def _check_api_key_patterns(self, url: str, html: str) -> None:
        """Check HTML and inline scripts for exposed API keys and tokens."""
        found = []
        for pattern, name in API_KEY_PATTERNS:
            match = pattern.search(html)
            if match:
                # Show prefix of the key, not the full value
                key_preview = (match.group(1) if match.lastindex else match.group(0))[:12] + "..."
                found.append(f"{name} (starts: {key_preview})")

        if found:
            log_fail(logger, f"API key patterns found on {url}: {found[0]}")
            self.results.append(self._result(
                url, "Info disclosure — API keys in page source", "FAIL",
                detail=(
                    f"Potential API key(s) found in page source: {'; '.join(found)}. "
                    "Fix: never embed secret API keys in frontend code. "
                    "Use backend proxies for API calls requiring secret keys. "
                    "Rotate any exposed keys immediately."
                )
            ))
        else:
            log_pass(logger, f"No API key patterns found on {url}")
            self.results.append(self._result(
                url, "Info disclosure — API keys in page source", "PASS",
                detail="No common API key patterns found in page source."
            ))

    def _check_pii_disclosure(self, url: str, html: str) -> None:
        """Check page HTML for exposed PII — phone numbers and credit card patterns."""
        soup      = BeautifulSoup(html, "html.parser")
        text_body = soup.get_text(" ")

        phones = PHONE_PATTERN.findall(text_body)
        cards  = CREDIT_CARD_PATTERN.findall(html)

        findings = []
        if phones:
            preview = phones[0].strip()
            findings.append(f"{len(phones)} phone number(s) found (e.g. {preview})")
        if cards:
            findings.append(f"{len(cards)} credit card pattern(s) found")

        if findings:
            log_warn(logger, f"PII found on {url}: {'; '.join(findings)}")
            self.results.append(self._result(
                url, "PII disclosure — phone numbers / credit cards", "WARN",
                detail=(
                    f"Potential PII found in page source: {'; '.join(findings)}. "
                    "PII in HTML is indexed by search engines and cached in proxies. "
                    "Fix: ensure sensitive customer data is not rendered directly in HTML. "
                    "Use masked display (e.g. ***-***-1234) or deliver via authenticated API calls."
                )
            ))
        else:
            log_pass(logger, f"No PII (phone/card) patterns found on {url}")
            self.results.append(self._result(
                url, "PII disclosure — phone numbers / credit cards", "PASS",
                detail="No phone number or credit card patterns found in page source."
            ))

    def _check_source_maps(self, url: str, html: str) -> None:
        """Check if JavaScript source map (.js.map) files are publicly accessible."""
        soup    = BeautifulSoup(html, "html.parser")
        scripts = [
            s.attrs["src"] for s in soup.find_all("script", src=True)
            if s.attrs.get("src", "").endswith(".js")
        ]

        exposed = []
        for script_src in scripts[:5]:  # limit to first 5 to avoid too many requests
            map_url = urljoin(url, script_src) + ".map"
            resp    = self.http.get(map_url)
            if resp and resp.status_code == 200 and "sources" in resp.text:
                exposed.append(map_url)

        if exposed:
            log_warn(logger, f"Source maps accessible on {url}: {exposed[0]}")
            self.results.append(self._result(
                url, "Info disclosure — JavaScript source maps", "WARN",
                detail=(
                    f"Source map file(s) publicly accessible: {'; '.join(exposed[:3])}. "
                    "Source maps expose original unminified source code including comments and structure. "
                    "Fix: disable source map generation in production builds, or serve maps "
                    "only to authenticated developers."
                )
            ))
        else:
            log_pass(logger, f"No exposed source maps found on {url}")
            self.results.append(self._result(
                url, "Info disclosure — JavaScript source maps", "PASS",
                detail="No publicly accessible JavaScript source map files found."
            ))

    def _check_sensitive_paths(self, url: str) -> None:
        """Check for commonly exposed sensitive files and directories."""
        parsed   = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path, name, severity, fix in SENSITIVE_PATHS:
            target = base_url + path
            resp   = self.http.get(target, allow_redirects=False)
            if not resp:
                continue

            if resp.status_code == 200:
                log_fail(logger, f"Sensitive path accessible: {target}")
                self.results.append(self._result(
                    target, f"Info disclosure — {name}", severity,
                    detail=(
                        f"{name} is publicly accessible at {target}. "
                        f"Fix: {fix}"
                    )
                ))
            elif resp.status_code == 403:
                log_warn(logger, f"Sensitive path returns 403 (may exist): {target}")
                self.results.append(self._result(
                    target, f"Info disclosure — {name}", "WARN",
                    detail=(
                        f"{name} returned 403 at {target} — file may exist but access is restricted. "
                        f"Fix: {fix}"
                    )
                ))

    def _check_error_pages(self, url: str) -> None:
        """Trigger 404 and check if error pages expose stack traces or path info."""
        parsed   = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        probe    = base_url + "/nonexistent-path-probe-xyzabc123"

        resp = self.http.get(probe, allow_redirects=True)
        if not resp:
            return

        traces = [p for p in STACK_TRACE_PATTERNS if p.search(resp.text)]
        if traces:
            log_fail(logger, f"Stack trace in error page on {url}")
            self.results.append(self._result(
                probe, "Info disclosure — stack trace in error page", "FAIL",
                detail=(
                    "Error page exposes stack trace or framework internals. "
                    "This reveals file paths, class names, and application structure. "
                    "Fix: configure your framework to show generic error pages in production. "
                    "In Django: DEBUG=False. In Rails: config.consider_all_requests_local=false. "
                    "In PHP: display_errors=Off."
                )
            ))
        else:
            log_pass(logger, f"No stack trace in error page on {url}")
            self.results.append(self._result(
                probe, "Info disclosure — stack trace in error page", "PASS",
                detail="Error page does not appear to expose stack traces."
            ))

    def _check_directory_listing(self, url: str, resp) -> None:
        """Check if the server returns a directory listing instead of content."""
        found = [m for m in DIRECTORY_LISTING_MARKERS if m in resp.text]
        if found:
            log_fail(logger, f"Directory listing detected on {url}")
            self.results.append(self._result(
                url, "Info disclosure — directory listing", "FAIL",
                detail=(
                    "Server is returning a directory listing, exposing all files in this location. "
                    "Fix: disable directory listing. "
                    "In Apache: Options -Indexes. "
                    "In Nginx: remove 'autoindex on'. "
                    "In IIS: disable directory browsing in site settings."
                )
            ))
        else:
            log_pass(logger, f"No directory listing on {url}")
            self.results.append(self._result(
                url, "Info disclosure — directory listing", "PASS",
                detail="No directory listing detected."
            ))
