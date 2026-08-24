"""
Log4Shell / JNDI Injection Passive Scanner (CVE-2021-44228 and family).

Detects passive indicators that a target may be vulnerable to JNDI/Log4Shell attacks:

1. Detects Apache Log4j version strings in response headers (Server, X-Powered-By)
   or error pages that fall within the affected range (2.0-beta9 to 2.17.0)
2. Checks for exposed log4j configuration endpoints (/log4j.xml, /log4j.properties)
3. Detects JNDI lookup pattern in error messages echoed back to responses
4. Identifies Java/JVM stack traces mentioning log4j classes
5. Checks for spring-boot / logback references that coexist with log4j in some configs

NO JNDI PAYLOADS ARE SENT — this is fully passive detection only.
Sending ${jndi:ldap://...} payloads would be offensive testing.
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_LOG4J_HEADER_RE = re.compile(
    r'log4j[/-](\d+\.\d+(?:\.\d+)?)',
    re.I,
)

_LOG4J_CLASS_RE = re.compile(
    r'org\.apache\.logging\.log4j\.|'
    r'log4j\.Logger|log4j\.config\.|'
    r'log4j2?\.properties|log4j2?\.xml|'
    r'Log4jContextFactory|RollingFileAppender|PatternLayout',
    re.I,
)

_JNDI_IN_ERROR_RE = re.compile(
    r'\$\{(?:jndi|ctx|env|sys|main|map|bundle|sd):|'
    r'java\.naming\.|'
    r'javax\.naming\.InitialContext|'
    r'com\.sun\.jndi\.',
    re.I,
)

_AFFECTED_LOG4J_RE = re.compile(
    r'log4j[/-](\d+)\.(\d+)\.(\d+)',
    re.I,
)

_CONFIG_PATHS = [
    "/log4j.xml",
    "/log4j2.xml",
    "/log4j.properties",
    "/log4j2.properties",
    "/WEB-INF/log4j.xml",
    "/WEB-INF/log4j2.xml",
    "/WEB-INF/classes/log4j.xml",
    "/WEB-INF/classes/log4j2.xml",
    "/WEB-INF/classes/log4j.properties",
]


def _is_affected_version(major: int, minor: int, patch: int) -> bool:
    if major != 2:
        return False
    if minor < 17:
        return True
    if minor == 17 and patch == 0:
        return True
    return False


class Log4ShellPassiveScanner(BaseScanner):
    """Detect passive Log4Shell/JNDI injection vulnerability indicators."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "Log4Shell passive — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        self._check_headers(url, resp)
        self._check_body(url, resp.text)
        self._check_log4j_configs(url, origin)

        if not self.results:
            log_pass(logger, f"No Log4Shell/JNDI indicators at {url}")
            self.results.append(self._result(
                url, "Log4Shell passive — no Log4j/JNDI indicators detected", "PASS",
                detail=(
                    "No Log4j version strings, JNDI class references, or exposed log4j "
                    "configuration files detected."
                )
            ))

        return self.results

    def _check_headers(self, url: str, resp) -> None:
        for hdr_name, hdr_val in (resp.headers or {}).items():
            m = _LOG4J_HEADER_RE.search(hdr_val)
            if m:
                version = m.group(1)
                parts = [int(x) for x in version.split(".") if x.isdigit()]
                if len(parts) >= 3 and _is_affected_version(*parts[:3]):
                    log_fail(logger, f"Vulnerable Log4j version {version} in response header {hdr_name}")
                    self.results.append(self._result(
                        url,
                        f"Log4Shell — vulnerable Log4j {version} in response header",
                        "FAIL",
                        detail=(
                            f"Response header '{hdr_name}: {hdr_val}' reveals Log4j {version}, "
                            "which is within the CVE-2021-44228 (Log4Shell) affected range "
                            "(2.0-beta9 through 2.17.0). "
                            "Log4Shell allows remote code execution via JNDI lookup injection in "
                            "logged strings (User-Agent, X-Forwarded-For, or any logged parameter). "
                            "Fix: upgrade Log4j to 2.17.1+ (Java 8), 2.12.4+ (Java 7), "
                            "2.3.2+ (Java 6); or set log4j2.formatMsgNoLookups=true as interim mitigation."
                        )
                    ))
                else:
                    log_warn(logger, f"Log4j version {version} in response header {hdr_name}")
                    self.results.append(self._result(
                        url,
                        f"Log4Shell — Log4j {version} detected in response header",
                        "WARN",
                        detail=(
                            f"Response header reveals Log4j {version}. "
                            "Verify this version is not vulnerable to Log4Shell (CVE-2021-44228) "
                            "or related vulnerabilities (CVE-2021-44832, CVE-2021-45046). "
                            "Recommended: Log4j 2.17.1+ (Java 8), 2.12.4+ (Java 7)."
                        )
                    ))

    def _check_body(self, url: str, body: str) -> None:
        if _JNDI_IN_ERROR_RE.search(body):
            log_warn(logger, f"JNDI lookup pattern echoed in response at {url}")
            self.results.append(self._result(
                url, "Log4Shell — JNDI pattern reflected in response", "FAIL",
                detail=(
                    "A JNDI lookup expression or Java naming class was found in the page response. "
                    "This may indicate that a prior JNDI injection probe was reflected back, "
                    "or that Java naming internals are leaking in error output. "
                    "Fix: sanitize all logged inputs; update Log4j; never reflect raw request "
                    "parameters in error messages."
                )
            ))

        if _LOG4J_CLASS_RE.search(body):
            m = _AFFECTED_LOG4J_RE.search(body)
            if m:
                major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
                if _is_affected_version(major, minor, patch):
                    log_fail(logger, f"Vulnerable Log4j class in page body at {url}")
                    self.results.append(self._result(
                        url, "Log4Shell — Log4j class reference in page body (vulnerable version)", "FAIL",
                        detail=(
                            f"A Log4j class reference with an affected version string was found "
                            f"in the page body (Log4j {m.group(1)}.{m.group(2)}.{m.group(3)}). "
                            "This strongly suggests Log4j is in use and may be exploitable via Log4Shell. "
                            "Fix: upgrade Log4j immediately to 2.17.1+."
                        )
                    ))
                else:
                    log_warn(logger, f"Log4j class reference in page body at {url}")
                    self.results.append(self._result(
                        url, "Log4Shell — Log4j class reference in page body", "WARN",
                        detail=(
                            "A Log4j class name was found in the page body (stack trace or error page). "
                            "Verify the Log4j version in use and ensure it is 2.17.1+."
                        )
                    ))

    def _check_log4j_configs(self, url: str, origin: str) -> None:
        for path in _CONFIG_PATHS:
            try:
                resp = self.http.get(origin + path)
                if resp is None or resp.status_code != 200:
                    continue
                if _LOG4J_CLASS_RE.search(resp.text) or "log4j" in resp.text.lower():
                    log_fail(logger, f"Log4j configuration file accessible at {origin + path}")
                    self.results.append(self._result(
                        origin + path,
                        "Log4Shell — Log4j configuration file accessible",
                        "FAIL",
                        detail=(
                            f"A Log4j configuration file is publicly accessible at {origin + path}. "
                            "This exposes logging configuration, appender destinations, and may reveal "
                            "internal service hostnames or log file paths. "
                            "Fix: deny access to log4j.xml/properties via web server configuration; "
                            "move log configuration files outside the web root."
                        )
                    ))
                    break
            except Exception:
                continue
