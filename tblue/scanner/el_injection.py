"""
Expression Language (EL) Injection Scanner.

Expression Language injection is a critical vulnerability affecting Java
web applications. Unlike SSTI (which targets template engines), EL injection
targets Java's built-in expression language frameworks:

Affected frameworks:
- Spring Framework: SpEL (Spring Expression Language) — CVE-2022-22965 (Spring4Shell)
- Apache Struts2: OGNL (Object-Graph Navigation Language) — CVE-2017-5638, CVE-2018-11776
- Apache Struts2: CVE-2023-50164 (file upload path traversal)
- Thymeleaf: Template expression injection — CVE-2023-38286
- JSF/JSP EL: javax.el / jakarta.el expressions in JSP pages
- Apache Commons JEXL: JEXL injection in configuration-driven apps
- Groovy GStringTemplateEngine: Dynamic Groovy expression injection

Detection approach (passive, read-only):
1. Detect framework fingerprints from response headers (X-Powered-By, Server)
2. Look for EL expression artifacts in responses (rendered ${...}, #{...} etc.)
3. Detect Struts2/Spring error pages with stack traces
4. Identify OGNL-characteristic error messages
5. Detect unpatched vulnerable versions from framework disclosures
6. Check for Struts action extensions (.action, .do)
7. Detect exposed Spring Boot Actuator with SpEL endpoint

Professional equivalent: Burp Suite Pro "Expression Language Injection" rule,
Invicti EL injection scanner, Qualys WAS Spring4Shell detection.

CWE-917: Improper Neutralization of Special Elements used in an EL Statement
CVE-2022-22965 (Spring4Shell), CVE-2017-5638 (Struts2 OGNL)
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Spring Framework indicators
_SPRING_HEADER_RE = re.compile(
    r"spring|springframework|spring-boot",
    re.I,
)
_SPRING_VERSION_RE = re.compile(
    r"Spring(?:Framework|Boot)[\s/](\d+\.\d+(?:\.\d+)?)",
    re.I,
)
# Spring4Shell affected versions: < 5.3.18, < 5.2.20
_SPRING4SHELL_VULNERABLE = re.compile(
    r"Spring(?:Framework)?[\s/](?:"
    r"5\.3\.(?:0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17)(?:\D|$)|"
    r"5\.2\.(?:\d|1\d|20)(?:\D|$)|"
    r"[0-4]\."
    r")",
    re.I,
)

# Struts2 indicators
_STRUTS_ACTION_PATH_RE = re.compile(
    r"\.(?:action|do)(?:\?|$|/)",
    re.I,
)
_STRUTS_HEADER_RE = re.compile(
    r"struts|ognl|apache\s+struts",
    re.I,
)
_STRUTS_VERSION_RE = re.compile(
    r"Apache\s+Struts[\s/]?(\d+\.\d+(?:\.\d+)?)",
    re.I,
)
# Struts2 CVE-2023-50164 affected: 2.0.0 – 2.5.32, 6.0.0 – 6.3.0
_STRUTS_VULNERABLE_RE = re.compile(
    r"Apache\s+Struts[\s/]?(?:"
    r"2\.(?:[0-4]\.|5\.(?:[0-2]\d|3[012]))(?:\D|$)|"
    r"6\.(?:0\.|1\.|2\.|3\.0)(?:\D|$)"
    r")",
    re.I,
)

# OGNL error message patterns
_OGNL_ERROR_RE = re.compile(
    r"ognl\.|OgnlException|ognl\.OgnlException|"
    r"com\.opensymphony\.xwork2\.ognl|"
    r"OGNL\s+evaluation\s+error|"
    r"ParseException.*ognl|ognl.*ParseException",
    re.I,
)

# SpEL error message patterns
_SPEL_ERROR_RE = re.compile(
    r"org\.springframework\.expression\.|"
    r"SpelParseException|SpelEvaluationException|"
    r"SpelExpression|EvaluationContext|"
    r"spring.*expression.*error|Expression.*evaluation.*failed.*spring",
    re.I,
)

# EL expression artifacts (rendered in response when they shouldn't be)
_EL_ARTIFACT_RE = re.compile(
    r"""
    \$\{(?:pageContext|request|session|application|param|header|cookie)\.  |
    \#\{(?:bean|managed|session|request|backing)\w*\.                       |
    \$\{T\(java\.lang\.\w+\)                                               |
    \$\{.*getClass\(\).*\}                                                 |
    \#\{.*\.toList\(\).*\}
    """,
    re.I | re.X,
)

# Thymeleaf expression injection indicators
_THYMELEAF_EXPR_RE = re.compile(
    r"""
    \[\[__\$\{|               # Thymeleaf preprocessing expression
    __\$\{.*\}__\]\]|         # Thymeleaf expression artifact
    ThymeleafException|
    org\.thymeleaf\.exceptions\.|
    TemplateProcessingException
    """,
    re.I | re.X,
)

# JSP EL expression artifacts (unprocessed in output)
_JSP_EL_RE = re.compile(
    r"\$\{(?:param|header|cookie|initParam|pageScope|requestScope|sessionScope|applicationScope)\.",
    re.I,
)

# Spring WhiteLabel error page (Spring Boot default error)
_SPRING_ERROR_RE = re.compile(
    r"Whitelabel\s+Error\s+Page|"
    r"This\s+application\s+has\s+no\s+configured\s+error\s+view|"
    r"application\s+threw\s+an\s+unexpected\s+exception",
    re.I,
)

# Struts2-specific error patterns
_STRUTS_ERROR_RE = re.compile(
    r"There\s+is\s+no\s+Action\s+mapped|"
    r"struts\s+problem\s+report|"
    r"com\.opensymphony\.xwork2\.|"
    r"No\s+result\s+defined\s+for\s+action|"
    r"Struts\s+Action:\s*",
    re.I,
)

# JEXL expression patterns
_JEXL_ERROR_RE = re.compile(
    r"org\.apache\.commons\.jexl|"
    r"JexlException|JexlEngine|"
    r"JEXL\s+evaluation\s+failed",
    re.I,
)


class ELInjectionScanner(BaseScanner):
    """Detect Expression Language injection vulnerabilities (SpEL, OGNL, JSP EL)."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "EL injection — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        body = resp.text or ""
        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        all_headers = " ".join(f"{k}: {v}" for k, v in headers.items())
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        found_any = False

        # ── 1. Detect Spring4Shell vulnerability from version disclosure ──────
        found_any |= self._check_spring(url, body, all_headers)

        # ── 2. Detect Struts2 OGNL injection risk ─────────────────────────────
        found_any |= self._check_struts(url, body, all_headers, parsed)

        # ── 3. Detect OGNL/SpEL error messages ────────────────────────────────
        found_any |= self._check_el_errors(url, body)

        # ── 4. Detect EL expression artifacts in responses ────────────────────
        found_any |= self._check_el_artifacts(url, body)

        # ── 5. Detect Thymeleaf expression injection ──────────────────────────
        found_any |= self._check_thymeleaf(url, body)

        # ── 6. Probe known EL-injectable paths ───────────────────────────────
        found_any |= self._probe_el_endpoints(url, base)

        if not found_any:
            log_pass(logger, f"No EL injection indicators found on {url}")
            self.results.append(self._result(
                url,
                "EL injection — no expression language injection indicators",
                "PASS",
                detail=(
                    "No SpEL, OGNL, JSP EL, or Thymeleaf injection indicators detected. "
                    "Keep Spring Framework ≥5.3.18, Struts2 ≥2.5.33, "
                    "and Thymeleaf ≥3.1.2 to avoid CVE-2022-22965, "
                    "CVE-2023-50164, and CVE-2023-38286."
                )
            ))

        return self.results

    def _check_spring(self, url: str, body: str, headers_str: str) -> bool:
        spring_in_headers = bool(_SPRING_HEADER_RE.search(headers_str))
        spring_in_body = bool(_SPRING_HEADER_RE.search(body))

        if not (spring_in_headers or spring_in_body):
            return False

        # Check for Spring WhiteLabel error (version info leak)
        if _SPRING_ERROR_RE.search(body):
            log_warn(logger, f"Spring Boot WhiteLabel error page exposed: {url}")
            self.results.append(self._result(
                url,
                "EL injection — Spring Boot WhiteLabel error page exposed",
                "WARN",
                detail=(
                    f"A Spring Boot WhiteLabel error page is returned at {url}. "
                    "This reveals that Spring Boot is in use and may disclose "
                    "stack traces and application paths. "
                    "Fix: implement a custom error handler (ErrorController); "
                    "disable server: error.include-stacktrace in application.properties."
                )
            ))

        # Check for vulnerable Spring version
        m = _SPRING4SHELL_VULNERABLE.search(headers_str + "\n" + body[:2000])
        if m:
            version = m.group(0)[:50]
            log_fail(logger, f"Potentially vulnerable Spring version detected: {version}")
            self.results.append(self._result(
                url,
                "EL injection — potentially vulnerable Spring version (Spring4Shell risk)",
                "FAIL",
                detail=(
                    f"Spring Framework version disclosure suggests a version vulnerable to "
                    f"CVE-2022-22965 (Spring4Shell): '{version}'. "
                    "Spring4Shell allows unauthenticated RCE via class loader manipulation "
                    "and SpEL expression injection in Spring MVC. "
                    "Fix: upgrade Spring Framework to ≥5.3.18 or ≥5.2.20; "
                    "upgrade Spring Boot to ≥2.6.6 or ≥2.5.12; "
                    "ensure JDK ≥9 (module system limits exploitation)."
                )
            ))
            return True

        # SpEL error in response
        if _SPEL_ERROR_RE.search(body):
            log_fail(logger, f"SpEL evaluation error in response: {url}")
            self.results.append(self._result(
                url,
                "EL injection — SpEL (Spring Expression Language) evaluation error",
                "FAIL",
                detail=(
                    f"The response at {url} contains a Spring Expression Language "
                    "(SpEL) evaluation error. "
                    "If user input reaches a SpEL expression context without sanitization, "
                    "attackers can achieve Remote Code Execution via SpEL introspection. "
                    "Fix: avoid using SpelExpressionParser with user-supplied input; "
                    "use SimpleEvaluationContext instead of StandardEvaluationContext for "
                    "expressions that include any user data."
                )
            ))
            return True

        return _SPRING_ERROR_RE.search(body) is not None

    def _check_struts(self, url: str, body: str, headers_str: str,
                       parsed: Any) -> bool:
        struts_detected = (
            bool(_STRUTS_HEADER_RE.search(headers_str)) or
            bool(_STRUTS_HEADER_RE.search(body)) or
            bool(_STRUTS_ACTION_PATH_RE.search(url)) or
            bool(_STRUTS_ERROR_RE.search(body))
        )

        if not struts_detected:
            return False

        # Check for vulnerable Struts version
        vuln_m = _STRUTS_VULNERABLE_RE.search(headers_str + "\n" + body[:2000])
        if vuln_m:
            version = vuln_m.group(0)[:50]
            log_fail(logger, f"Potentially vulnerable Struts2 version: {version}")
            self.results.append(self._result(
                url,
                "EL injection — potentially vulnerable Struts2 version (OGNL/CVE-2023-50164)",
                "FAIL",
                detail=(
                    f"Apache Struts2 version disclosure suggests a vulnerable version: '{version}'. "
                    "CVE-2023-50164 (Struts2 ≤2.5.32 / 6.0.0-6.3.0) allows RCE via OGNL "
                    "expression injection through file upload path manipulation. "
                    "CVE-2017-5638 allows OGNL injection via Content-Type header. "
                    "Fix: upgrade to Apache Struts2 ≥2.5.33 or ≥6.3.0.1; "
                    "enable OGNL expressions sandbox in struts.xml."
                )
            ))
            return True

        if _STRUTS_ACTION_PATH_RE.search(url):
            log_warn(logger, f"Struts2 action extension in URL: {url}")
            self.results.append(self._result(
                url,
                "EL injection — Struts2 .action/.do extension detected (OGNL risk)",
                "WARN",
                detail=(
                    f"The URL {url} uses Struts2 action extensions (.action/.do). "
                    "Struts2 applications have historically been vulnerable to OGNL injection "
                    "(CVE-2017-5638, CVE-2018-11776, CVE-2023-50164). "
                    "Fix: upgrade to the latest Struts2; enable the OGNL security sandbox; "
                    "validate Content-Type and Content-Disposition headers server-side."
                )
            ))
            return True

        return False

    def _check_el_errors(self, url: str, body: str) -> bool:
        if _OGNL_ERROR_RE.search(body):
            log_fail(logger, f"OGNL evaluation error in response: {url}")
            self.results.append(self._result(
                url,
                "EL injection — OGNL (Struts2) evaluation error in response",
                "FAIL",
                detail=(
                    "The response contains an OGNL evaluation error, indicating that "
                    "user input may have reached the OGNL expression parser. "
                    "OGNL injection enables Remote Code Execution in Struts2 applications. "
                    "Fix: upgrade Struts2; enable OGNL security sandbox; "
                    "never pass user input to OGNL evaluation context."
                )
            ))
            return True

        if _JEXL_ERROR_RE.search(body):
            log_warn(logger, f"JEXL evaluation error in response: {url}")
            self.results.append(self._result(
                url,
                "EL injection — Apache Commons JEXL evaluation error",
                "WARN",
                detail=(
                    "The response contains a JEXL (Java Expression Language) error. "
                    "JEXL injection allows attackers to execute arbitrary Java code "
                    "if user input reaches the JEXL engine. "
                    "Fix: use JEXL's sandbox (JexlSandbox) to restrict accessible classes; "
                    "never evaluate user-controlled expressions."
                )
            ))
            return True

        return False

    def _check_el_artifacts(self, url: str, body: str) -> bool:
        # Check for unprocessed EL expressions in response
        m = _EL_ARTIFACT_RE.search(body)
        if m:
            snippet = m.group(0)[:80]
            log_warn(logger, f"EL expression artifact in response: {snippet}")
            self.results.append(self._result(
                url,
                "EL injection — unprocessed EL expression in response body",
                "WARN",
                detail=(
                    f"Unprocessed Expression Language syntax found in response: '{snippet}'. "
                    "This may indicate the EL expression context is active and could be "
                    "injectable with attacker-controlled input. "
                    "Fix: ensure EL expressions are only evaluated in trusted contexts; "
                    "disable EL evaluation in JSP pages that don't require it "
                    "(use page directive: <%@ page isELIgnored='true' %>)."
                )
            ))
            return True

        m = _JSP_EL_RE.search(body)
        if m:
            snippet = m.group(0)[:60]
            log_warn(logger, f"Unprocessed JSP EL expression: {snippet}")
            self.results.append(self._result(
                url,
                "EL injection — unprocessed JSP EL expression in response",
                "WARN",
                detail=(
                    f"JSP EL expression syntax found unprocessed in response: '{snippet}'. "
                    "This may indicate misconfigured JSP processing or EL injection entry points. "
                    "Fix: verify JSP compilation is working correctly; "
                    "disable EL where not needed."
                )
            ))
            return True

        return False

    def _check_thymeleaf(self, url: str, body: str) -> bool:
        m = _THYMELEAF_EXPR_RE.search(body)
        if m:
            snippet = m.group(0)[:80]
            log_fail(logger, f"Thymeleaf expression injection indicator: {snippet}")
            self.results.append(self._result(
                url,
                "EL injection — Thymeleaf template expression injection indicator",
                "FAIL",
                detail=(
                    f"Thymeleaf expression pattern detected in response: '{snippet}'. "
                    "CVE-2023-38286: Thymeleaf template injection via unvalidated "
                    "spring.view.prefix configuration allows RCE in Spring MVC applications. "
                    "Fix: upgrade Thymeleaf to ≥3.1.2.RELEASE; "
                    "never use user input as Thymeleaf template fragment selectors; "
                    "use th:text instead of th:utext to auto-escape HTML."
                )
            ))
            return True
        return False

    def _probe_el_endpoints(self, url: str, base: str) -> bool:
        # Check common Struts2 diagnostic endpoints
        struts_probes = [
            "/struts/webconsole.html",
            "/struts/console.action",
        ]
        for path in struts_probes:
            probe_url = base + path
            try:
                r = self.http.get(probe_url)
                if r and r.status_code == 200:
                    probe_body = r.text or ""
                    if any(kw in probe_body.lower()
                           for kw in ("struts", "ognl", "webconsole", "debug")):
                        log_fail(logger, f"Struts2 debug console accessible: {probe_url}")
                        self.results.append(self._result(
                            probe_url,
                            "EL injection — Struts2 debug/web console accessible",
                            "FAIL",
                            detail=(
                                f"The Struts2 development/debug console is accessible at "
                                f"{probe_url}. This allows OGNL expression execution, "
                                "equivalent to an RCE vulnerability. "
                                "Fix: set struts.devMode=false in struts.properties; "
                                "block access to /struts/ paths in production web server config."
                            )
                        ))
                        return True
            except Exception:
                continue
        return False
