"""
Command Injection Detection Scanner.

Detects OS command injection vulnerabilities by looking for parameters
commonly used in shell command construction and checking responses for
OS-specific output patterns.

Detection approach (strictly read-only):
1. Find parameters from URL query string and page forms
2. Probe with command injection payloads that produce detectable output
   when the command is executed (e.g., id, whoami output patterns)
3. Detect timing differences that indicate blind command injection
   (using sleep payloads with time measurement — kept minimal)
4. Check for error messages that reveal shell execution context

Parameters checked: cmd, exec, command, ping, query, shell, ip, host,
                    domain, lookup, resolve, dig, nslookup, trace

Payloads are read-only shell commands: id, whoami, hostname — never
destructive commands (rm, dd, wget from external, etc.)

CWE-78: Improper Neutralization of Special Elements used in an OS Command
"""

import re
import time
from typing import Any, Dict, List, Set
from urllib.parse import urlparse, parse_qs, urlencode

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Parameter names that commonly feed shell commands
_CMD_PARAMS = frozenset({
    "cmd", "exec", "command", "execute", "run", "shell",
    "ping", "query", "ip", "host", "hostname", "domain",
    "lookup", "resolve", "dig", "nslookup", "trace", "traceroute",
    "whois", "check", "test", "addr", "address",
})

# Command injection payloads — non-destructive; produce distinctive output
_CI_PAYLOADS = [
    ";id",
    "&&id",
    "|id",
    "$(id)",
    "`id`",
    ";whoami",
    "&&whoami",
    "|whoami",
    ";hostname",
    "&&hostname",
]

# Output patterns that indicate command execution
_CMD_OUTPUT_RE = re.compile(
    r"uid=\d+\(\w+\)|"          # Linux id output: uid=0(root)
    r"root|www-data|apache|"    # Common web user names
    r"^[a-zA-Z0-9\-]+$",        # Bare hostname (matched contextually)
    re.M,
)

# Linux uid/gid pattern specifically
_UID_GID_RE = re.compile(r"uid=\d+\([\w\-]+\)\s+gid=\d+\([\w\-]+\)", re.M)

# Shell error patterns that reveal command execution context
_SHELL_ERR_RE = re.compile(
    r"sh:.*not found|bash:.*command not found|"
    r"/bin/sh:|syntax error near|"
    r"command not found|unexpected EOF",
    re.I,
)

# Timing threshold for blind injection (seconds)
_BLIND_SLEEP_PAYLOAD = ";sleep 2"
_BLIND_THRESHOLD = 1.8


class CommandInjectionScanner(BaseScanner):
    """Detects OS command injection via output reflection and error disclosure."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping command injection checks: {url}")
            self.results.append(self._result(
                url, "Command injection — no response", "PASS",
                detail="Target did not respond; command injection checks skipped."
            ))
            return self.results

        body = resp.text or ""
        params = self._collect_params(url, body)

        if not params:
            log_pass(logger, f"No command-injection-prone parameters: {url}")
            self.results.append(self._result(
                url, "Command injection — no vulnerable parameter patterns found", "PASS",
                detail=(
                    "No URL parameters matching command injection risk patterns "
                    "(cmd, exec, host, ping, ip, etc.) were found."
                )
            ))
            return self.results

        for param in list(params)[:5]:  # Limit to 5 params per scan
            if self._probe_param(url, param):
                return self.results  # One finding per scan

        if not self.results:
            log_pass(logger, f"No command injection indicators: {url}")
            self.results.append(self._result(
                url, "Command injection — no indicators detected", "PASS",
                detail=(
                    "Command injection payloads did not produce OS command output "
                    "or shell error messages in responses."
                )
            ))

        return self.results

    def _collect_params(self, url: str, body: str) -> Set[str]:
        found: Set[str] = set()
        parsed = urlparse(url)
        for param in parse_qs(parsed.query):
            if param.lower() in _CMD_PARAMS:
                found.add(param)

        soup = BeautifulSoup(body, "html.parser")
        for inp in soup.find_all("input"):
            name = (inp.get("name") or "").lower()
            if name in _CMD_PARAMS:
                found.add(name)

        return found

    def _probe_param(self, url: str, param: str) -> bool:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        base_value = (params.get(param) or ["localhost"])[0]

        for payload in _CI_PAYLOADS[:6]:  # 6 payloads per param
            probe_query = dict(params)
            probe_query[param] = [f"{base_value}{payload}"]
            new_query = urlencode({k: v[0] for k, v in probe_query.items()})
            probe_url = parsed._replace(query=new_query).geturl()

            r = self.http.get(probe_url)
            if r is None:
                continue

            body = r.text or ""

            # Check for uid=gid= pattern (most definitive)
            if _UID_GID_RE.search(body):
                log_fail(logger, f"Command injection: uid/gid output via '{param}': {url}")
                self.results.append(self._result(
                    url,
                    f"Command injection — OS command output (uid/gid) via parameter '{param}'",
                    "FAIL",
                    detail=(
                        f"Injecting '{payload}' into '{param}' returned uid/gid output "
                        "from the OS id command. Remote OS command injection confirmed. "
                        "Fix: never pass user input to shell commands; "
                        "use library functions instead of shell (e.g., subprocess with list args, "
                        "not shell=True); validate ip/hostname inputs against strict regex."
                    )
                ))
                return True

            # Shell error messages (softer signal)
            if _SHELL_ERR_RE.search(body):
                log_warn(logger, f"Command injection: shell error via '{param}': {url}")
                self.results.append(self._result(
                    url,
                    f"Command injection — shell error message via parameter '{param}'",
                    "WARN",
                    detail=(
                        f"Injecting '{payload}' into '{param}' triggered a shell error "
                        "('command not found', 'unexpected EOF', etc.). "
                        "This strongly suggests the input is passed to a shell. "
                        "Fix: use subprocess with argument list (not string), "
                        "or use dedicated library functions (e.g., socket.gethostbyname "
                        "instead of calling nslookup)."
                    )
                ))
                return True

        # Timing-based blind detection (last resort, single probe)
        return self._probe_timing(url, param, params)

    def _probe_timing(self, url: str, param: str, params: dict) -> bool:
        probe_query = dict(params)
        probe_query[param] = [f"localhost{_BLIND_SLEEP_PAYLOAD}"]
        new_query = urlencode({k: v[0] for k, v in probe_query.items()})
        probe_url = urlparse(url)._replace(query=new_query).geturl()

        start = time.time()
        r = self.http.get(probe_url)
        elapsed = time.time() - start

        if r is None:
            return False

        if elapsed >= _BLIND_THRESHOLD:
            log_warn(logger, f"Command injection: timing delay {elapsed:.1f}s via '{param}': {url}")
            self.results.append(self._result(
                url,
                f"Command injection — timing delay {elapsed:.1f}s suggests blind injection via '{param}'",
                "WARN",
                detail=(
                    f"Injecting ';sleep 2' into '{param}' caused a {elapsed:.1f}s response delay. "
                    "This is consistent with blind OS command injection where the sleep "
                    "command executed server-side. "
                    "Fix: eliminate shell command construction from user input entirely."
                )
            ))
            return True

        return False
