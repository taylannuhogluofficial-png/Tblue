"""LaTeX Injection Passive scanner — passive detection of LaTeX injection indicators in responses."""
import re
from .base import BaseScanner

_LATEX_ANY_RE = re.compile(
    r'(?:\\begin\{|\\end\{|\\input\{|\\include\{|'
    r'\\def\\|\\newcommand|\\usepackage|'
    r'LaTeX\s+Error|Undefined\s+control\s+sequence|kpathsea|'
    r'\.tex\b|application/x-tex|application/x-latex)',
    re.I,
)

_LATEX_CMD_INJECTION_RE = re.compile(
    r'\\(?:input|include|write18|immediate\\write18|'
    r'openout|closeout|read|openin)\s*\{[^}]{1,200}\}',
    re.I,
)

_LATEX_SHELL_ESCAPE_RE = re.compile(
    r'\\write18\s*\{[^}]{1,200}\}|'
    r'\\immediate\\write18\s*\{[^}]{1,200}\}',
    re.I,
)

_LATEX_FILE_READ_RE = re.compile(
    r'\\input\s*\{[^}]{0,200}(?:\.\.|/etc/|/proc/|passwd|shadow)[^}]*\}',
    re.I,
)

_LATEX_REFLECTED_PARAM_RE = re.compile(
    r'\\(?:input|include|def|newcommand)\s*\{[^}]{0,200}'
    r'(?:searchParams|location\.hash|userInput|req\.query)',
    re.I,
)

_LATEX_ERROR_DISCLOSURE_RE = re.compile(
    r'(?:LaTeX\s+Error|kpathsea|l\.\d+\s+\\|'
    r'Runaway\s+argument|Missing\s+\$\s+inserted|'
    r'Undefined\s+control\s+sequence)',
    re.I,
)


class LaTeXInjectionPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "latex_injection_not_used", "PASS")]

        body = resp.text
        if not _LATEX_ANY_RE.search(body):
            return [self._result(url, "latex_injection_not_used", "PASS")]

        findings = []

        if _LATEX_SHELL_ESCAPE_RE.search(body):
            findings.append(self._result(
                url, "latex_injection_shell_escape", "FAIL",
                detail=r"\write18 or \immediate\write18 command detected — shell escape in LaTeX executes OS commands; if user input is included in a LaTeX document sent to pdflatex with --shell-escape, full RCE is achieved.",
            ))

        if _LATEX_FILE_READ_RE.search(body):
            findings.append(self._result(
                url, "latex_injection_file_read", "FAIL",
                detail=r"\input{/etc/...} or path traversal pattern in LaTeX source — \input reads files from the server filesystem; attackers can exfiltrate /etc/passwd, application configs, or private keys via generated PDF.",
            ))

        if _LATEX_REFLECTED_PARAM_RE.search(body):
            findings.append(self._result(
                url, "latex_injection_param_in_command", "FAIL",
                detail=r"LaTeX command (\input, \include, \def) includes URL parameter — attacker-controlled LaTeX directive in generated document; enables file inclusion, variable redefinition, or shell escape.",
            ))

        if _LATEX_CMD_INJECTION_RE.search(body):
            findings.append(self._result(
                url, "latex_injection_command_present", "WARN",
                detail=r"LaTeX file I/O command (\input, \include, \openout, \read) in response — if this content is user-controlled, file read/write operations on the rendering server are possible.",
            ))

        if _LATEX_ERROR_DISCLOSURE_RE.search(body):
            findings.append(self._result(
                url, "latex_injection_error_disclosure", "WARN",
                detail="LaTeX engine error message (LaTeX Error, kpathsea, Undefined control sequence) in response — reveals LaTeX engine type, version, and file paths; enables targeted injection payload selection.",
            ))

        return findings or [self._result(url, "latex_injection_safe", "PASS")]
