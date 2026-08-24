"""Tests for LaTeXInjectionPassiveScanner."""
from unittest.mock import MagicMock
from tblue.scanner.latex_injection_passive import LaTeXInjectionPassiveScanner


def _scanner():
    s = LaTeXInjectionPassiveScanner.__new__(LaTeXInjectionPassiveScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_latex_shell_escape():
    s = _scanner()
    s.http.get.return_value = _resp(
        r"\begin{document}\write18{id}\end{document}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "latex_injection_shell_escape" in types


def test_latex_file_read():
    s = _scanner()
    s.http.get.return_value = _resp(
        r"\begin{document}\input{/etc/passwd}\end{document}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "latex_injection_file_read" in types


def test_latex_error_disclosure():
    s = _scanner()
    s.http.get.return_value = _resp(
        "LaTeX Error: Undefined control sequence \\badcmd on line 5"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "latex_injection_error_disclosure" in types


def test_latex_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Regular HTML page</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "latex_injection_not_used"
    assert results[0]["status"] == "PASS"


def test_latex_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "latex_injection_not_used"
