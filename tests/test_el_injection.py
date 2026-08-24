"""Tests for tblue.scanner.el_injection — ELInjectionScanner."""

from unittest.mock import MagicMock, patch
from tblue.scanner.el_injection import ELInjectionScanner

URL = "https://example.com"


def _make_scanner():
    return ELInjectionScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = {}
    return r


def test_target_unreachable_pass():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_clean_page_pass():
    """No EL patterns → PASS."""
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html><p>Hello</p></html>")):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] == "FAIL" for r in results)


def test_spring4shell_vulnerable_version_fails():
    """Spring Framework 5.3.17 disclosure → FAIL (Spring4Shell)."""
    s = _make_scanner()
    headers = {"x-powered-by": "Spring Boot/2.6.5"}
    body = "<html><p>Welcome to my Spring app</p><p>SpringFramework/5.3.17</p></html>"

    def se(url, **kw):
        if url == URL:
            return _resp(200, body, headers)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("spring4shell" in f["type"].lower() or "spring" in f["type"].lower() for f in fails)


def test_spring_whitelabel_error_warns():
    """Spring Boot WhiteLabel error page → WARN."""
    s = _make_scanner()
    body = """<html>
<body>
<h1>Whitelabel Error Page</h1>
<p>This application has no configured error view, so you are seeing this as a fallback.</p>
</body>
</html>"""
    headers = {"x-powered-by": "Spring Boot"}

    def se(url, **kw):
        if url == URL:
            return _resp(500, body, headers)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("whitelabel" in w["type"].lower() or "spring" in w["type"].lower() for w in warns)


def test_spel_error_in_response_fails():
    """SpEL evaluation error in response → FAIL."""
    s = _make_scanner()
    body = """<html><body>
<p>Error: org.springframework.expression.spel.SpelEvaluationException: EL1007E</p>
<p>Property or field 'secret' cannot be found</p>
</body></html>"""

    def se(url, **kw):
        if url == URL:
            return _resp(500, body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("spel" in f["type"].lower() or "spring.*expression" in f["type"].lower()
               or "expression language" in f["type"].lower() for f in fails)


def test_ognl_error_in_response_fails():
    """OGNL evaluation error → FAIL."""
    s = _make_scanner()
    body = """<html>
<p>OgnlException: Malformed expression: </p>
<p>at com.opensymphony.xwork2.ognl.OgnlUtil.compile(OgnlUtil.java:...</p>
</html>"""

    def se(url, **kw):
        if url == URL:
            return _resp(400, body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("ognl" in f["type"].lower() for f in fails)


def test_struts2_action_extension_warns():
    """URL with .action extension → WARN."""
    s = _make_scanner()
    struts_url = "https://example.com/login.action"
    body = "<html><p>Please log in</p></html>"

    def se(url, **kw):
        if url == struts_url:
            return _resp(200, body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(struts_url)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("struts" in w["type"].lower() or "action" in w["type"].lower() for w in warns)


def test_vulnerable_struts_version_fails():
    """Struts2 2.5.30 disclosure → FAIL."""
    s = _make_scanner()
    body = "<html><p>Apache Struts/2.5.30</p></html>"

    def se(url, **kw):
        if url == URL:
            return _resp(200, body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("struts" in f["type"].lower() or "ognl" in f["type"].lower() for f in fails)


def test_thymeleaf_exception_fails():
    """ThymeleafException in response → FAIL."""
    s = _make_scanner()
    body = """<html><body>
<p>TemplateProcessingException: Could not parse as expression: "${userInput}"</p>
</body></html>"""

    def se(url, **kw):
        if url == URL:
            return _resp(500, body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("thymeleaf" in f["type"].lower() for f in fails)


def test_unprocessed_el_expression_warns():
    """JSP EL expression artifact in response → WARN."""
    s = _make_scanner()
    body = "<html><p>Welcome ${param.username}</p></html>"

    def se(url, **kw):
        if url == URL:
            return _resp(200, body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("el" in w["type"].lower() or "expression" in w["type"].lower() for w in warns)


def test_struts_webconsole_accessible_fails():
    """Struts2 web console accessible → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html><p>App home</p></html>")
        if "/struts/webconsole.html" in url:
            return _resp(200, "<html><p>Struts debug console - OGNL eval</p></html>")
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("struts" in f["type"].lower() or "console" in f["type"].lower() for f in fails)


def test_jexl_error_warns():
    """JEXL evaluation error → WARN."""
    s = _make_scanner()
    body = """<html>
<p>org.apache.commons.jexl3.JexlException: could not evaluate expression</p>
</html>"""

    def se(url, **kw):
        if url == URL:
            return _resp(500, body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("jexl" in w["type"].lower() for w in warns)
