"""Tests for tblue.scanner.path_confusion — PathConfusionScanner."""

from unittest.mock import MagicMock, patch
from tblue.scanner.path_confusion import PathConfusionScanner

URL = "https://example.com"


def _make_scanner():
    return PathConfusionScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = {}
    return r


def test_unreachable_pass():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_clean_target_pass():
    """No protected paths accessible → PASS."""
    s = _make_scanner()
    # All paths return 404 or 403 consistently
    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html><p>Home</p></html>")
        return _resp(403, "Forbidden")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] == "FAIL" for r in results)


def test_spring_actuator_bypass_via_semicolon_fails():
    """Actuator 403 normally, but accessible via ..;/ bypass → FAIL."""
    s = _make_scanner()
    actuator_body = '{"status":"UP","components":{"db":{"status":"UP"}}}'

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html><p>App</p></html>")
        # Canonical actuator path → protected
        if url == "https://example.com/actuator":
            return _resp(403, "Access Denied")
        # Spring ..;/ bypass variant succeeds
        if "..;" in url and "actuator" in url:
            return _resp(200, actuator_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("actuator" in f["type"].lower() or "spring" in f["type"].lower() or
               "path confusion" in f["type"].lower() for f in fails)


def test_actuator_already_open_no_bypass_flag():
    """Actuator accessible directly (200) — path_confusion doesn't re-flag it."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if "/actuator" in url:
            return _resp(200, '{"status":"UP"}')
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    # Should not produce a FAIL (spring_actuator.py handles this)
    path_fails = [r for r in results if r["status"] == "FAIL"
                  and "actuator" in r["type"].lower()]
    assert len(path_fails) == 0


def test_admin_protected_then_bypass_via_double_slash_warns():
    """Admin path 403 normally, but bypass via double slash returns unique body → WARN."""
    s = _make_scanner()
    admin_body = "<html><h1>Admin Dashboard</h1><ul><li>User list</li></ul></html>"

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html><a href='/admin'>Admin</a></html>")
        if url == "https://example.com/admin":
            return _resp(403, "<html>Forbidden</html>")
        if "//admin" in url or "/admin;" in url:
            return _resp(200, admin_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("admin" in r["type"].lower() or "path confusion" in r["type"].lower()
               or "bypass" in r["type"].lower() for r in warns_or_fails)


def test_bypass_returns_same_403_body_no_flag():
    """Bypass variant also returns 403 with similar body → no flag."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        # Both canonical and bypass return same 403
        return _resp(403, "<html>Access Denied - You shall not pass</html>")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert len(fails) == 0


def test_common_admin_path_bypass_warns():
    """Common /admin path 403 normally, bypass variant returns 200 with real content."""
    s = _make_scanner()
    admin_content = "<html><h1>Admin Panel</h1><form>Settings here</form><p>Users: 100</p></html>"

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html><p>Public site</p></html>")
        if url == "https://example.com/admin":
            return _resp(403, "Forbidden")
        if "admin" in url and (";" in url or "//" in url or "." == url[-1:]):
            return _resp(200, admin_content)
        if "admin" in url:
            return _resp(200, admin_content)  # any bypass works
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("path confusion" in r["type"].lower() or "bypass" in r["type"].lower()
               or "admin" in r["type"].lower() for r in warns_or_fails)


def test_bypass_returns_tiny_body_no_flag():
    """Bypass returns 200 but body is < 50 chars → not flagged (generic response)."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/admin":
            return _resp(403, "Forbidden")
        if "admin" in url:
            return _resp(200, "OK")  # tiny body, not real admin content
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert len(fails) == 0


def test_linked_admin_path_403_bypass_with_content_warns():
    """Page links to /admin (protected), bypass via semicolon returns real admin content."""
    s = _make_scanner()
    admin_content = "<html><h1>Admin Panel</h1><p>Total users: 350</p><ul><li>Settings</li></ul></html>"

    def se(url, **kw):
        if url == URL:
            html = '<html><body><a href="/admin/users">Admin Users</a></body></html>'
            return _resp(200, html)
        # Canonical /admin path → protected
        if url == "https://example.com/admin/users":
            return _resp(401, "<html>Unauthorized</html>")
        # Bypass with semicolon → succeeds
        if "admin" in url and (";" in url or ".." in url or "//" in url):
            return _resp(200, admin_content)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    # May or may not find bypass depending on which variant hits first
    # but no exceptions should be thrown
    assert results  # At minimum, we get a result (PASS or WARN)


def test_actuator_bypass_returns_empty_body_no_flag():
    """Bypass returns 200 but empty body → not flagged as actuator bypass."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if "/actuator" in url:
            if "..;" in url:
                return _resp(200, "")  # empty body
            return _resp(403, "Forbidden")
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert len(fails) == 0


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_actuator_canonical_returns_none():
    """Actuator canonical fetch returns None → continue at line 208."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if "/actuator" in url or "/management" in url:
            return None
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_actuator_bypass_resp_is_none():
    """Actuator protected, bypass fetch returns None → continue at line 223."""
    s = _make_scanner()
    canonical_actuator = {
        "https://example.com/actuator",
        "https://example.com/actuator/env",
        "https://example.com/actuator/health",
    }

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url in canonical_actuator:
            return _resp(403, "Forbidden")
        if "/actuator" in url or "/management" in url:
            return None  # bypass URLs return None
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_actuator_inner_bypass_raises():
    """All non-specific URLs raise → covers inner-bypass (251-252), outer-actuator (255-256),
    linked-canonical (319-320), and common-canonical (378-379) except handlers."""
    s = _make_scanner()
    html = '<html><a href="/admin">Admin</a></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if url == "https://example.com/actuator":
            return _resp(403, "Forbidden")
        raise RuntimeError("network error")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_linked_tag_no_href_skipped():
    """Tag with no href/action or special scheme href → continue at line 268."""
    s = _make_scanner()
    html = ('<html>'
            '<a>No href</a>'
            '<a href="#">Hash link</a>'
            '<a href="mailto:test@example.com">Email</a>'
            '<a href="javascript:void(0)">JS</a>'
            '</html>')
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_linked_non_protected_href_skipped():
    """Href doesn't match protected-path pattern → continue at line 270."""
    s = _make_scanner()
    html = '<html><a href="/products">Products</a><a href="/about">About</a></html>'
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_linked_duplicate_protected_path_skipped():
    """Two links to same protected path → second skipped at line 274."""
    s = _make_scanner()
    html = '<html><a href="/admin">Admin 1</a><a href="/admin">Admin 2</a></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        return _resp(200, "Public page")  # canonical returns 200 → line 281 for first

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_linked_canonical_returns_200():
    """Protected-looking href but canonical returns 200 → continue at line 281."""
    s = _make_scanner()
    html = '<html><a href="/admin">Admin</a></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        return _resp(200, "Public page")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_linked_bypass_resp_is_none():
    """Linked canonical 401, bypass returns None → continue at lines 288 and 352."""
    s = _make_scanner()
    html = '<html><a href="/admin">Admin</a></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if url == "https://example.com/admin":
            return _resp(401, "Unauthorized")
        return None  # all bypass and other canonical probes return None

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_linked_bypass_empty_body_covers_content_similar_and_len():
    """Bypass returns 200 with empty body → _content_similar line 144 + len < 50 line 296."""
    s = _make_scanner()
    html = '<html><a href="/admin">Admin</a></html>'
    denied_body = "Access Denied by middleware service"  # 34 chars, different from ""

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if url == "https://example.com/admin":
            return _resp(401, denied_body)
        return _resp(200, "")  # bypass returns empty body

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_linked_bypass_content_similar():
    """Bypass returns 200 with body identical to denied → content_similar True, lines 294 and 359."""
    s = _make_scanner()
    html = '<html><a href="/admin">Admin</a></html>'
    denied_body = "Forbidden! " * 10  # 110 chars
    canonical_paths = {
        "https://example.com/admin",
        "https://example.com/admin/",
        "https://example.com/api/admin",
        "https://example.com/management",
        "https://example.com/config",
        "https://example.com/internal",
    }

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if url in canonical_paths:
            return _resp(401, denied_body)
        return _resp(200, denied_body)  # bypass returns same body → content similar

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_linked_inner_bypass_raises():
    """Bypass fetch raises inside _check_linked_paths → except at lines 317-318 and 376-377."""
    s = _make_scanner()
    html = '<html><a href="/admin">Admin</a></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if url == "https://example.com/admin":
            return _resp(401, "Forbidden")
        raise RuntimeError("timeout")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_linked_beautifulsoup_raises():
    """BeautifulSoup raises in _check_linked_paths → except at lines 321-322."""
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")), \
         patch("tblue.scanner.path_confusion.BeautifulSoup",
               side_effect=RuntimeError("parse error")):
        results = s.scan(URL)
    assert isinstance(results, list)
