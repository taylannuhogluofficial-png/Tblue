"""Tests for tblue.scanner.spring_actuator — SpringActuatorScanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.spring_actuator import SpringActuatorScanner

URL = "https://example.com"


def _make_scanner():
    return SpringActuatorScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def test_no_endpoints_exposed():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=_resp(404)):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_actuator_root_exposed():
    s = _make_scanner()
    actuator_body = '{"_links":{"health":{"href":"/actuator/health"},"env":{"href":"/actuator/env"}}}'

    def se(url, **kw):
        if "/actuator" in url and "/actuator/" not in url:
            return _resp(body=actuator_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("Actuator" in f["type"] for f in fails)


def test_actuator_env_exposed():
    s = _make_scanner()
    env_body = '{"activeProfiles":["prod"],"properties":{"datasource":{"password":"secret"}}}'

    def se(url, **kw):
        if url.endswith("/actuator/env"):
            return _resp(body=env_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("env" in f["type"].lower() for f in fails)


def test_h2_console_exposed():
    s = _make_scanner()
    h2_body = '<html><body>Welcome to H2 Console</body></html>'

    def se(url, **kw):
        if "/h2-console" in url:
            return _resp(body=h2_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("H2" in f["type"] for f in fails)


def test_jolokia_exposed():
    s = _make_scanner()
    jolokia_body = '{"status": 200, "request": {"type": "list"}, "value": {}}'

    def se(url, **kw):
        if "/jolokia" in url:
            return _resp(body=jolokia_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("Jolokia" in f["type"] for f in fails)


def test_laravel_telescope_exposed():
    s = _make_scanner()
    telescope_body = '<html><body class="telescope laravel-app">Telescope</body></html>'

    def se(url, **kw):
        if "/telescope" in url:
            return _resp(body=telescope_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("Telescope" in f["type"] for f in fails)


def test_rails_info_exposed():
    s = _make_scanner()
    rails_body = '<html><body>Rails version 7.0 - Ruby 3.1</body></html>'

    def se(url, **kw):
        if "/rails/info" in url:
            return _resp(body=rails_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("Rails" in f["type"] for f in fails)


def test_200_but_no_confirmation_skipped():
    s = _make_scanner()
    # Returns 200 but body doesn't match any confirmation pattern
    def se(url, **kw):
        if "/actuator" in url:
            return _resp(200, "<html>404 Not Found</html>")
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    # Should not flag false positives without confirmation
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not fails


def test_probe_exception_handled():
    s = _make_scanner()
    def se(url, **kw):
        raise ConnectionError("timeout")
    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_django_debug_toolbar_fail():
    """/__debug__/ returning djdt body triggers FAIL (covers line 183)."""
    s = _make_scanner()

    def se(url, **kw):
        if "/__debug__" in url:
            return _resp(200, '<div id="djdt"><div class="djDebugPanelButton">DebugToolbar</div></div>')
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("Debug" in f["type"] for f in fails)


def test_generic_admin_panel_warns():
    """/admin/ returning 200 triggers WARN via else-branch (covers lines 187, 196-197)."""
    s = _make_scanner()

    def se(url, **kw):
        if url.endswith("/admin/"):
            return _resp(200, "<html><h1>Admin Panel</h1></html>")
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("Admin" in w["type"] for w in warns)


def test_probe_returns_none_skipped():
    """Probe returning None is skipped without crashing (covers line 164)."""
    s = _make_scanner()
    call_count = [0]

    def se(url, **kw):
        call_count[0] += 1
        return None  # all probes return None

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    # All probes skipped → PASS
    assert any(r["status"] == "PASS" for r in results)
    assert call_count[0] > 0
