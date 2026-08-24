"""Extra coverage for framework_config — lines 226-230 (_is_framework_config), 320, 335-336, 363-364."""

from unittest.mock import MagicMock, patch
from tblue.scanner.framework_config import (
    FrameworkConfigScanner, _is_framework_config, _has_sensitive_creds,
)

URL = "https://example.com"


def _make_scanner():
    return FrameworkConfigScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


# ── _is_framework_config config.xml path (lines 226-227) ─────────────────────

def test_is_framework_config_hibernate_config_xml():
    """config.xml with Hibernate config matches (line 226-227)."""
    body = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE hibernate-configuration PUBLIC "-//Hibernate/Hibernate Configuration DTD 3.0//EN"
  "http://hibernate.sourceforge.net/hibernate-configuration-3.0.dtd">
<hibernate-configuration>
  <session-factory>
    <property name="hibernate.connection.url">jdbc:mysql://localhost/mydb</property>
    <property name="hibernate.connection.password">s3cr3tP@ss</property>
  </session-factory>
</hibernate-configuration>"""
    assert _is_framework_config("/config.xml", body) is True


def test_is_framework_config_generic_configuration_tag():
    """config.xml with <configuration> tag matches (line 226-227 fallback)."""
    body = "<configuration><appSettings><add key='db' value='mydb'/></appSettings></configuration>"
    assert _is_framework_config("/config.xml", body) is True


def test_is_framework_config_config_xml_no_match():
    """config.xml without recognizable content returns False."""
    assert _is_framework_config("/config.xml", "Hello World") is False


# ── _is_framework_config app.php / mail.php path (lines 228-229) ─────────────

def test_is_framework_config_laravel_app_php_return_array():
    """Laravel config/app.php with 'return [' matches (lines 228-229)."""
    body = """<?php
return [
    'name' => 'My Application',
    'env' => env('APP_ENV', 'production'),
    'debug' => (bool) env('APP_DEBUG', false),
    'key' => env('APP_KEY'),
];"""
    assert _is_framework_config("/config/app.php", body) is True


def test_is_framework_config_laravel_mail_php():
    """Laravel config/mail.php with return [ matches (lines 228-229)."""
    body = "<?php\nreturn [\n    'driver' => 'smtp',\n    'host' => 'smtp.mailgun.org',\n];"
    assert _is_framework_config("/config/mail.php", body) is True


# ── _is_framework_config fallback returns False (line 230) ───────────────────

def test_is_framework_config_unknown_path_returns_false():
    """Unrecognized path with arbitrary content returns False (line 230)."""
    assert _is_framework_config("/some/unknown/file.cfg", "key=value") is False


# ── Log probe returns 200 but non-log body (line 320) ────────────────────────

def test_log_probe_non_log_content_skipped():
    """Log path returning 200 with regular HTML is skipped (line 320 continue)."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if "laravel.log" in url or "error.log" in url:
            # Returns 200 but with HTML content that is NOT log content
            return _resp(200, "<html><body><h1>Not a log file</h1></body></html>")
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    log_fails = [r for r in results if r["status"] == "FAIL" and "log" in r.get("type", "").lower()]
    assert not log_fails, f"HTML response from log path should not be flagged: {log_fails}"


# ── Log probe exception (lines 335-336) ──────────────────────────────────────

def test_log_probe_exception_continues():
    """Exception during log probe is caught and skipped (lines 335-336)."""
    s = _make_scanner()
    call_count = [0]

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        call_count[0] += 1
        raise ConnectionError("Connection reset")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    # Should not raise; scanner catches exceptions in probe loop
    assert isinstance(results, list)


# ── Config probe exception (lines 363-364) ────────────────────────────────────

def test_config_probe_exception_continues():
    """Exception during config probe is caught and skipped (lines 363-364)."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        # Log probes return 404, config probes raise exception
        if any(p in url for p in [".log", ".out", "server.log"]):
            return _resp(404)
        raise TimeoutError("Connection timed out")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    assert isinstance(results, list)
