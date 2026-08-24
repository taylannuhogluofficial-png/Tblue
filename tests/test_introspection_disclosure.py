"""Tests for API Introspection / Debug Mode Disclosure scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestIntrospectionDisclosureScanner:
    def _scanner(self):
        from tblue.scanner.introspection_disclosure import IntrospectionDisclosureScanner
        return IntrospectionDisclosureScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        r.url = URL
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_debug_endpoints_passes(self):
        """No debug endpoints return 200 → PASS."""
        s = self._scanner()
        not_found = self._resp("", 404)
        root = self._resp("<html>ok</html>", 200)

        def get_side(url, **kwargs):
            return root if url == URL else not_found

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_werkzeug_debugger_fails(self):
        """/__debugger__ returns Werkzeug debug UI → FAIL."""
        s = self._scanner()
        debug_body = "Werkzeug Debugger\nTraceback (most recent call last):"
        root = self._resp("<html>ok</html>", 200)

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "__debugger__" in url:
                return self._resp(debug_body, 200)
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("werkzeug" in r["type"].lower() or "debug" in r["type"].lower() for r in fails)

    def test_phpinfo_fails(self):
        """/phpinfo.php returns PHP info page → FAIL."""
        s = self._scanner()
        phpinfo_body = "<html><head><title>phpinfo()</title></head><body>PHP Version 8.1.0</body></html>"
        root = self._resp("<html>ok</html>", 200)

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "phpinfo" in url:
                return self._resp(phpinfo_body, 200)
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("phpinfo" in r["type"].lower() or "php" in r["type"].lower() for r in fails)

    def test_prometheus_metrics_warns(self):
        """/metrics returns Prometheus metrics → WARN."""
        s = self._scanner()
        metrics_body = "# HELP go_goroutines Number of goroutines\n# TYPE go_goroutines gauge\ngo_goroutines 42\n"
        root = self._resp("<html>ok</html>", 200)

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if url.endswith("/metrics"):
                return self._resp(metrics_body, 200)
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("prometheus" in r["type"].lower() or "metrics" in r["type"].lower() for r in warns_or_fails)

    def test_fastapi_docs_warns(self):
        """/docs returns Swagger UI → WARN."""
        s = self._scanner()
        docs_body = '<html><title>FastAPI</title><div id="swagger-ui"></div></html>'
        root = self._resp("<html>ok</html>", 200)

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if url.endswith("/docs"):
                return self._resp(docs_body, 200)
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        bad = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("swagger" in r["type"].lower() or "fastapi" in r["type"].lower()
                   or "docs" in r["type"].lower() for r in bad)

    def test_spring_env_actuator_fails(self):
        """/actuator/env returns Spring environment → FAIL."""
        s = self._scanner()
        env_body = '{"activeProfiles":["prod"],"propertySources":[{"name":"applicationConfig","properties":{"db.password":{"value":"secret"}}}]}'
        root = self._resp("<html>ok</html>", 200)

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "actuator/env" in url:
                return self._resp(env_body, 200)
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("spring" in r["type"].lower() or "actuator" in r["type"].lower() or "env" in r["type"].lower() for r in fails)

    def test_pprof_profiler_fails(self):
        """/debug/pprof returns Go profiler → FAIL."""
        s = self._scanner()
        pprof_body = "<html><pre>Types of profiles available:\nCount\tProfile\n 42\theap</pre></html>"
        root = self._resp("<html>ok</html>", 200)

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "pprof" in url and "/heap" not in url:
                return self._resp(pprof_body, 200)
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("pprof" in r["type"].lower() or "go" in r["type"].lower() for r in fails)

    def test_result_structure(self):
        s = self._scanner()
        not_found = self._resp("", 404)
        with patch.object(s.http, "get", return_value=not_found):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")
