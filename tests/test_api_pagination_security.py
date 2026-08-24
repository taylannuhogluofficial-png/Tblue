"""Tests for API Pagination Security scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestAPIPaginationSecurityScanner:
    def _scanner(self):
        from tblue.scanner.api_pagination_security import APIPaginationSecurityScanner
        return APIPaginationSecurityScanner(MagicMock())

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {"content-type": "application/json"}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_api_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp('{"data": []}', 200)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_large_response_without_pagination_warns(self):
        s = self._scanner()
        # Body > 50KB with no Link header triggers the size warning
        large_body = '{"total": 5000, "data": [' + ', '.join(
            ['{"id": ' + str(i) + ', "name": "user' + str(i) + '", "email": "user' + str(i) + '@example.com"}' for i in range(800)]
        ) + ']}'

        def get_side(url, **kwargs):
            if "/api/users" in url and "limit=" not in url:
                return self._resp(large_body, 200)
            return self._resp('{"data": []}', 200)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("pagination" in r["type"] or "count" in r["type"] for r in warns)

    def test_high_total_count_warns(self):
        s = self._scanner()
        body = '{"total_count": 50000, "data": [{"id": 1}]}'

        def get_side(url, **kwargs):
            if "/api/users" in url:
                return self._resp(body, 200)
            return self._resp('{}', 200)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("count" in r["type"] or "data" in r["type"] for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
