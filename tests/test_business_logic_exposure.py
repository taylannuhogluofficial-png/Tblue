"""Tests for Business Logic Exposure scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestBusinessLogicExposureScanner:
    def _scanner(self):
        from tblue.scanner.business_logic_exposure import BusinessLogicExposureScanner
        return BusinessLogicExposureScanner(MagicMock())

    def _resp(self, body="OK", status=200, headers=None):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_page_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>Welcome</html>", 404)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_client_price_calc_warns(self):
        from tblue.scanner.business_logic_exposure import _check_client_side_price_logic
        body = "var total = parseInt(price) * quantity;"
        findings = _check_client_side_price_logic(body, URL)
        assert any("client_price" in f["type"] for f in findings)

    def test_mass_assignment_fields_warns(self):
        from tblue.scanner.business_logic_exposure import _check_mass_assignment_fields
        body = '{"is_admin": false, "role": "user", "email": "user@example.com"}'
        findings = _check_mass_assignment_fields(body, URL)
        assert any("mass_assignment" in f["type"] for f in findings)

    def test_admin_api_with_admin_data_fails(self):
        from tblue.scanner.business_logic_exposure import _check_admin_api_accessible, _ADMIN_INDICATORS_RE
        http = MagicMock()
        r = MagicMock()
        r.status_code = 200
        r.text = '{"users": [{"is_admin": true, "role": "admin"}]}'
        http.get.return_value = r
        findings = _check_admin_api_accessible(http, "https://example.com")
        assert any("admin_api" in f["type"] for f in findings)

    def test_clean_body_passes(self):
        from tblue.scanner.business_logic_exposure import _check_client_side_price_logic
        findings = _check_client_side_price_logic("<html><p>Welcome</p></html>", URL)
        assert findings == []

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>OK</html>", 404)):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
