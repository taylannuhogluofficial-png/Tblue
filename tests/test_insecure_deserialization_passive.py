"""Tests for Insecure Deserialization Passive scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestInsecureDeserializationPassiveScanner:
    def _scanner(self):
        from tblue.scanner.insecure_deserialization_passive import InsecureDeserializationPassiveScanner
        return InsecureDeserializationPassiveScanner(MagicMock())

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
        with patch.object(s.http, "get", return_value=self._resp("<html>OK</html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_java_serial_b64_fails(self):
        from tblue.scanner.insecure_deserialization_passive import _check_java_serialized
        findings = _check_java_serialized("data:rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", URL)
        assert any("b64" in f["type"] for f in findings)

    def test_java_serial_hex_fails(self):
        from tblue.scanner.insecure_deserialization_passive import _check_java_serialized
        findings = _check_java_serialized("stream=aced0005737200116a61766100", URL)
        assert any("hex" in f["type"] for f in findings)

    def test_php_object_injection_fails(self):
        from tblue.scanner.insecure_deserialization_passive import _check_php_object
        findings = _check_php_object('O:8:"UserData":2:{s:4:"name";s:5:"admin";}', URL)
        assert any("php_object" in f["type"] for f in findings)

    def test_viewstate_no_mac_warns(self):
        from tblue.scanner.insecure_deserialization_passive import _check_viewstate
        body = '<input name="__VIEWSTATE" value="' + 'A' * 120 + '"/>'
        findings = _check_viewstate(body, URL)
        assert any("no_mac" in f["type"] for f in findings)

    def test_clean_body_passes(self):
        from tblue.scanner.insecure_deserialization_passive import _check_java_serialized
        findings = _check_java_serialized("<html><body>Welcome</body></html>", URL)
        assert findings == []

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
