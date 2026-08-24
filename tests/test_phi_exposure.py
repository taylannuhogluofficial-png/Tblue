"""Tests for PHIExposureScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.phi_exposure import PHIExposureScanner, _scan_body_for_phi

URL = "https://example.com"


class TestPHIExposure:
    def _scanner(self):
        return PHIExposureScanner(MagicMock())

    def _resp(self, body="", status=200, ct="application/json"):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {"content-type": ct}
        return r

    def test_no_phi_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp('{"status": "ok"}', status=200)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_ssn_pattern_fails(self):
        body = '{"user": {"ssn": "123-45-6789", "name": "John"}}'
        findings = _scan_body_for_phi(body)
        assert any("ssn" in f["type"] for f in findings)

    def test_date_of_birth_fails(self):
        body = '{"patient": {"date_of_birth": "1985-03-12", "id": 1}}'
        findings = _scan_body_for_phi(body)
        assert any("dob" in f["type"] or "birth" in f["type"] for f in findings)

    def test_diagnosis_field_fails(self):
        body = '{"record": {"diagnosis": "Type 2 Diabetes", "icd_code": "E11.9"}}'
        findings = _scan_body_for_phi(body)
        assert any("diagnosis" in f["type"] for f in findings)

    def test_fhir_resource_fails(self):
        body = '{"resourceType": "Patient", "id": "12345", "name": [{"text": "John Doe"}]}'
        findings = _scan_body_for_phi(body)
        assert any("fhir" in f["type"] for f in findings)

    def test_clean_json_passes(self):
        body = '{"products": [{"id": 1, "name": "Widget", "price": 9.99}]}'
        findings = _scan_body_for_phi(body)
        assert findings == []

    def test_html_response_skipped(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(
            "<html><body>Login required</body></html>", ct="text/html"
        )):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("", status=404)):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
