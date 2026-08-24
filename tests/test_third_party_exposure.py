"""Tests for Third-Party Resource Exposure scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestThirdPartyExposureScanner:
    def _scanner(self):
        from tblue.scanner.third_party_exposure import ThirdPartyExposureScanner
        return ThirdPartyExposureScanner(MagicMock())

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

    def test_clean_page_passes(self):
        """Page with no external resources → PASS."""
        s = self._scanner()
        body = "<html><body><script src='/js/app.js'></script></body></html>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_high_third_party_count_warns(self):
        """More than 15 external origins → WARN."""
        s = self._scanner()
        scripts = "\n".join(
            f'<script src="https://cdn{i}.example{i}.com/lib.js"></script>'
            for i in range(20)
        )
        body = f"<html><head>{scripts}</head></html>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("origins" in r["type"].lower() or "third-party" in r["type"].lower() for r in warns)

    def test_tracking_domain_warns(self):
        """Google Analytics / DoubleClick embedded → WARN."""
        s = self._scanner()
        body = '<html><script src="https://www.googletagmanager.com/gtag/js"></script><script src="https://doubleclick.net/ads.js"></script></html>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("tracking" in r["type"].lower() or "risk" in r["type"].lower()
                   or "ad-network" in r["type"].lower() for r in warns)

    def test_external_script_without_sri_warns(self):
        """External <script> without integrity → WARN."""
        s = self._scanner()
        body = '<html><script src="https://cdn.example.net/lib.js"></script></html>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("sri" in r["type"].lower() or "integrity" in r["type"].lower() for r in warns)

    def test_external_script_with_sri_passes(self):
        """External script WITH integrity → no SRI warning."""
        s = self._scanner()
        body = ('<html><script src="https://cdn.example.net/lib.js" '
                'integrity="sha384-abc123" crossorigin="anonymous"></script></html>')
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        sri_warns = [r for r in results
                     if ("sri" in r.get("type", "").lower() or "integrity" in r.get("type", "").lower())
                     and r["status"] == "WARN"]
        assert not sri_warns

    def test_external_iframe_without_sandbox_warns(self):
        """External <iframe> without sandbox → WARN."""
        s = self._scanner()
        body = '<html><iframe src="https://partner.example.net/widget"></iframe></html>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("iframe" in r["type"].lower() or "sandbox" in r["type"].lower() for r in warns)

    def test_external_iframe_with_sandbox_passes(self):
        """External iframe WITH sandbox → no sandbox warning."""
        s = self._scanner()
        body = '<html><iframe src="https://partner.example.net/widget" sandbox="allow-scripts"></iframe></html>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        sandbox_warns = [r for r in results
                         if "sandbox" in r.get("type", "").lower() and r["status"] == "WARN"]
        assert not sandbox_warns

    def test_mixed_http_resource_warns(self):
        """HTTP resource on HTTPS page → WARN."""
        s = self._scanner()
        body = '<html><img src="http://cdn.example.net/logo.png"></html>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("http" in r["type"].lower() or "mixed" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html></html>")):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_is_external_true(self):
        from tblue.scanner.third_party_exposure import _is_external
        assert _is_external("https://cdn.example.net/lib.js", "example.com") is True

    def test_is_external_false(self):
        from tblue.scanner.third_party_exposure import _is_external
        assert _is_external("/js/app.js", "example.com") is False

    def test_is_external_same_host(self):
        from tblue.scanner.third_party_exposure import _is_external
        assert _is_external("https://example.com/js/app.js", "example.com") is False

    def test_is_high_risk_doubleclick(self):
        from tblue.scanner.third_party_exposure import _is_high_risk
        assert _is_high_risk("doubleclick.net") is True

    def test_is_high_risk_subdomain(self):
        from tblue.scanner.third_party_exposure import _is_high_risk
        assert _is_high_risk("www.hotjar.com") is True

    def test_is_high_risk_safe(self):
        from tblue.scanner.third_party_exposure import _is_high_risk
        assert _is_high_risk("cloudflare.com") is False

    def test_extract_third_parties(self):
        from tblue.scanner.third_party_exposure import _extract_third_parties
        body = '<script src="https://cdn.other.com/a.js"></script><script src="/local.js"></script>'
        parties = _extract_third_parties(body, "example.com")
        assert "cdn.other.com" in parties or "other.com" in parties

    def test_find_external_scripts_without_sri(self):
        from tblue.scanner.third_party_exposure import _find_external_scripts_without_sri
        body = '<script src="https://cdn.other.com/lib.js"></script>'
        missing = _find_external_scripts_without_sri(body, "example.com")
        assert missing

    def test_find_external_scripts_with_sri(self):
        from tblue.scanner.third_party_exposure import _find_external_scripts_without_sri
        body = '<script src="https://cdn.other.com/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>'
        missing = _find_external_scripts_without_sri(body, "example.com")
        assert not missing
