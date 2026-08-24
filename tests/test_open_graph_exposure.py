"""Tests for Open Graph / Social Metadata Exposure scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestOpenGraphExposureScanner:
    def _scanner(self):
        from tblue.scanner.open_graph_exposure import OpenGraphExposureScanner
        return OpenGraphExposureScanner(MagicMock())

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

    def test_no_og_tags_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html><body>Hello</body></html>")):
            results = s.scan(URL)
        assert any("no social metadata" in r["type"] for r in results)
        assert all(r["status"] == "PASS" for r in results)

    def test_clean_og_tags_pass(self):
        """Normal OG tags with no sensitive data → PASS."""
        s = self._scanner()
        body = '''
        <meta property="og:title" content="My Website">
        <meta property="og:description" content="A great website about things">
        <meta property="og:url" content="https://example.com/page">
        <meta property="og:image" content="https://example.com/img.png">
        '''
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        warns = [r for r in results if r["status"] == "WARN"]
        assert not fails
        assert not warns

    def test_internal_ip_in_og_url_fails(self):
        """og:url with internal IP → FAIL."""
        s = self._scanner()
        body = '<meta property="og:url" content="http://10.0.0.5/page">'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails
        assert any("og:url" in r["type"] for r in fails)

    def test_staging_url_in_og_image_fails(self):
        """og:image pointing to staging server → FAIL."""
        s = self._scanner()
        body = '<meta property="og:image" content="https://staging.internal.corp/img.png">'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("og:image" in r["type"] for r in fails)

    def test_email_in_og_description_warns(self):
        """Email address in og:description → WARN."""
        s = self._scanner()
        body = '<meta property="og:description" content="Contact john.doe@example.com for help">'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("email" in r["type"].lower() for r in warns)

    def test_staging_reference_in_title_warns(self):
        """Staging env name in og:title → WARN."""
        s = self._scanner()
        body = '<meta property="og:title" content="[STAGING] My App Dashboard">'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("staging" in r["type"].lower() or "environment" in r["type"].lower() for r in warns)

    def test_json_ld_with_email_warns(self):
        """JSON-LD with email address → WARN."""
        s = self._scanner()
        body = '''
        <script type="application/ld+json">
        {"@type": "Organization", "email": "info@example.com", "name": "My Org"}
        </script>
        '''
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("JSON-LD" in r["type"] or "PII" in r["type"] for r in warns)

    def test_192_168_url_fails(self):
        """192.168.x.x URL in OG tag → FAIL."""
        s = self._scanner()
        body = '<meta property="og:url" content="http://192.168.1.100/app">'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html></html>")):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")
            assert "type" in r


class TestHelpers:
    def test_extract_og_tags_from_body(self):
        from tblue.scanner.open_graph_exposure import _extract_og_tags
        body = '''<meta property="og:title" content="My Title">
                  <meta property="og:description" content="My Desc">'''
        tags = _extract_og_tags(body)
        assert tags.get("og:title") == "My Title"
        assert tags.get("og:description") == "My Desc"

    def test_internal_ip_detection(self):
        from tblue.scanner.open_graph_exposure import _is_internal_url
        assert _is_internal_url("http://10.0.0.1/page", "example.com")
        assert _is_internal_url("http://192.168.1.100/", "example.com")
        assert not _is_internal_url("https://example.com/page", "example.com")

    def test_staging_detection(self):
        from tblue.scanner.open_graph_exposure import _is_internal_url
        assert _is_internal_url("https://staging.example.com/page", "example.com")
        assert _is_internal_url("https://dev-app.company.com/", "company.com")

    def test_json_ld_pii_extraction(self):
        from tblue.scanner.open_graph_exposure import _scan_json_ld_for_pii
        blocks = [{"@type": "Person", "email": "john@example.com", "name": "John"}]
        pii = _scan_json_ld_for_pii(blocks)
        assert any("john@example.com" in p for p in pii)

    def test_json_ld_no_pii(self):
        from tblue.scanner.open_graph_exposure import _scan_json_ld_for_pii
        blocks = [{"@type": "Product", "name": "Widget", "price": "9.99"}]
        pii = _scan_json_ld_for_pii(blocks)
        assert not pii
