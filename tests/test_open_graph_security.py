"""Tests for Open Graph Security scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestOpenGraphSecurityScanner:
    def _scanner(self):
        from tblue.scanner.open_graph_security import OpenGraphSecurityScanner
        return OpenGraphSecurityScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_og_tags_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html><head></head></html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_og_image_http_warns(self):
        s = self._scanner()
        body = '<meta property="og:image" content="http://cdn.example.com/image.jpg">'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("mixed" in r["type"].lower() or "og" in r["type"].lower() for r in warns)

    def test_og_url_domain_mismatch_warns(self):
        s = self._scanner()
        body = '<meta property="og:url" content="https://evil.com/page">'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("mismatch" in r["type"].lower() or "domain" in r["type"].lower() for r in warns)

    def test_json_ld_external_context_warns(self):
        s = self._scanner()
        body = '<script type="application/ld+json">{"@context": "https://schema.attacker.com", "@type": "Article"}</script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("json" in r["type"].lower() or "context" in r["type"].lower() for r in warns)

    def test_json_ld_schema_org_ok(self):
        s = self._scanner()
        body = '<script type="application/ld+json">{"@context": "https://schema.org", "@type": "Article"}</script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        assert not any("json-ld-external" in r.get("type", "") for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_og_tags_mixed_content(self):
        from tblue.scanner.open_graph_security import _check_og_tags
        body = '<meta property="og:image" content="http://cdn.example.com/img.jpg">'
        findings = _check_og_tags(body, "https://example.com", "example.com")
        assert any("mixed" in f["type"].lower() for f in findings)

    def test_check_og_tags_domain_mismatch(self):
        from tblue.scanner.open_graph_security import _check_og_tags
        body = '<meta property="og:url" content="https://evil.com/page">'
        findings = _check_og_tags(body, "https://example.com", "example.com")
        assert any("mismatch" in f["type"].lower() for f in findings)

    def test_check_json_ld_external_context(self):
        from tblue.scanner.open_graph_security import _check_json_ld
        body = '<script type="application/ld+json">{"@context": "https://evil.com/context"}</script>'
        findings = _check_json_ld(body, URL)
        assert any("context" in f["type"].lower() for f in findings)

    def test_check_json_ld_schema_org_ok(self):
        from tblue.scanner.open_graph_security import _check_json_ld
        body = '<script type="application/ld+json">{"@context": "https://schema.org"}</script>'
        findings = _check_json_ld(body, URL)
        assert findings == []
