"""Tests for Elasticsearch / OpenSearch exposure scanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.elasticsearch_exposure import ElasticsearchExposureScanner


def _resp(body="", status=200):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    return r


class TestElasticsearchExposure(unittest.TestCase):

    def _scanner(self):
        s = ElasticsearchExposureScanner.__new__(ElasticsearchExposureScanner)
        s.http = MagicMock()
        s.results = []
        s._result = lambda url, ftype, sev, detail="": {
            "url": url, "type": ftype, "severity": sev, "detail": detail
        }
        return s

    def _not_found(self):
        return _resp("", 404)

    def test_no_exposure_returns_pass(self):
        s = self._scanner()
        s.http.get.return_value = self._not_found()
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("elasticsearch_not_exposed", types)

    def test_unauthenticated_access_detected(self):
        s = self._scanner()
        es_body = '{"cluster_name":"my-cluster","tagline":"You Know, for Search"}'

        def get_side(url, **kw):
            if ":9200/" in url and not "_cat" in url and not "cluster" in url:
                return _resp(es_body, 200)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("elasticsearch_unauthenticated_access", types)

    def test_auth_enforced_pass(self):
        s = self._scanner()

        def get_side(url, **kw):
            if ":9200/" in url:
                return _resp("Unauthorized", 401)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("elasticsearch_auth_enforced", types)

    def test_index_listing_exposed(self):
        s = self._scanner()
        cat_body = '[{"index":"users"},{"index":"payments"},{"index":"sessions"}]'

        def get_side(url, **kw):
            if "_cat/indices" in url:
                return _resp(cat_body, 200)
            if ":9200/" in url:
                return _resp('{"cluster_name":"x"}', 200)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("elasticsearch_index_listing", types)

    def test_opensearch_detected(self):
        s = self._scanner()
        os_body = '{"distribution":"opensearch","version":{"number":"2.5.0"}}'

        def get_side(url, **kw):
            if ":9200/" in url and not "_cat" in url and not "cluster" in url:
                return _resp(os_body, 200)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("elasticsearch_unauthenticated_access", types)


if __name__ == "__main__":
    unittest.main()
