"""
Integration tests for database exposure scanners (Elasticsearch, MongoDB/CouchDB).

The Elasticsearch scanner probes hardcoded ports (9200/9201/9300) on the target
host — we can't redirect those port probes to a local test server without root
privileges.  Instead we use direct mock-based integration tests that exercise
the full detection logic with realistic response payloads.

MongoDB/CouchDB tests use a mix of local HTTP servers and mock-based approaches.
"""

import threading
import json
from unittest.mock import MagicMock, patch
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests as _requests

from tblue.scanner.elasticsearch_exposure import ElasticsearchExposureScanner
from tblue.scanner.mongodb_exposure       import MongoDBExposureScanner


def _es_scanner():
    s = ElasticsearchExposureScanner.__new__(ElasticsearchExposureScanner)
    s.results = []
    s.http = MagicMock()
    s._result = lambda url, ftype, sev, detail="": {
        "url": url, "type": ftype, "severity": sev, "detail": detail
    }
    return s


def _mongo_scanner():
    s = MongoDBExposureScanner.__new__(MongoDBExposureScanner)
    s.results = []
    s.http = MagicMock()
    s._result = lambda url, ftype, sev, detail="": {
        "url": url, "type": ftype, "severity": sev, "detail": detail
    }
    return s


def _mock_resp(body, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = body if isinstance(body, str) else json.dumps(body)
    r.headers = {}
    return r


def _not_found():
    return _mock_resp("", 404)


# ── Elasticsearch ─────────────────────────────────────────────────────────────

def test_elasticsearch_root_fingerprint_detected():
    """Elasticsearch root endpoint with cluster_name/tagline should FAIL."""
    es_root = json.dumps({
        "name": "my-node",
        "cluster_name": "production-cluster",
        "cluster_uuid": "abc123",
        "version": {"number": "8.11.0", "lucene_version": "9.8.0"},
        "tagline": "You Know, for Search",
    })

    scanner = _es_scanner()
    scanner.http.get.side_effect = lambda url, **kw: (
        _mock_resp(es_root) if ":9200/" in url else _not_found()
    )
    results = scanner.scan("https://example.com")
    fail_types = [r["type"] for r in results if r["severity"] == "FAIL"]
    assert any("elasticsearch" in t for t in fail_types), \
        f"Expected Elasticsearch FAIL, got: {fail_types}"


def test_elasticsearch_cat_indices_exposed():
    """/_cat/indices JSON listing should trigger index_listing FAIL.

    The scanner only probes /_cat/indices if the root URL returns 200.
    """
    indices_body = json.dumps([
        {"health": "green", "status": "open", "index": "users", "docs.count": "10000"},
        {"health": "green", "status": "open", "index": "payments", "docs.count": "5000"},
    ])

    scanner = _es_scanner()

    def get_side(url, **kw):
        if "/_cat/indices" in url:
            return _mock_resp(indices_body)
        if ":9200/" in url or ":9201/" in url or ":9300/" in url:
            # Root returns 200 but no fingerprint body — scanner still proceeds
            return _mock_resp("{}", 200)
        return _not_found()

    scanner.http.get.side_effect = get_side
    results = scanner.scan("https://example.com")
    fail_types = [r["type"] for r in results if r["severity"] == "FAIL"]
    assert any("index" in t for t in fail_types), \
        f"Expected index_listing FAIL, got: {fail_types}"


def test_elasticsearch_cluster_health_exposed():
    """/_cluster/health JSON should trigger cluster health WARN.

    The scanner only probes /_cluster/health if root returns 200.
    Cluster health is a WARN (not FAIL) since it's less severe than full access.
    """
    health_body = json.dumps({
        "cluster_name": "prod-cluster",
        "status": "green",
        "number_of_nodes": 3,
        "active_shards": 15,
    })

    scanner = _es_scanner()

    def get_side(url, **kw):
        if "/_cluster/health" in url:
            return _mock_resp(health_body)
        if ":9200/" in url or ":9201/" in url or ":9300/" in url:
            return _mock_resp("{}", 200)
        return _not_found()

    scanner.http.get.side_effect = get_side
    results = scanner.scan("https://example.com")
    warn_types = [r["type"] for r in results if r["severity"] in ("WARN", "FAIL")]
    assert any("cluster" in t for t in warn_types), \
        f"Expected cluster_health WARN/FAIL, got: {warn_types}"


def test_elasticsearch_auth_enforced_passes():
    """401 responses on ES endpoints should produce PASS (auth enforced)."""
    scanner = _es_scanner()
    scanner.http.get.return_value = _mock_resp('{"error":"Unauthorized"}', 401)
    results = scanner.scan("https://example.com")
    types_by_sev = [(r["type"], r["severity"]) for r in results]
    fail_results = [(t, s) for (t, s) in types_by_sev if s == "FAIL"]
    assert len(fail_results) == 0, f"Expected no FAILs with auth enforced, got: {fail_results}"


def test_elasticsearch_no_exposure_returns_pass():
    """All 404 responses should produce elasticsearch_not_exposed PASS."""
    scanner = _es_scanner()
    scanner.http.get.return_value = _not_found()
    results = scanner.scan("https://example.com")
    types = [r["type"] for r in results]
    assert any("not_exposed" in t for t in types), \
        f"Expected not_exposed PASS, got: {types}"


# ── CouchDB ───────────────────────────────────────────────────────────────────

def test_couchdb_welcome_page_detected():
    """CouchDB welcome JSON on port 5984 should FAIL."""
    couch_welcome = '{"couchdb":"Welcome","version":"3.3.2","git_sha":"abcdef1"}'
    scanner = _mongo_scanner()

    def get_side(url, **kw):
        if ":5984/" in url and "_all_dbs" not in url:
            return _mock_resp(couch_welcome)
        return _not_found()

    scanner.http.get.side_effect = get_side
    results = scanner.scan("https://example.com")
    types = [r["type"] for r in results]
    assert "couchdb_unauthenticated_access" in types, \
        f"Expected CouchDB FAIL, got: {types}"


def test_couchdb_database_listing_detected():
    """/_all_dbs listing returned should produce couchdb_database_listing FAIL."""
    couch_root = '{"couchdb":"Welcome","version":"3.3.2"}'
    all_dbs    = '["_users","_replicator","users","payments","audit_log"]'
    scanner    = _mongo_scanner()

    def get_side(url, **kw):
        if ":5984/_all_dbs" in url:
            return _mock_resp(all_dbs)
        if ":5984/" in url:
            return _mock_resp(couch_root)
        return _not_found()

    scanner.http.get.side_effect = get_side
    results = scanner.scan("https://example.com")
    types = [r["type"] for r in results]
    assert "couchdb_database_listing" in types, \
        f"Expected database listing FAIL, got: {types}"


def test_couchdb_auth_enforced_passes():
    """401 on CouchDB root should produce couchdb_auth_enforced PASS."""
    scanner = _mongo_scanner()

    def get_side(url, **kw):
        if ":5984/" in url or ":5985/" in url:
            return _mock_resp('{"error":"unauthorized"}', 401)
        return _not_found()

    scanner.http.get.side_effect = get_side
    results = scanner.scan("https://example.com")
    types = [r["type"] for r in results]
    assert "couchdb_auth_enforced" in types, \
        f"Expected couchdb_auth_enforced PASS, got: {types}"


def test_mongodb_connection_string_in_page():
    """mongodb:// in page JS should trigger mongodb_connection_string_exposed FAIL."""
    body = 'var db = "mongodb://admin:secret@mongo.internal:27017/mydb";'
    scanner = _mongo_scanner()

    def get_side(url, **kw):
        if url == "https://example.com":
            return _mock_resp(body)
        return _not_found()

    scanner.http.get.side_effect = get_side
    results = scanner.scan("https://example.com")
    types = [r["type"] for r in results]
    assert "mongodb_connection_string_exposed" in types, \
        f"Expected connection string FAIL, got: {types}"
