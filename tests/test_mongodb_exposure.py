"""Tests for MongoDB / CouchDB / Firebase exposure scanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.mongodb_exposure import MongoDBExposureScanner


def _resp(body="", status=200):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    return r


class TestMongoDBExposure(unittest.TestCase):

    def _scanner(self):
        s = MongoDBExposureScanner.__new__(MongoDBExposureScanner)
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
        self.assertIn("mongodb_not_exposed", types)

    def test_couchdb_welcome_detected(self):
        s = self._scanner()
        couch_body = '{"couchdb":"Welcome","version":"3.3.2","git_sha":"abc123"}'

        def get_side(url, **kw):
            if ":5984/" in url and not "_all_dbs" in url:
                return _resp(couch_body, 200)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("couchdb_unauthenticated_access", types)

    def test_couchdb_auth_enforced(self):
        s = self._scanner()

        def get_side(url, **kw):
            if ":5984/" in url:
                return _resp('{"error":"unauthorized"}', 401)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("couchdb_auth_enforced", types)

    def test_couchdb_all_dbs_exposed(self):
        s = self._scanner()
        couch_root = '{"couchdb":"Welcome","version":"3.3.2"}'
        dbs_body   = '["_users","_replicator","users","payments","sessions"]'

        def get_side(url, **kw):
            if ":5984/_all_dbs" in url:
                return _resp(dbs_body, 200)
            if ":5984/" in url:
                return _resp(couch_root, 200)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("couchdb_database_listing", types)

    def test_mongodb_connection_string_in_page(self):
        s = self._scanner()
        body = 'var db = "mongodb://admin:password@mongo.internal:27017/mydb";'

        def get_side(url, **kw):
            if url == "https://example.com":
                return _resp(body, 200)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("mongodb_connection_string_exposed", types)

    def test_mongodb_http_interface_exposed(self):
        s = self._scanner()
        mongo_body = "<html>MongoDB REST Interface — listDatabases</html>"

        def get_side(url, **kw):
            if ":28017/" in url:
                return _resp(mongo_body, 200)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("mongodb_http_interface_exposed", types)


if __name__ == "__main__":
    unittest.main()
