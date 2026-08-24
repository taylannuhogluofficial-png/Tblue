"""Tests for TopicsAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.topics_api_security import TopicsAPISecurityScanner


def _scanner():
    s = TopicsAPISecurityScanner.__new__(TopicsAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestTopicsExfil:
    def test_topics_exfiltrated_fails(self):
        s = _scanner()
        body = "const t = await document.browsingTopics()\nfetch('/track', {body: JSON.stringify(t)})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "topics_api_data_exfiltrated" in types


class TestTopicsStored:
    def test_topics_stored_locally_warns(self):
        s = _scanner()
        body = "const topics = await document.browsingTopics()\nlocalStorage.setItem('profile', JSON.stringify(topics))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "topics_api_data_stored_locally" in types


class TestTopicsCombinedPII:
    def test_topics_combined_with_pii_fails(self):
        s = _scanner()
        body = "const t = await document.browsingTopics()\nsendBeacon('/profile', JSON.stringify({userId: user.userId, topics: t}))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "topics_api_combined_with_pii" in types


class TestNotUsed:
    def test_no_topics_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "topics_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
