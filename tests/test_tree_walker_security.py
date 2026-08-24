"""Tests for TreeWalkerSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.tree_walker_security import TreeWalkerSecurityScanner


def _scanner():
    s = TreeWalkerSecurityScanner.__new__(TreeWalkerSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_tree_walker_sensitive_node_harvest():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)\n"
        "// harvests password and auth token text nodes"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "tree_walker_sensitive_node_harvest" in types


def test_tree_walker_exfil_text_nodes():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const text = treeWalker.nextNode()\n"
        "sendBeacon('/harvest', text.textContent)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "tree_walker_exfil_text_nodes" in types


def test_tree_walker_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.createTreeWalker(document.body, NodeFilter.SHOW_ALL, searchParams.get('filter'))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "tree_walker_from_param" in types


def test_tree_walker_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No DOM traversal API used here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "tree_walker_not_used"
    assert results[0]["status"] == "PASS"


def test_tree_walker_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "tree_walker_not_used"
