"""Extra branch coverage for tblue.scanner.tls_deep."""

from unittest.mock import MagicMock, patch
from tblue.scanner.tls_deep import TLSDeepScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return TLSDeepScanner(session)


def test_http_url_returns_empty():
    """HTTP URL → scanner skips TLS checks (returns empty list)."""
    s = _scanner()
    results = s.scan("http://example.com")
    assert isinstance(results, list)
    assert results == []


def test_https_url_no_crash():
    """HTTPS URL → scanner runs without uncaught exceptions."""
    s = _scanner()
    with patch("ssl.SSLContext"), patch("socket.create_connection", side_effect=OSError("refused")):
        try:
            results = s.scan(URL)
            assert isinstance(results, list)
        except Exception as e:
            assert False, f"scan() raised: {e}"


def test_no_exceptions():
    """scan() does not propagate exceptions to caller."""
    s = _scanner()
    try:
        s.scan(URL)
    except Exception as e:
        assert False, f"scan() raised: {e}"


def test_result_keys():
    """If any results are produced, they contain required keys."""
    s = _scanner()
    with patch("ssl.SSLContext"), patch("socket.create_connection", side_effect=OSError):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
