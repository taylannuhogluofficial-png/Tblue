"""Extra branch coverage for tblue.scanner.ssl."""

from unittest.mock import MagicMock, patch
from tblue.scanner.ssl import SSLScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return SSLScanner(session)


def test_http_url_warns():
    """HTTP (non-HTTPS) URL → FAIL or WARN about no TLS."""
    s = _scanner()
    results = s.scan("http://example.com")
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad


def test_https_url_probed():
    """HTTPS URL → scanner runs and returns list."""
    s = _scanner()
    with patch("ssl.create_default_context"), \
         patch("socket.create_connection", return_value=MagicMock()):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_result_keys():
    """Results contain required keys."""
    s = _scanner()
    results = s.scan("http://example.com")
    for r in results:
        assert "url" in r and "status" in r and "type" in r


def test_no_exceptions():
    """scan() does not raise for any URL."""
    s = _scanner()
    try:
        s.scan(URL)
    except Exception as e:
        assert False, f"scan() raised: {e}"
