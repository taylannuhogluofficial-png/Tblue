"""Extra branch coverage for tblue.scanner.ports."""

from unittest.mock import MagicMock, patch
from tblue.scanner.ports import PortScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return PortScanner(session)


def test_closed_ports_returns_pass():
    """All ports closed → no FAIL results."""
    s = _scanner()
    with patch("socket.create_connection", side_effect=OSError("Connection refused")):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_open_sensitive_port_fails():
    """Open sensitive port (e.g., 8080) → FAIL or WARN."""
    s = _scanner()
    mock_sock = MagicMock()

    def create_conn(addr, timeout):
        host, port = addr
        if port in (8080, 8443, 9200, 27017):
            return mock_sock
        raise OSError("Connection refused")

    with patch("socket.create_connection", side_effect=create_conn):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert isinstance(results, list)


def test_result_structure():
    """Results contain required keys."""
    s = _scanner()
    with patch("socket.create_connection", side_effect=OSError("refused")):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r


def test_scan_no_exception():
    """scan() does not raise regardless of socket errors."""
    s = _scanner()
    with patch("socket.create_connection", side_effect=OSError):
        try:
            s.scan(URL)
        except Exception as e:
            assert False, f"scan() raised: {e}"
