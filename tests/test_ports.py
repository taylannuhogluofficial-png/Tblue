"""
Tests for open port scanner.
Uses monkeypatching to avoid real TCP connections.
"""

import pytest
from tblue.scanner.ports import PortScanner, _tcp_open


def make_scanner() -> PortScanner:
    from unittest.mock import MagicMock
    return PortScanner(MagicMock())


def test_redis_open_fails(monkeypatch):
    monkeypatch.setattr("tblue.scanner.ports._tcp_open",
                        lambda host, port: port == 6379)
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("6379/redis" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_mysql_open_fails(monkeypatch):
    monkeypatch.setattr("tblue.scanner.ports._tcp_open",
                        lambda host, port: port == 3306)
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("3306/mysql" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_no_open_ports_passes(monkeypatch):
    monkeypatch.setattr("tblue.scanner.ports._tcp_open", lambda h, p: False)
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("no dangerous ports" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_ssh_open_warns(monkeypatch):
    monkeypatch.setattr("tblue.scanner.ports._tcp_open",
                        lambda host, port: port == 22)
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("22/ssh" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_docker_api_open_fails(monkeypatch):
    monkeypatch.setattr("tblue.scanner.ports._tcp_open",
                        lambda host, port: port == 2375)
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("docker api" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_multiple_open_ports_all_reported(monkeypatch):
    open_ports = {3306, 6379, 27017}
    monkeypatch.setattr("tblue.scanner.ports._tcp_open",
                        lambda host, port: port in open_ports)
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    fails   = [r for r in results if r["status"] == "FAIL"]
    assert len(fails) >= 3


def test_result_has_fix_guidance(monkeypatch):
    monkeypatch.setattr("tblue.scanner.ports._tcp_open",
                        lambda host, port: port == 6379)
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    redis = next(r for r in results if "redis" in r["type"].lower())
    assert "fix" in redis["detail"].lower() or "bind" in redis["detail"].lower()


def test_invalid_url_returns_empty():
    scanner = make_scanner()
    results = scanner.scan("not-a-valid-url")
    assert results == []


def test_tcp_open_returns_false_on_oserror(monkeypatch):
    # Directly test that _tcp_open returns False when socket.create_connection raises OSError
    import socket as socket_mod
    original = socket_mod.create_connection
    try:
        socket_mod.create_connection = lambda *a, **kw: (_ for _ in ()).throw(OSError("refused"))
        result = _tcp_open("127.0.0.1", 65535)
        assert result is False
    finally:
        socket_mod.create_connection = original


def test_tcp_open_returns_true_on_success(monkeypatch):
    # Patch socket.create_connection to return a mock context manager
    from unittest.mock import MagicMock
    import socket as socket_mod
    mock_sock = MagicMock()
    mock_sock.__enter__ = lambda s: s
    mock_sock.__exit__ = MagicMock(return_value=False)
    original = socket_mod.create_connection
    try:
        socket_mod.create_connection = lambda *a, **kw: mock_sock
        result = _tcp_open("127.0.0.1", 9999)
        assert result is True
    finally:
        socket_mod.create_connection = original
