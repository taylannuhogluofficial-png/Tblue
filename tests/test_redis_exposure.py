"""Tests for Redis / Memcached exposure scanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.redis_exposure import RedisExposureScanner


def _resp(body="", status=200):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    return r


class TestRedisExposure(unittest.TestCase):

    def _scanner(self):
        s = RedisExposureScanner.__new__(RedisExposureScanner)
        s.http = MagicMock()
        s.results = []
        s._result = lambda url, ftype, sev, detail="": {
            "url": url, "type": ftype, "severity": sev, "detail": detail
        }
        return s

    def _not_found(self):
        return _resp("", 404)

    def test_no_redis_returns_pass(self):
        s = self._scanner()
        s.http.get.return_value = self._not_found()
        # Mock TCP to fail
        with patch("tblue.scanner.redis_exposure._tcp_banner", return_value=""):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("redis_not_exposed", types)

    def test_redis_pong_detected(self):
        s = self._scanner()
        s.http.get.return_value = self._not_found()

        def tcp_side(host, port, send=b"PING\r\n", timeout=2.0):
            if port == 6379 and send == b"PING\r\n":
                return "+PONG\r\n"
            return ""

        with patch("tblue.scanner.redis_exposure._tcp_banner", side_effect=tcp_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("redis_unauthenticated_access", types)
        sev = next(r["severity"] for r in results if r["type"] == "redis_unauthenticated_access")
        self.assertEqual(sev, "FAIL")

    def test_redis_noauth_response(self):
        s = self._scanner()
        s.http.get.return_value = self._not_found()

        def tcp_side(host, port, send=b"PING\r\n", timeout=2.0):
            if port == 6379 and send == b"PING\r\n":
                return "-NOAUTH Authentication required\r\n"
            return ""

        with patch("tblue.scanner.redis_exposure._tcp_banner", side_effect=tcp_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("redis_auth_enforced", types)

    def test_redis_info_exposed(self):
        s = self._scanner()
        s.http.get.return_value = self._not_found()

        def tcp_side(host, port, send=b"PING\r\n", timeout=2.0):
            if send == b"INFO server\r\n":
                return "# Server\nredis_version:7.0.5\nused_memory:1048576\nrole:master\n"
            return ""

        with patch("tblue.scanner.redis_exposure._tcp_banner", side_effect=tcp_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("redis_info_exposed", types)

    def test_memcached_stats_detected(self):
        s = self._scanner()
        s.http.get.return_value = self._not_found()

        def tcp_side(host, port, send=b"PING\r\n", timeout=2.0):
            if port == 11211:
                return "STAT version 1.6.17\nSTAT uptime 12345\nEND\r\n"
            return ""

        with patch("tblue.scanner.redis_exposure._tcp_banner", side_effect=tcp_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("memcached_unauthenticated_access", types)


if __name__ == "__main__":
    unittest.main()
