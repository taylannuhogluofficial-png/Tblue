"""Tests for the shared response cache (tblue/cache.py)."""

import threading
import time
import unittest


class TestResponseCache(unittest.TestCase):

    def _cache(self, **kw):
        from tblue.cache import ResponseCache
        return ResponseCache(**kw)

    def test_first_fetch_calls_fetcher(self):
        cache = self._cache()
        calls = []

        def fetcher(url, **kw):
            calls.append(url)
            return f"resp:{url}"

        result = cache.get_or_fetch("http://example.com", fetcher)
        self.assertEqual(result, "resp:http://example.com")
        self.assertEqual(len(calls), 1)

    def test_second_fetch_served_from_cache(self):
        cache = self._cache()
        calls = []

        def fetcher(url, **kw):
            calls.append(url)
            return f"resp:{url}"

        cache.get_or_fetch("http://example.com", fetcher)
        cache.get_or_fetch("http://example.com", fetcher)
        self.assertEqual(len(calls), 1, "Fetcher should only be called once")

    def test_different_urls_are_independent(self):
        cache = self._cache()
        calls = []

        def fetcher(url, **kw):
            calls.append(url)
            return f"resp:{url}"

        cache.get_or_fetch("http://a.com", fetcher)
        cache.get_or_fetch("http://b.com", fetcher)
        self.assertEqual(len(calls), 2)

    def test_size_property(self):
        cache = self._cache()
        fetcher = lambda url, **kw: "r"

        self.assertEqual(cache.size, 0)
        cache.get_or_fetch("http://a.com", fetcher)
        self.assertEqual(cache.size, 1)
        cache.get_or_fetch("http://b.com", fetcher)
        self.assertEqual(cache.size, 2)

    def test_max_entries_evicts_oldest(self):
        cache = self._cache(max_entries=3)
        fetcher = lambda url, **kw: "r"

        for i in range(4):
            cache.get_or_fetch(f"http://url{i}.com", fetcher)

        self.assertLessEqual(cache.size, 3)

    def test_invalidate_removes_entry(self):
        cache = self._cache()
        calls = []

        def fetcher(url, **kw):
            calls.append(url)
            return "r"

        cache.get_or_fetch("http://a.com", fetcher)
        cache.invalidate("http://a.com")
        cache.get_or_fetch("http://a.com", fetcher)
        self.assertEqual(len(calls), 2, "Fetcher should be called again after invalidate")

    def test_clear_empties_cache(self):
        cache = self._cache()
        fetcher = lambda url, **kw: "r"

        cache.get_or_fetch("http://a.com", fetcher)
        cache.get_or_fetch("http://b.com", fetcher)
        cache.clear()
        self.assertEqual(cache.size, 0)

    def test_concurrent_fetches_same_url_calls_fetcher_once(self):
        """Double-fetch prevention: only one thread should call fetcher."""
        cache = self._cache()
        calls = []
        barrier = threading.Barrier(5)

        def fetcher(url, **kw):
            time.sleep(0.05)  # simulate network latency
            calls.append(url)
            return "resp"

        def worker():
            barrier.wait()
            cache.get_or_fetch("http://shared.com", fetcher)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        self.assertEqual(len(calls), 1, f"Fetcher called {len(calls)} times, expected 1")

    def test_ttl_expiry_causes_refetch(self):
        cache = self._cache(ttl=0.05)
        calls = []

        def fetcher(url, **kw):
            calls.append(url)
            return "resp"

        cache.get_or_fetch("http://a.com", fetcher)
        time.sleep(0.1)  # wait past TTL
        cache.get_or_fetch("http://a.com", fetcher)
        self.assertEqual(len(calls), 2, "Should re-fetch after TTL expiry")

    def test_fetcher_exception_returns_none(self):
        cache = self._cache()

        def bad_fetcher(url, **kw):
            raise RuntimeError("network error")

        result = cache.get_or_fetch("http://broken.com", bad_fetcher)
        self.assertIsNone(result)


class TestHTTPClientCache(unittest.TestCase):
    """Verify HTTPClient wires the cache correctly."""

    def _client(self, cache=None):
        import requests
        from tblue.http import HTTPClient
        return HTTPClient(
            session=requests.Session(),
            timeout=5,
            retries=1,
            cache=cache,
        )

    def test_http_client_accepts_cache_kwarg(self):
        from tblue.cache import ResponseCache
        cache = ResponseCache()
        client = self._client(cache=cache)
        self.assertIs(client.cache, cache)

    def test_http_client_without_cache_still_works(self):
        client = self._client(cache=None)
        self.assertIsNone(client.cache)


if __name__ == "__main__":
    unittest.main()
