"""
Thread-safe response cache for Tblue scanner pool.

Eliminates redundant HTTP fetches: when 400+ scanners all call
self.http.get(target_url), only the first request hits the network.
All subsequent callers receive the cached Response object instantly.

Design:
- Exact URL match (method + url + frozenset of custom headers)
- Double-fetch prevention: a threading.Event serialises concurrent
  first-fetchers; only one thread sends the real request.
- Bounded size: oldest entries evicted when cache exceeds max_entries.
- Only GET requests are cached; POST/PATCH/OPTIONS bypass the cache.
"""

import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, Optional

_MISS     = object()   # sentinel


class _Entry:
    __slots__ = ("response", "ts")

    def __init__(self, response: Any) -> None:
        self.response = response
        self.ts       = time.monotonic()


class ResponseCache:
    """
    Shared, thread-safe GET-response cache.

    Usage in HTTPClient:
        cache = ResponseCache()
        resp  = cache.get_or_fetch(url, fetcher, **kwargs)
    """

    def __init__(self, max_entries: int = 2000, ttl: float = 300.0) -> None:
        self._max     = max_entries
        self._ttl     = ttl
        self._store:  OrderedDict[str, _Entry]          = OrderedDict()
        self._events: Dict[str, threading.Event]        = {}
        self._lock    = threading.Lock()

    # ------------------------------------------------------------------
    def _make_key(self, url: str, headers: Optional[Dict] = None) -> str:
        hdr_part = ""
        if headers:
            hdr_part = "|" + "&".join(
                f"{k}={v}" for k, v in sorted(headers.items())
            )
        return url + hdr_part

    # ------------------------------------------------------------------
    def get_or_fetch(
        self,
        url:     str,
        fetcher: Callable[..., Any],
        headers: Optional[Dict] = None,
        **kwargs: Any,
    ) -> Any:
        """
        Return cached response for *url*, or call *fetcher(url, ...)* once
        and cache the result.  Concurrent threads waiting for the same URL
        block until the first fetch completes.
        """
        key = self._make_key(url, headers)

        # Fast path: already cached
        with self._lock:
            entry = self._store.get(key, _MISS)
            if entry is not _MISS:
                if time.monotonic() - entry.ts < self._ttl:
                    self._store.move_to_end(key)
                    return entry.response
                # expired
                del self._store[key]

            # Check if another thread is already fetching
            if key in self._events:
                ev = self._events[key]
                wait = True
            else:
                ev = threading.Event()
                self._events[key] = ev
                wait = False

        if wait:
            ev.wait(timeout=30)
            with self._lock:
                entry = self._store.get(key, _MISS)
                if entry is not _MISS:
                    return entry.response
            return None  # fetch failed in the other thread

        # We are the sole fetcher for this URL
        try:
            resp = fetcher(url, headers=headers, **kwargs) if headers else fetcher(url, **kwargs)
        except Exception:
            resp = None
        finally:
            with self._lock:
                if resp is not None:
                    self._store[key] = _Entry(resp)
                    self._store.move_to_end(key)
                    # Evict oldest if over limit
                    while len(self._store) > self._max:
                        self._store.popitem(last=False)
                self._events.pop(key, None)
            ev.set()

        return resp

    # ------------------------------------------------------------------
    def invalidate(self, url: str, headers: Optional[Dict] = None) -> None:
        key = self._make_key(url, headers)
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._events.clear()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._store)
