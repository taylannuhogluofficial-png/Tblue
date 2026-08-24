"""
HTTP client with retry logic, backoff, rate limiting, and response cache.
All scanners use this instead of calling requests directly.
"""

import time
from typing import Optional, Dict, Any, TYPE_CHECKING
from requests import Session, Response
from tblue.constants import (
    DEFAULT_TIMEOUT,
    DEFAULT_RETRIES,
    DEFAULT_BACKOFF,
    DEFAULT_RATE_LIMIT,
)
from tblue.logger import get_logger

if TYPE_CHECKING:
    from tblue.cache import ResponseCache

logger = get_logger(__name__)


class HTTPClient:
    """
    HTTP client with retry, exponential backoff, rate limiting, and
    an optional shared response cache.

    When a ResponseCache is provided, identical GET requests are served
    from cache after the first fetch — the primary source of speed-up
    when 400+ scanners each call self.http.get(target_url).

    Never raises — returns None on failure.
    """

    def __init__(
        self,
        session:    Session,
        timeout:    int              = DEFAULT_TIMEOUT,
        retries:    int              = DEFAULT_RETRIES,
        backoff:    float            = DEFAULT_BACKOFF,
        rate_limit: float            = DEFAULT_RATE_LIMIT,
        cache:      Optional["ResponseCache"] = None,
    ) -> None:
        self.session    = session
        self.timeout    = timeout
        self.retries    = retries
        self.backoff    = backoff
        self.rate_limit = rate_limit
        self.cache      = cache
        self._last_request_time: float = 0.0

    def _throttle(self) -> None:
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self._last_request_time = time.time()

    def get(
        self,
        url:             str,
        params:          Optional[Dict[str, Any]] = None,
        allow_redirects: bool = True,
        headers:         Optional[Dict[str, str]] = None,
    ) -> Optional[Response]:
        """GET with cache, retry and backoff. Returns None on failure."""
        # Only cache simple GETs with no query params and no custom headers
        # (custom headers change the effective response)
        if self.cache is not None and params is None and headers is None:
            return self.cache.get_or_fetch(
                url,
                lambda u, **kw: self._request("GET", u, allow_redirects=allow_redirects, **kw),
            )
        return self._request("GET", url, params=params,
                             allow_redirects=allow_redirects, headers=headers)

    def post(
        self,
        url:     str,
        data:    Optional[Any] = None,
        json:    Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Response]:
        """POST with retry and backoff. Returns None on failure."""
        return self._request("POST", url, data=data, json=json, headers=headers)

    def patch(
        self,
        url:     str,
        data:    Optional[Any] = None,
        json:    Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Response]:
        """PATCH with retry and backoff. Returns None on failure."""
        return self._request("PATCH", url, data=data, json=json, headers=headers)

    def options(self, url: str) -> Optional[Response]:
        """OPTIONS request. Returns None on failure."""
        return self._request("OPTIONS", url, allow_redirects=False)

    def _request(self, method: str, url: str, **kwargs: Any) -> Optional[Response]:
        """Internal: retry + backoff. Always returns None on failure."""
        self._throttle()

        for attempt in range(1, self.retries + 1):
            try:
                resp = self.session.request(
                    method, url, timeout=self.timeout, **kwargs
                )
                return resp
            except Exception as exc:
                wait = self.backoff * (2 ** (attempt - 1))
                if attempt < self.retries:
                    logger.warning(
                        f"Request failed ({attempt}/{self.retries}) {url} — "
                        f"{exc} — retry in {wait:.1f}s"
                    )
                    time.sleep(wait)
                else:
                    logger.error(f"All {self.retries} attempts failed: {url} — {exc}")

        return None
