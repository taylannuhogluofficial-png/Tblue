"""
HTTP client with retry logic, backoff, rate limiting, and response cache.
All scanners use this instead of calling requests directly.
"""

import time
from urllib.parse import urlparse
from typing import Optional, Dict, Any, TYPE_CHECKING
from requests import Session, Response
from tblue.constants import (
    DEFAULT_TIMEOUT,
    DEFAULT_RETRIES,
    DEFAULT_BACKOFF,
    DEFAULT_RATE_LIMIT,
    DEFAULT_USER_AGENT,
)
from tblue.logger import get_logger

if TYPE_CHECKING:
    from tblue.cache import ResponseCache

logger = get_logger(__name__)


def _host_in_scope(url: str, allowed_host: Optional[str]) -> bool:
    """True when url points at allowed_host (or a subdomain of it)."""
    if not allowed_host:
        return True
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return True
    return host == allowed_host or host.endswith("." + allowed_host)


class ScopedSession(Session):
    """A Session that drops user-supplied credentials when a redirect
    leaves the scan target.

    Picking a clean session per request (HTTPClient._request) only covers
    requests we issue ourselves. A redirect is followed by requests inside
    a single send(), using whichever session started it — so a target that
    answers 302 with an off-host Location would otherwise carry --header
    values and the cookie jar to that host.

    requests' own rebuild_auth drops Authorization on a host change, which
    covers --bearer and --auth. It does not touch arbitrary headers, and a
    cookie set without an explicit domain matches any host, so --cookie
    travels too. Both are stripped here.
    """

    def __init__(self) -> None:
        super().__init__()
        self.allowed_host: Optional[str] = None
        self.scoped_headers: set = set()

    def rebuild_auth(self, prepared_request, response):
        super().rebuild_auth(prepared_request, response)
        if _host_in_scope(prepared_request.url, self.allowed_host):
            return
        for name in self.scoped_headers:
            prepared_request.headers.pop(name, None)
        prepared_request.headers.pop("Cookie", None)


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
        allowed_host: Optional[str] = None,
    ) -> None:
        self.session    = session
        self.timeout    = timeout
        self.retries    = retries
        self.backoff    = backoff
        self.rate_limit = rate_limit
        self.cache      = cache
        # Host the user authorised us to talk to. Requests to anything else
        # (crt.sh, OSV, OTX, ...) must never carry their credentials.
        self.allowed_host = (allowed_host or "").lower().lstrip(".") or None
        # A ScopedSession also needs the target, to strip credentials off
        # redirects that leave it (see ScopedSession.rebuild_auth).
        if isinstance(session, ScopedSession):
            session.allowed_host = self.allowed_host
        self._offsite_session: Optional[Session] = None
        self._last_request_time: float = 0.0

    # ── Credential scoping ────────────────────────────────────────────────
    def _in_scope(self, url: str) -> bool:
        """True when url points at the scan target (or a subdomain of it)."""
        return _host_in_scope(url, self.allowed_host)

    def _clean_session(self) -> Session:
        """A session with no cookies, no auth and no user-supplied headers.

        Third-party enrichment lookups go through this so a --bearer token or
        --cookie for the target is never transmitted to an unrelated service.
        """
        if self._offsite_session is None:
            s = Session()
            s.headers["User-Agent"] = self.session.headers.get(
                "User-Agent", DEFAULT_USER_AGENT)
            for h in ("Accept", "Accept-Language"):
                if h in self.session.headers:
                    s.headers[h] = self.session.headers[h]
            self._offsite_session = s
        return self._offsite_session

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

        session = self.session if self._in_scope(url) else self._clean_session()

        for attempt in range(1, self.retries + 1):
            try:
                resp = session.request(
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
