"""
Playwright Browser Engine — session management for browser-based scanning.

Wraps Playwright's sync API into a context manager that scanners can use
without worrying about browser lifecycle. Gracefully skips if Playwright
is not installed.

Usage:
    from tblue.browser.engine import BrowserSession

    with BrowserSession(headless=True) as session:
        page = session.new_page()
        page.goto("https://example.com")
        content = page.content()
"""

from typing import Any, Dict, List, Optional
from tblue.logger import get_logger

logger = get_logger(__name__)


def playwright_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


class BrowserPage:
    """Thin wrapper around a Playwright page with security-scan helpers."""

    def __init__(self, page):
        self._page = page
        self.requests: List[Dict] = []
        self.responses: List[Dict] = []
        self.console_messages: List[Dict] = []
        self.csp_violations: List[str] = []
        self.js_errors: List[str] = []
        self._setup_listeners()

    def _setup_listeners(self):
        """Wire up network and console event listeners."""
        self._page.on("request", self._on_request)
        self._page.on("response", self._on_response)
        self._page.on("console", self._on_console)
        self._page.on("pageerror", self._on_page_error)

    def _on_request(self, request):
        self.requests.append({
            "url": request.url,
            "method": request.method,
            "resource_type": request.resource_type,
            "headers": dict(request.headers),
        })

    def _on_response(self, response):
        try:
            headers = dict(response.headers)
        except Exception:
            headers = {}
        self.responses.append({
            "url": response.url,
            "status": response.status,
            "headers": headers,
            "resource_type": response.request.resource_type,
        })

    def _on_console(self, msg):
        text = msg.text
        self.console_messages.append({"type": msg.type, "text": text})
        if "content security policy" in text.lower() or "csp" in text.lower():
            self.csp_violations.append(text)

    def _on_page_error(self, error):
        self.js_errors.append(str(error))

    # ── Public navigation + extraction API ───────────────────────────────────

    def goto(self, url: str, wait_until: str = "networkidle", timeout: int = 15000):
        try:
            self._page.goto(url, wait_until=wait_until, timeout=timeout)
            return True
        except Exception as e:
            logger.debug(f"Browser navigation error for {url}: {e}")
            return False

    def content(self) -> str:
        try:
            return self._page.content()
        except Exception:
            return ""

    def title(self) -> str:
        try:
            return self._page.title()
        except Exception:
            return ""

    def url(self) -> str:
        try:
            return self._page.url
        except Exception:
            return ""

    def evaluate(self, expression: str) -> Any:
        try:
            return self._page.evaluate(expression)
        except Exception as e:
            logger.debug(f"evaluate error: {e}")
            return None

    def query_selector_all(self, selector: str) -> List:
        try:
            return self._page.query_selector_all(selector)
        except Exception:
            return []

    def cookies(self) -> List[Dict]:
        try:
            return self._page.context.cookies()
        except Exception:
            return []

    def local_storage(self) -> Dict:
        return self.evaluate("() => Object.fromEntries(Object.entries(localStorage))") or {}

    def session_storage(self) -> Dict:
        return self.evaluate("() => Object.fromEntries(Object.entries(sessionStorage))") or {}

    def add_script_tag(self, content: str):
        try:
            self._page.add_script_tag(content=content)
        except Exception as e:
            logger.debug(f"add_script_tag error: {e}")

    def wait_for_timeout(self, ms: int):
        try:
            self._page.wait_for_timeout(ms)
        except Exception:
            pass

    def get_spa_routes(self) -> List[str]:
        """Extract client-side routes from common SPA frameworks."""
        routes = []
        # React Router / Next.js links
        links = self.evaluate("""
            () => [...document.querySelectorAll('a[href]')]
                .map(a => a.getAttribute('href'))
                .filter(h => h && h.startsWith('/') && !h.includes('.'))
                .slice(0, 50)
        """) or []
        routes.extend(links)

        # Extract from JS bundle route tables (common pattern)
        route_hints = self.evaluate("""
            () => {
                try {
                    const src = document.documentElement.innerHTML;
                    const matches = src.match(/path:[\\s]*["'](\\/[^"']*?)["']/g) || [];
                    return matches.map(m => m.replace(/path:[\\s]*["']/,'').replace(/["']/,''))
                               .filter(p => p.length > 1)
                               .slice(0, 30);
                } catch(e) { return []; }
            }
        """) or []
        routes.extend(route_hints)

        return list(dict.fromkeys(r for r in routes if r and r.startswith("/")))

    @property
    def http_requests(self) -> List[Dict]:
        """Return requests over plain HTTP (not HTTPS)."""
        return [r for r in self.requests if r["url"].startswith("http://")]

    @property
    def cross_origin_requests(self) -> List[Dict]:
        """Return requests to different origins."""
        return [r for r in self.requests if r["resource_type"] in ("script", "stylesheet", "fetch", "xhr")]


class BrowserSession:
    """Context manager that owns the Playwright browser lifecycle."""

    def __init__(
        self,
        headless: bool = True,
        timeout: int = 15000,
        user_agent: str = "Tblue-Browser-Scanner/1.0",
        extra_headers: Optional[Dict] = None,
    ):
        self.headless = headless
        self.timeout = timeout
        self.user_agent = user_agent
        self.extra_headers = extra_headers or {}
        self._pw = None
        self._browser = None
        self._context = None

    def __enter__(self):
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(
            headless=self.headless,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-extensions",
            ],
        )
        self._context = self._browser.new_context(
            user_agent=self.user_agent,
            extra_http_headers=self.extra_headers,
            ignore_https_errors=True,  # we detect SSL issues separately
            java_script_enabled=True,
        )
        self._context.set_default_timeout(self.timeout)
        return self

    def __exit__(self, *args):
        try:
            if self._context:
                self._context.close()
            if self._browser:
                self._browser.close()
            if self._pw:
                self._pw.stop()
        except Exception as e:
            logger.debug(f"Browser cleanup error: {e}")

    def new_page(self) -> BrowserPage:
        raw_page = self._context.new_page()
        return BrowserPage(raw_page)
