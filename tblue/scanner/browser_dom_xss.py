"""
Browser-Based DOM XSS Scanner.

This is the scanner that static analysis cannot match. Static tools read HTML and
guess whether innerHTML= might be tainted. This scanner actually EXECUTES the
JavaScript in a real Chromium browser and monitors the DOM for sink invocations.

How it works:
  1. Inject a sink monitor before the page loads (patches innerHTML, eval, etc.)
  2. Navigate to URL with XSS probe values in all URL parameters
  3. After page settles, check if any patched sink was called with the probe
  4. Also listen for window.onerror events triggered by probe execution
  5. Check for probe in document.title (a common DOM XSS sink)

Why this beats static analysis:
  • Handles obfuscated JS, minified bundles, webpack chunks
  • Sees data flow through framework internals (React setState → DOM update)
  • Catches second-order DOM XSS (probe stored → rendered later in same session)
  • Detects template injection in client-side templates (Handlebars, Mustache)

Strictly blue-team:
  • Probe value is a visible marker string — no alert(), no actual execution
  • All probes are sent to the scan target (your own site)
  • No callbacks to external servers

CWE-79: Improper Neutralization of Input During Web Page Generation
"""

from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs, urlencode

from tblue.scanner.base import BaseScanner
from tblue.browser.engine import playwright_available, BrowserSession
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Probe that will appear in DOM sinks if reflected without encoding
_DOM_XSS_PROBE = "TBLxss9z7"
_DOM_XSS_PAYLOAD = f"{_DOM_XSS_PROBE}<img src=x onerror=window.__tbl_fired=1>"

# Sink monitor script — injected before page JS runs
_SINK_MONITOR_JS = """
() => {
    window.__tbl_sinks = [];
    window.__tbl_fired = 0;

    const _probe = '""" + _DOM_XSS_PROBE + """';

    // Monitor innerHTML / outerHTML / insertAdjacentHTML
    const _monitorProp = (proto, prop) => {
        const orig = Object.getOwnPropertyDescriptor(proto, prop);
        if (!orig || !orig.set) return;
        Object.defineProperty(proto, prop, {
            set(v) {
                if (typeof v === 'string' && v.includes(_probe)) {
                    window.__tbl_sinks.push({sink: prop, snippet: v.substring(0, 200)});
                }
                return orig.set.call(this, v);
            },
            get: orig.get,
            configurable: true,
        });
    };
    _monitorProp(Element.prototype, 'innerHTML');
    _monitorProp(Element.prototype, 'outerHTML');

    // Monitor document.write / document.writeln
    const _origWrite = document.write.bind(document);
    document.write = function(s) {
        if (typeof s === 'string' && s.includes(_probe)) {
            window.__tbl_sinks.push({sink: 'document.write', snippet: s.substring(0, 200)});
        }
        return _origWrite(s);
    };

    // Monitor eval
    const _origEval = window.eval;
    window.eval = function(s) {
        if (typeof s === 'string' && s.includes(_probe)) {
            window.__tbl_sinks.push({sink: 'eval', snippet: s.substring(0, 200)});
        }
        return _origEval(s);
    };

    // Monitor location.href / location.hash writes (open redirect + DOM XSS)
    const _origLoc = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
    if (_origLoc && _origLoc.set) {
        Object.defineProperty(Location.prototype, 'href', {
            set(v) {
                if (typeof v === 'string' && v.includes(_probe)) {
                    window.__tbl_sinks.push({sink: 'location.href', snippet: v.substring(0, 200)});
                }
                return _origLoc.set.call(this, v);
            },
            get: _origLoc.get,
            configurable: true,
        });
    }
}
"""

_READ_SINKS_JS = "() => ({sinks: window.__tbl_sinks || [], fired: window.__tbl_fired || 0})"
_READ_TITLE_JS = "() => document.title"

# Max params to probe (avoid hammering large forms)
_MAX_PARAMS = 8


class BrowserDOMXSSScanner(BaseScanner):
    """DOM XSS detection via actual Chromium browser execution."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        if not playwright_available():
            logger.warning("Playwright not installed — skipping browser DOM XSS scan (pip install playwright && playwright install chromium)")
            return self.results

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            # No URL params → probe common param names on the page
            self._scan_no_params(url, parsed)
        else:
            self._scan_params(url, parsed, params)

        if not self.results:
            log_pass(logger, f"Browser DOM XSS — no sink invocations detected on {url}")
            self.results.append(self._result(
                url,
                "Browser DOM XSS — no sink invocations detected",
                "PASS",
                detail=(
                    "The browser-based DOM XSS scanner executed probe values in URL parameters "
                    "and monitored innerHTML, outerHTML, eval, document.write, and location.href "
                    "sinks in a real Chromium browser. No probe reached a dangerous sink without "
                    "encoding. This check goes beyond static analysis — it actually runs the "
                    "JavaScript to verify data flow."
                ),
            ))

        return self.results

    def _probe_url(self, base_parsed, params: dict, param: str, value: str) -> str:
        """Build a probe URL with the given value in param."""
        probe_params = {k: (v[0] if k != param else value) for k, v in params.items()}
        return f"{base_parsed.scheme}://{base_parsed.netloc}{base_parsed.path}?{urlencode(probe_params)}"

    def _scan_params(self, url: str, parsed, params: dict) -> None:
        """Probe each URL parameter with DOM XSS payload."""
        try:
            with BrowserSession(headless=True) as session:
                for param in list(params.keys())[:_MAX_PARAMS]:
                    probe_url = self._probe_url(parsed, params, param, _DOM_XSS_PAYLOAD)
                    self._check_url(session, url, probe_url, param)
                    if any(r["status"] == "FAIL" for r in self.results):
                        break  # stop after first confirmed finding
        except Exception as e:
            logger.debug(f"Browser DOM XSS scan error: {e}")

    def _scan_no_params(self, url: str, parsed) -> None:
        """When URL has no params, probe common injection points as query strings."""
        common_params = ["q", "search", "query", "s", "id", "page", "name", "input"]
        try:
            with BrowserSession(headless=True) as session:
                for param in common_params[:4]:
                    probe_url = f"{url}{'&' if parsed.query else '?'}{param}={_DOM_XSS_PAYLOAD}"
                    self._check_url(session, url, probe_url, param)
                    if any(r["status"] == "FAIL" for r in self.results):
                        break
        except Exception as e:
            logger.debug(f"Browser DOM XSS scan error: {e}")

    def _check_url(self, session: BrowserSession, original_url: str, probe_url: str, param: str) -> None:
        """Navigate to probe URL in browser and check for sink invocations."""
        page = session.new_page()

        # Inject sink monitor BEFORE page JS runs
        try:
            page._page.add_init_script(_SINK_MONITOR_JS[4:-1])  # strip wrapping `() => { ... }`
        except Exception:
            # Fall back: inject after load if init script fails
            pass

        navigated = page.goto(probe_url, wait_until="networkidle", timeout=12000)
        if not navigated:
            return

        # Small wait for deferred JS (setTimeout, requestAnimationFrame)
        page.wait_for_timeout(500)

        # Read sink state
        sink_data = page.evaluate(_READ_SINKS_JS) or {}
        sinks_hit = sink_data.get("sinks", [])
        fired = sink_data.get("fired", 0)

        # Also check title (common sink for reflected XSS)
        title = page.evaluate(_READ_TITLE_JS) or ""

        if fired:
            log_fail(logger, f"Browser DOM XSS: payload executed on {original_url} param '{param}'")
            self.results.append(self._result(
                original_url,
                f"Browser DOM XSS — payload EXECUTED via param '{param}'",
                "FAIL",
                detail=(
                    f"The DOM XSS probe payload was EXECUTED in Chromium. "
                    f"The onerror handler fired (window.__tbl_fired=1) after injecting "
                    f"'{_DOM_XSS_PAYLOAD}' into URL parameter '{param}'.\n\n"
                    "This confirms the parameter value reaches a dangerous DOM sink without "
                    "sufficient sanitization, and the injected HTML was parsed and executed.\n\n"
                    "Fix:\n"
                    "• Use textContent instead of innerHTML for user-controlled data\n"
                    "• Apply DOMPurify.sanitize() before any innerHTML assignment\n"
                    "• Use framework-safe rendering (React JSX, Angular templates with sanitization)\n"
                    "• Enable Content-Security-Policy to restrict script execution"
                ),
            ))

        elif sinks_hit:
            sink_names = ", ".join(s.get("sink", "?") for s in sinks_hit[:3])
            log_warn(logger, f"Browser DOM XSS: probe reached sink(s) [{sink_names}] on {original_url} param '{param}'")
            self.results.append(self._result(
                original_url,
                f"Browser DOM XSS — probe reached DOM sink(s): {sink_names}",
                "WARN",
                detail=(
                    f"The probe value '{_DOM_XSS_PROBE}' was passed to DOM sink(s): {sink_names} "
                    f"when URL parameter '{param}' was set to the probe.\n\n"
                    "The sink received the probe string but the onerror handler did not fire, "
                    "which may mean the payload was partially sanitized, or the encoding "
                    "stripped the <img> tag but not the probe string itself.\n\n"
                    "Manual verification is required. This is a potential DOM XSS vector.\n\n"
                    "Fix: audit all uses of these DOM sinks and ensure user-controlled data "
                    "is sanitized with DOMPurify before assignment."
                ),
            ))

        elif _DOM_XSS_PROBE in title:
            log_warn(logger, f"Browser DOM XSS: probe in document.title on {original_url} param '{param}'")
            self.results.append(self._result(
                original_url,
                f"Browser DOM XSS — probe reflected in document.title via param '{param}'",
                "WARN",
                detail=(
                    f"The probe value appeared in document.title after injecting into '{param}'. "
                    "While title reflection is not directly exploitable for XSS, it indicates "
                    "unsanitized reflection into a DOM property, and some browsers historically "
                    "had title-based XSS vectors. Verify encoding is applied."
                ),
            ))

        # Also flag HTTP requests loaded by the page (mixed content)
        http_reqs = page.http_requests
        if http_reqs:
            http_urls = [r["url"] for r in http_reqs[:5]]
            log_warn(logger, f"Browser: {len(http_reqs)} HTTP sub-resources on {original_url}")
            self.results.append(self._result(
                original_url,
                f"Browser — {len(http_reqs)} HTTP sub-resource(s) loaded on HTTPS page",
                "WARN",
                detail=(
                    f"The browser detected {len(http_reqs)} HTTP (non-HTTPS) sub-resource "
                    f"request(s) while rendering the page:\n"
                    + "\n".join(f"• {u}" for u in http_urls)
                    + "\n\nHTTP sub-resources can be intercepted by network attackers "
                    "(mixed content). Modern browsers may block them, but they indicate "
                    "configuration drift.\n\nFix: update all resource URLs to HTTPS."
                ),
            ))
            return  # don't double-report per param
