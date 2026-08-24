"""Service Worker security deep — unsafe fetch interception, skipWaiting risks, wildcard scope, postMessage without origin check."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_SW_REGISTER_RE = re.compile(
    r'navigator\.serviceWorker\.register\s*\(\s*["\']([^"\']+)["\']',
    re.I,
)
_SW_SKIP_WAITING_RE = re.compile(r'\bskipWaiting\s*\(\s*\)', re.I)
_SW_CLAIM_CLIENTS_RE = re.compile(r'\bclients\.claim\s*\(\s*\)', re.I)
_SW_FETCH_INTERCEPT_RE = re.compile(r"self\.addEventListener\s*\(\s*['\"]fetch['\"]", re.I)
_SW_NO_ORIGIN_CHECK_RE = re.compile(
    r'self\.addEventListener\s*\(\s*[\'"]message[\'"]\s*,[^}]{0,200}\bevent\.data\b(?![^}]{0,100}origin)',
    re.I | re.S,
)
_SW_CACHE_SENSITIVE_RE = re.compile(
    r'cache\.put\s*\([^)]*(?:token|auth|credential|password|session)',
    re.I,
)
_SW_CACHE_ALL_RE = re.compile(r'cache\.addAll\s*\(\s*\[', re.I)
_SW_EVAL_RE = re.compile(r'\beval\s*\(|importScripts\s*\([^)]*http://', re.I)

_SW_SCOPE_WIDE_RE = re.compile(r'scope\s*:\s*["\']\/["\']', re.I)

_SW_PATHS = ["/sw.js", "/service-worker.js", "/serviceworker.js", "/worker.js", "/sw-bundle.js", "/assets/sw.js"]


def _get_header(headers, name: str) -> str:
    if hasattr(headers, "get"):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    if isinstance(headers, dict):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    return ""


class ServiceWorkerSecurityDeepScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "sw_deep_no_response", "PASS", detail="No response")]

        body = resp.text or ""
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        sw_registrations = _SW_REGISTER_RE.findall(body)
        if _SW_SCOPE_WIDE_RE.search(body):
            results.append(self._result(url, "sw_scope_too_wide", "WARN",
                                        detail="Service worker registered with scope '/' — "
                                               "intercepts ALL page requests including sensitive API calls; "
                                               "scope should be restricted to the minimum required path"))

        sw_files_to_check = []
        for sw_path in sw_registrations:
            if sw_path.startswith("/"):
                sw_files_to_check.append(origin + sw_path)
            elif sw_path.startswith("http"):
                sw_files_to_check.append(sw_path)

        for path in _SW_PATHS:
            sw_files_to_check.append(origin + path)

        checked = set()
        for sw_url in sw_files_to_check:
            if sw_url in checked:
                continue
            checked.add(sw_url)
            try:
                sw_resp = self.http.get(sw_url)
                if sw_resp is None or sw_resp.status_code != 200:
                    continue
                sw_body = sw_resp.text or ""
                sw_ct = _get_header(sw_resp.headers, "content-type")

                if "javascript" not in sw_ct.lower() and "application/x-javascript" not in sw_ct.lower():
                    if "service-worker-allowed" not in str(sw_resp.headers).lower():
                        continue

                if _SW_SKIP_WAITING_RE.search(sw_body) and _SW_FETCH_INTERCEPT_RE.search(sw_body):
                    results.append(self._result(sw_url, "sw_skip_waiting_with_fetch", "WARN",
                                                detail="Service worker uses skipWaiting() + fetch intercept — "
                                                       "new SW activates immediately without user reload, "
                                                       "potentially serving stale or attacker-controlled cached responses"))

                if _SW_NO_ORIGIN_CHECK_RE.search(sw_body):
                    results.append(self._result(sw_url, "sw_message_no_origin_check", "FAIL",
                                                detail="Service worker message handler uses event.data without checking event.origin — "
                                                       "malicious pages can send arbitrary commands to the service worker"))

                if _SW_CACHE_SENSITIVE_RE.search(sw_body):
                    results.append(self._result(sw_url, "sw_caches_sensitive_data", "WARN",
                                                detail="Service worker caches responses with token/auth/credential in key — "
                                                       "authentication artifacts persisted in Cache Storage, "
                                                       "accessible after logout if cache not cleared"))

                if _SW_EVAL_RE.search(sw_body):
                    results.append(self._result(sw_url, "sw_eval_or_http_import", "FAIL",
                                                detail="Service worker uses eval() or imports scripts over HTTP — "
                                                       "CSP unsafe-eval or MITM attack can inject arbitrary code "
                                                       "into service worker context"))

                if results:
                    break
            except Exception:
                pass

        if not results:
            if sw_registrations or any(self._try_head(origin + p) for p in _SW_PATHS[:2]):
                results.append(self._result(url, "sw_deep_found_no_issues", "PASS",
                                            detail="Service worker detected but no deep security issues found"))
            else:
                results.append(self._result(url, "sw_not_found", "PASS",
                                            detail="No service worker registration detected"))
        return results

    def _try_head(self, url: str) -> bool:
        try:
            r = self.http.get(url)
            return r is not None and r.status_code == 200
        except Exception:
            return False
