"""Extra branch coverage for tblue.scanner.service_worker_security."""

from unittest.mock import MagicMock, patch
from tblue.scanner.service_worker_security import ServiceWorkerSecurityScanner

URL = "https://example.com"


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.url = URL
    return r


def _scanner():
    session = MagicMock()
    return ServiceWorkerSecurityScanner(session)


def test_no_service_worker_passes():
    """Page with no service worker → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html><body>No service worker</body></html>")):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_service_worker_detected():
    """Page registering a service worker → scanner processes it."""
    s = _scanner()
    html = '<html><script>navigator.serviceWorker.register("/sw.js")</script></html>'
    sw_body = "self.addEventListener('fetch', e => e.respondWith(caches.match(e.request)))"

    def get_side(url, **kw):
        if "sw.js" in url:
            return _resp(sw_body, 200)
        return _resp(html, 200)

    with patch.object(s.http, "get", side_effect=get_side):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_none_response_no_fail():
    """None response → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert all(r["status"] != "FAIL" for r in results)


def test_result_keys():
    """Results contain required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html></html>")):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
