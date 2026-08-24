"""Tests for redirect chain security scanner."""

from unittest.mock import MagicMock
from tblue.scanner.redirect_chain import RedirectChainScanner


def _scanner(chain: list):
    """
    chain: list of (url, status, location) tuples.
    Last entry has no Location (final destination).
    """
    session = MagicMock()
    call_count = [0]

    def fake_request(method, url, **kwargs):
        idx = call_count[0]
        call_count[0] += 1
        resp = MagicMock()
        if idx < len(chain):
            _, status, location = chain[idx]
            resp.status_code = status
            resp.headers = {"Location": location} if location else {}
        else:
            resp.status_code = 200
            resp.headers = {}
        return resp

    session.request.side_effect = fake_request
    return RedirectChainScanner(session)


# ── HTTPS throughout ──────────────────────────────────────────────────────────

def test_https_only_chain_passes():
    scanner = _scanner([
        ("https://example.com", 301, "https://www.example.com"),
        ("https://www.example.com", 200, None),
    ])
    results = scanner.scan("https://example.com")
    assert any("https throughout" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_no_redirects_clean():
    scanner = _scanner([
        ("https://example.com", 200, None),
    ])
    results = scanner.scan("https://example.com")
    # No redirects — no redirect count finding
    assert not any("redirect" in r["type"].lower() and r["status"] == "FAIL" for r in results)


# ── HTTP leg in chain ─────────────────────────────────────────────────────────

def test_http_to_https_redirect_flagged():
    scanner = _scanner([
        ("http://example.com",  301, "https://example.com"),
        ("https://example.com", 200, None),
    ])
    results = scanner.scan("http://example.com")
    assert any("http leg" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_https_sandwich_http_flagged():
    scanner = _scanner([
        ("https://example.com",        302, "http://cdn.example.com"),
        ("http://cdn.example.com",     302, "https://www.example.com"),
        ("https://www.example.com",    200, None),
    ])
    results = scanner.scan("https://example.com")
    assert any(("http leg" in r["type"].lower() or "https→http→https" in r["type"].lower())
               and r["status"] == "FAIL" for r in results)


def test_final_destination_http_warns():
    scanner = _scanner([
        ("https://example.com", 301, "http://www.example.com"),
        ("http://www.example.com", 200, None),
    ])
    results = scanner.scan("https://example.com")
    assert any(("http leg" in r["type"].lower() or "final destination" in r["type"].lower())
               and r["status"] in ("FAIL", "WARN") for r in results)


# ── Redirect count ────────────────────────────────────────────────────────────

def test_acceptable_redirect_count_passes():
    scanner = _scanner([
        ("https://example.com",    301, "https://www.example.com"),
        ("https://www.example.com",301, "https://www.example.com/home"),
        ("https://www.example.com/home", 200, None),
    ])
    results = scanner.scan("https://example.com")
    assert any("acceptable" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_many_redirects_warns():
    chain = []
    for i in range(6):
        chain.append((f"https://example.com/hop{i}", 301, f"https://example.com/hop{i+1}"))
    chain.append((f"https://example.com/hop6", 200, None))
    scanner = _scanner(chain)
    results = scanner.scan("https://example.com/hop0")
    assert any("many redirects" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Network error ─────────────────────────────────────────────────────────────

def test_network_error_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("timeout")
    scanner = RedirectChainScanner(session)
    results = scanner.scan("https://example.com")
    assert results == []


def test_redirect_loop_detected_fails():
    # Two steps that form a loop: A→B→A
    call_count = [0]
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.headers = {"Location": "https://example.com/b" if call_count[0] == 0 else "https://example.com"}
        resp.status_code = 302
        call_count[0] += 1
        return resp

    session.request.side_effect = fake_request
    s = RedirectChainScanner(session)
    results = s.scan("https://example.com")
    assert any("loop" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_none_response_breaks_chain_gracefully():
    # http.get() returns None after first hop → chain ends at that point
    call_count = [0]
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        if call_count[0] == 0:
            call_count[0] += 1
            resp = MagicMock()
            resp.status_code = 301
            resp.headers = {"Location": "https://www.example.com"}
            return resp
        call_count[0] += 1
        return None  # simulate exhausted retries

    session.request.side_effect = fake_request
    s = RedirectChainScanner(session)
    results = s.scan("https://example.com")
    # Should not crash; may return empty or partial results
    assert isinstance(results, list)


def test_relative_redirect_location_resolved():
    # Location header is a relative path, not absolute
    call_count = [0]
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        if call_count[0] == 0:
            resp.status_code = 301
            resp.headers = {"Location": "/new-path"}  # relative
        else:
            resp.status_code = 200
            resp.headers = {}
        call_count[0] += 1
        return resp

    session.request.side_effect = fake_request
    s = RedirectChainScanner(session)
    results = s.scan("https://example.com")
    # Relative redirect on an HTTPS origin → all HTTPS → PASS or no FAIL
    assert not any("http leg" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_excessive_redirects_fails():
    # Build a chain of exactly _MAX_REDIRECTS hops
    from tblue.scanner.redirect_chain import _MAX_REDIRECTS
    call_count = [0]
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        idx = call_count[0]
        call_count[0] += 1
        if idx < _MAX_REDIRECTS:
            resp.status_code = 302
            resp.headers = {"Location": f"https://example.com/hop{idx+1}"}
        else:
            resp.status_code = 200
            resp.headers = {}
        return resp

    session.request.side_effect = fake_request
    s = RedirectChainScanner(session)
    results = s.scan("https://example.com")
    assert any("excessive" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_no_redirects_skips_count_check():
    # A 200 with no Location → no redirect hops → _check_redirect_count returns early
    scanner = _scanner([("https://example.com", 200, None)])
    results = scanner.scan("https://example.com")
    # _check_redirect_count returns early for 0 redirects — no count-related finding
    count_finds = [r for r in results if "redirect" in r["type"].lower()
                   and "count" in r["type"].lower()]
    assert len(count_finds) == 0
