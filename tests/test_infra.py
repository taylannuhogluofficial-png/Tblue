"""Tests for infrastructure hardening scanner."""

from unittest.mock import MagicMock, patch
from tblue.scanner.infra import InfraScanner


def _make_resp(status=404, body="Not Found", headers=None):
    resp = MagicMock()
    resp.status_code = status
    resp.text        = body
    resp.headers     = headers or {}
    return resp


def _scanner_with_responses(url_responses: dict):
    """Build a scanner whose http.get() returns responses keyed by URL substring."""
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        for pattern, resp in url_responses.items():
            if pattern in url:
                return resp
        return _make_resp()  # default 404

    session.request.side_effect = fake_request
    return InfraScanner(session)


# ── Directory listing ─────────────────────────────────────────────────────────

def test_directory_listing_detected():
    scanner = _scanner_with_responses({
        "/uploads/": _make_resp(200, "Index of /uploads/\n<a href='../'>Parent Directory</a>"),
    })
    scanner._check_directory_listing("https://example.com")
    assert any("directory listing" in r["type"].lower() and r["status"] == "FAIL"
               for r in scanner.results)


def test_no_directory_listing_passes():
    scanner = _scanner_with_responses({})
    scanner._check_directory_listing("https://example.com")
    assert any("directory listing" in r["type"].lower() and r["status"] == "PASS"
               for r in scanner.results)


# ── Artifacts ─────────────────────────────────────────────────────────────────

def test_git_config_exposed_fails():
    scanner = _scanner_with_responses({
        "/.git/config": _make_resp(200, "[core]\n\trepositoryformatversion = 0\n"),
    })
    scanner._check_artifacts("https://example.com")
    assert any(".git" in r["type"].lower() and r["status"] == "FAIL"
               for r in scanner.results)


def test_source_map_exposed_warns():
    scanner = _scanner_with_responses({
        "/js/app.js.map": _make_resp(200, '{"version":3,"sources":["app.js"],"mappings":"AAAA"}'),
    })
    scanner._check_artifacts("https://example.com")
    assert any("source map" in r["type"].lower() and r["status"] == "WARN"
               for r in scanner.results)


def test_html_false_positive_skipped():
    # A 200 response that's actually HTML should be filtered
    scanner = _scanner_with_responses({
        "/.git/config": _make_resp(200, "<!DOCTYPE html><html><body>Not found</body></html>"),
    })
    scanner._check_artifacts("https://example.com")
    assert not any(".git" in r["type"].lower() and r["status"] == "FAIL"
                   for r in scanner.results)


def test_404_artifact_not_flagged():
    scanner = _scanner_with_responses({})
    scanner._check_artifacts("https://example.com")
    assert not any("git" in r["type"].lower() and r["status"] == "FAIL"
                   for r in scanner.results)


# ── Referrer-Policy ───────────────────────────────────────────────────────────

def test_referrer_policy_unsafe_url_warns():
    scanner = _scanner_with_responses({
        "example.com": _make_resp(200, "", {"Referrer-Policy": "unsafe-url"}),
    })
    scanner._check_referrer_policy("https://example.com")
    assert any("unsafe-url" in r["type"].lower() and r["status"] == "WARN"
               for r in scanner.results)


def test_safe_referrer_policy_no_warn():
    scanner = _scanner_with_responses({
        "example.com": _make_resp(200, "", {"Referrer-Policy": "strict-origin-when-cross-origin"}),
    })
    scanner._check_referrer_policy("https://example.com")
    assert not any("unsafe-url" in r["type"].lower() for r in scanner.results)


def test_no_referrer_when_downgrade_warns():
    scanner = _scanner_with_responses({
        "example.com": _make_resp(200, "", {"Referrer-Policy": "no-referrer-when-downgrade"}),
    })
    scanner._check_referrer_policy("https://example.com")
    assert any("no-referrer-when-downgrade" in r["type"].lower() for r in scanner.results)


def test_missing_referrer_policy_header_no_result():
    scanner = _scanner_with_responses({
        "example.com": _make_resp(200, "", {}),
    })
    scanner._check_referrer_policy("https://example.com")
    # If header is absent, infra scanner defers to base headers scanner
    assert not any("referrer" in r["type"].lower() for r in scanner.results)


def test_referrer_policy_exception_does_not_crash():
    session = MagicMock()
    session.request.side_effect = Exception("timeout")
    scanner = InfraScanner(session)
    scanner._check_referrer_policy("https://example.com")
    assert isinstance(scanner.results, list)


# ── OpenID Connect discovery ──────────────────────────────────────────────────

def test_oidc_discovery_exposed_warns():
    body = '{"issuer":"https://example.com","authorization_endpoint":"https://example.com/auth"}'
    scanner = _scanner_with_responses({
        "/.well-known/openid-configuration": _make_resp(200, body),
    })
    scanner._check_openid_config("https://example.com")
    assert any("openid" in r["type"].lower() and r["status"] == "WARN" for r in scanner.results)


def test_oidc_not_exposed_no_result():
    scanner = _scanner_with_responses({})
    scanner._check_openid_config("https://example.com")
    assert not any("openid" in r["type"].lower() for r in scanner.results)


def test_oidc_exception_does_not_crash():
    session = MagicMock()
    session.request.side_effect = Exception("dns failure")
    scanner = InfraScanner(session)
    scanner._check_openid_config("https://example.com")
    assert isinstance(scanner.results, list)


# ── Directory listing — more paths ────────────────────────────────────────────

def test_multiple_paths_with_dir_listing():
    scanner = _scanner_with_responses({
        "/uploads/": _make_resp(200, "Index of /uploads/"),
        "/images/":  _make_resp(200, "Index of /images/"),
    })
    scanner._check_directory_listing("https://example.com")
    listing = [r for r in scanner.results if "directory listing" in r["type"].lower()
               and r["status"] == "FAIL"]
    assert listing
    assert "uploads" in listing[0]["detail"] or "images" in listing[0]["detail"]


# ── Artifact seen_types dedup ─────────────────────────────────────────────────

def test_only_one_result_per_artifact_type():
    # Both app.js.map and main.js.map match "Source map" — should dedup to one result
    scanner = _scanner_with_responses({
        "/js/app.js.map":  _make_resp(200, '{"version":3,"sources":["app.js"]}'),
        "/js/main.js.map": _make_resp(200, '{"version":3,"sources":["main.js"]}'),
    })
    scanner._check_artifacts("https://example.com")
    source_map_results = [r for r in scanner.results if "source map" in r["type"].lower()]
    assert len(source_map_results) == 1


# ── Full scan integration ─────────────────────────────────────────────────────

def test_scan_returns_list():
    scanner = _scanner_with_responses({})
    results = scanner.scan("https://example.com")
    assert isinstance(results, list)


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_directory_listing_get_raises_continues():
    """http.get raises for directory paths → except Exception: continue at lines 90-91."""
    scanner = _scanner_with_responses({})
    with patch.object(scanner.http, "get", side_effect=RuntimeError("timeout")):
        scanner._check_directory_listing("https://example.com")
    assert any("directory listing" in r["type"].lower() and r["status"] == "PASS"
               for r in scanner.results)


def test_artifacts_get_raises_continues():
    """http.get raises for artifact paths → except Exception: continue at lines 137-138."""
    scanner = _scanner_with_responses({})
    with patch.object(scanner.http, "get", side_effect=RuntimeError("timeout")):
        scanner._check_artifacts("https://example.com")
    assert scanner.results == []  # no artifacts flagged when all probes raise


def test_openid_config_get_raises_passes():
    """http.get raises for OIDC path → except Exception: pass at lines 162-163."""
    scanner = _scanner_with_responses({})
    with patch.object(scanner.http, "get", side_effect=RuntimeError("connection refused")):
        scanner._check_openid_config("https://example.com")
    assert scanner.results == []  # exception swallowed, no results


def test_referrer_policy_get_raises_passes():
    """http.get raises in _check_referrer_policy → except Exception: pass at lines 196-197."""
    scanner = _scanner_with_responses({})
    with patch.object(scanner.http, "get", side_effect=RuntimeError("timeout")):
        scanner._check_referrer_policy("https://example.com")
    assert scanner.results == []  # exception swallowed, no results
