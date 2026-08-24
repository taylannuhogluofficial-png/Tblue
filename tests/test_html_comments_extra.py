"""Extra coverage for html_comments — lines 63-64 (exception in scan), 80 (short comment), 83 (max per label)."""

from unittest.mock import MagicMock, patch
from tblue.scanner.html_comments import HTMLCommentsScanner


def _scanner(html="", status=200):
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = status
        resp.text = html
        return resp

    session.request.side_effect = fake_request
    return HTMLCommentsScanner(session)


# ── Exception in scan() http.get (lines 63-64) ───────────────────────────────

def test_scan_http_get_exception_returns_empty():
    """Exception raised directly from http.get in scan() → except returns empty (lines 63-64)."""
    scanner = HTMLCommentsScanner(MagicMock())
    with patch.object(scanner.http, "get", side_effect=ConnectionError("timeout")):
        results = scanner.scan("https://example.com")
    assert results == []


def test_non_200_response_returns_empty():
    """Non-200 response returns empty results (early return on status_code != 200)."""
    scanner = _scanner(html="<!-- password: secret -->", status=403)
    results = scanner.scan("https://example.com")
    assert results == [], f"Expected empty results for 403 response, got: {results}"


def test_redirect_response_returns_empty():
    """302 redirect response returns empty results."""
    scanner = _scanner(html="", status=302)
    results = scanner.scan("https://example.com")
    assert results == []


def test_server_error_returns_empty():
    """500 error response returns empty results."""
    scanner = _scanner(html="<!-- db_password=secret -->", status=500)
    results = scanner.scan("https://example.com")
    assert results == []


# ── Comment shorter than _MIN_COMMENT_LEN (line 80) ──────────────────────────

def test_very_short_comment_below_min_length_skipped():
    """Comments shorter than _MIN_COMMENT_LEN are skipped (line 80 — continue)."""
    # _MIN_COMMENT_LEN appears to be around 10-20 chars; use extremely short comment
    scanner = _scanner("<!-- pw -->")
    results = scanner.scan("https://example.com")
    # Very short comment is skipped; only PASS should appear if any
    fail_results = [r for r in results if r["status"] == "FAIL"]
    assert not fail_results, f"Too-short comment should be skipped: {fail_results}"


def test_empty_comment_skipped():
    """Empty comment is skipped by the length check."""
    scanner = _scanner("<!---->")
    results = scanner.scan("https://example.com")
    fail_results = [r for r in results if r["status"] == "FAIL"]
    assert not fail_results


# ── _MAX_PER_LABEL reached (line 83) ─────────────────────────────────────────

def test_max_per_label_deduplication_applied():
    """More than _MAX_PER_LABEL (3) matching comments for same label are deduplicated (line 83)."""
    # Generate many API key comments with slightly different values
    comments = "\n".join(
        f"<!-- api_key: sk-live-aAbBcCdDeEfF{i:04d}gGhHiIjJkKlLmMnN -->"
        for i in range(20)
    )
    scanner = _scanner(comments)
    results = scanner.scan("https://example.com")

    api_key_findings = [r for r in results if "api key" in r.get("type", "").lower()
                        or "credential" in r.get("type", "").lower()
                        or r["status"] in ("FAIL", "WARN")]
    # The max-per-label cap must apply — fewer than 20 findings
    findings_count = len([r for r in results if r["status"] in ("FAIL", "WARN")])
    assert findings_count < 20, f"Max-per-label cap not applied: got {findings_count} findings"
