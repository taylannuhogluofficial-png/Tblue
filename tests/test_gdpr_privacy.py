"""Tests for GDPR/privacy compliance checks."""

from unittest.mock import MagicMock
from tblue.scanner.gdpr_privacy import GDPRPrivacyScanner


def _scanner(html="", set_cookie="", cookies=None):
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = html
        resp.headers = {}
        if set_cookie:
            resp.headers["Set-Cookie"] = set_cookie
        # Mock the cookies jar
        if cookies:
            resp.cookies = {k: v for k, v in cookies.items()}
        else:
            resp.cookies = {}
        return resp

    session.request.side_effect = fake_request
    return GDPRPrivacyScanner(session)


_COOKIEBOT_HTML = '<script id="Cookiebot" src="https://consent.cookiebot.com/uc.js"></script>'
_ONETRUST_HTML = '<script src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js" data-domain-script="abc"></script>'
_PRIVACY_HTML = '<a href="/privacy-policy">Privacy Policy</a>'
_NO_PRIVACY_HTML = '<a href="/about">About</a><a href="/contact">Contact</a>'
_GA_HTML = '<script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXX"></script>'
_FB_HTML = '<script>!function(f,b,e,v){fbq("init","123456")}</script>'
_GENERIC_CONSENT_HTML = '<div id="cookie-banner" class="cookieconsent">We use cookies</div>'


# ── Consent banner detection ───────────────────────────────────────────────────

def test_cookiebot_detected():
    scanner = _scanner(_COOKIEBOT_HTML)
    results = scanner.scan("https://example.com")
    assert any("cookiebot" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_onetrust_detected():
    scanner = _scanner(_ONETRUST_HTML)
    results = scanner.scan("https://example.com")
    assert any("onetrust" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_generic_consent_banner_detected():
    scanner = _scanner(_GENERIC_CONSENT_HTML)
    results = scanner.scan("https://example.com")
    assert any("consent" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_no_consent_banner_warns():
    scanner = _scanner("<html><body>Hello</body></html>")
    results = scanner.scan("https://example.com")
    assert any("no cookie consent banner" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


# ── Privacy policy link ───────────────────────────────────────────────────────

def test_privacy_policy_link_passes():
    scanner = _scanner(_PRIVACY_HTML)
    results = scanner.scan("https://example.com")
    assert any("privacy policy link present" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_datenschutz_link_passes():
    scanner = _scanner('<a href="/datenschutz">Datenschutz</a>')
    results = scanner.scan("https://example.com")
    assert any("privacy policy link present" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_no_privacy_policy_warns():
    scanner = _scanner(_NO_PRIVACY_HTML)
    results = scanner.scan("https://example.com")
    assert any("no privacy policy link" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


# ── Tracking scripts ──────────────────────────────────────────────────────────

def test_google_analytics_detected():
    scanner = _scanner(_GA_HTML)
    results = scanner.scan("https://example.com")
    assert any("google analytics" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


def test_facebook_pixel_detected():
    scanner = _scanner(_FB_HTML)
    results = scanner.scan("https://example.com")
    assert any("facebook pixel" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


def test_no_tracking_scripts_passes():
    scanner = _scanner("<html><body>Clean page</body></html>")
    results = scanner.scan("https://example.com")
    assert any("no tracking scripts" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


# ── Cookies before consent ────────────────────────────────────────────────────

def test_non_essential_cookie_on_first_load_warns():
    scanner = _scanner(set_cookie="analytics_session=abc123; Path=/")
    results = scanner.scan("https://example.com")
    assert any("cookies set on first load" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


def test_session_cookie_not_flagged():
    scanner = _scanner(set_cookie="PHPSESSID=abc123; Path=/; HttpOnly")
    results = scanner.scan("https://example.com")
    assert not any("cookies set on first load" in r["type"].lower() for r in results)


# ── Network error → empty ─────────────────────────────────────────────────────

def test_network_error_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("timeout")
    scanner = GDPRPrivacyScanner(session)
    results = scanner.scan("https://example.com")
    assert results == []


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_http_get_raises_directly_returns_empty():
    """Patching http.get to raise directly → except at lines 75-76 → empty results."""
    from unittest.mock import patch
    scanner = GDPRPrivacyScanner(MagicMock())
    with patch.object(scanner.http, "get", side_effect=RuntimeError("network down")):
        results = scanner.scan("https://example.com")
    assert results == []


def test_cookies_via_cookies_jar_property_warns():
    """No Set-Cookie header but resp.cookies has entries → line 179 → WARN."""
    scanner = _scanner(cookies={"analytics_track": "user123"})
    results = scanner.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("cookies set on first load" in w["type"].lower() for w in warns)


def test_check_cookies_headers_get_raises():
    """resp.headers.get raises in _check_cookies_before_consent → except at lines 171-172."""
    from unittest.mock import patch
    scanner = GDPRPrivacyScanner(MagicMock())
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "<html></html>"
    mock_resp.cookies = {}
    mock_resp.headers = MagicMock()
    mock_resp.headers.get.side_effect = RuntimeError("bad headers object")
    with patch.object(scanner.http, "get", return_value=mock_resp):
        results = scanner.scan("https://example.com")
    assert isinstance(results, list)


def test_check_cookies_dict_conversion_raises():
    """dict(resp.cookies) raises in _check_cookies_before_consent → except at line 181."""
    from unittest.mock import patch
    scanner = GDPRPrivacyScanner(MagicMock())
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "<html></html>"
    mock_resp.headers = {}  # no Set-Cookie header → cookie_header = ""
    mock_resp.cookies.keys.side_effect = RuntimeError("broken cookies jar")
    with patch.object(scanner.http, "get", return_value=mock_resp):
        results = scanner.scan("https://example.com")
    assert isinstance(results, list)
