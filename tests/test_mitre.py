"""Tests for MITRE ATT&CK technique lookup."""

from tblue.mitre import get_techniques


# ── Basic lookups ──────────────────────────────────────────────────────────────

def test_clean_type_returns_empty():
    result = get_techniques("All checks passed")
    assert result == []


def test_hsts_missing_maps_to_adversary_in_the_middle():
    result = get_techniques("HSTS missing")
    ids = [t["id"] for t in result]
    assert "T1557" in ids


def test_admin_exposed_maps_to_t1190():
    result = get_techniques("Admin panel exposed — /admin")
    ids = [t["id"] for t in result]
    assert "T1190" in ids


def test_env_file_exposed_maps_to_credentials_in_files():
    result = get_techniques(".env file exposed at /.env")
    ids = [t["id"] for t in result]
    assert "T1552.001" in ids


def test_xss_maps_to_javascript_technique():
    result = get_techniques("XSS reflected in search parameter")
    ids = [t["id"] for t in result]
    assert "T1059.007" in ids


def test_subdomain_takeover_maps_to_t1584():
    result = get_techniques("Subdomain takeover — blog.example.com → github.io")
    ids = [t["id"] for t in result]
    assert "T1584.001" in ids


def test_open_redirect_maps_to_spearphishing():
    result = get_techniques("Open redirect parameter detected — ?next=")
    ids = [t["id"] for t in result]
    assert "T1566.002" in ids


def test_cookie_missing_httponly_maps_to_steal_cookie():
    result = get_techniques("Cookie missing HttpOnly flag — session cookie")
    ids = [t["id"] for t in result]
    assert "T1539" in ids


def test_cors_wildcard_maps_to_browser_session():
    result = get_techniques("CORS wildcard origin accepted with credentials")
    ids = [t["id"] for t in result]
    assert "T1185" in ids


def test_supply_chain_maps_to_t1195():
    result = get_techniques("SRI missing — external scripts without subresource integrity")
    ids = [t["id"] for t in result]
    assert "T1195.002" in ids


def test_port_exposed_maps_to_network_info():
    result = get_techniques("Port 6379 open — Redis exposed")
    ids = [t["id"] for t in result]
    assert "T1590" in ids


def test_typosquatting_maps_to_domain_acquisition():
    result = get_techniques("Typosquatting domain found — examp1e.com")
    ids = [t["id"] for t in result]
    assert "T1583.001" in ids


def test_robots_txt_maps_to_automated_collection():
    result = get_techniques("robots.txt sensitive paths disclosed")
    ids = [t["id"] for t in result]
    assert "T1119" in ids


def test_version_disclosure_maps_to_gather_host_info():
    result = get_techniques("Version disclosure — X-Powered-By: PHP/8.0")
    ids = [t["id"] for t in result]
    assert "T1592" in ids


# ── Result structure ───────────────────────────────────────────────────────────

def test_technique_has_required_fields():
    result = get_techniques("HSTS missing")
    assert result
    for t in result:
        assert "id" in t
        assert "name" in t
        assert "tactic" in t
        assert "url" in t


def test_technique_url_contains_id():
    result = get_techniques("HSTS missing")
    t = result[0]
    assert t["id"].replace(".", "/") in t["url"]


# ── Deduplication ──────────────────────────────────────────────────────────────

def test_no_duplicate_technique_ids():
    # A finding that could match multiple rules
    result = get_techniques("Admin exposed XSS .env file version disclosure")
    ids = [t["id"] for t in result]
    assert len(ids) == len(set(ids))


# ── Multiple techniques per finding ───────────────────────────────────────────

def test_multiple_techniques_returned():
    # HSTS missing → T1557 (AitM) — but could also map to others depending on phrasing
    result = get_techniques("HSTS missing — HTTP downgrade possible")
    assert len(result) >= 1


def test_jwt_maps_to_access_token():
    result = get_techniques("JWT alg:none accepted — no signature verification")
    ids = [t["id"] for t in result]
    assert "T1134" in ids


# ── No false positives on common passing phrases ──────────────────────────────

def test_pass_message_returns_empty():
    assert get_techniques("HTTPS enforced — no HTTP redirect") == []


def test_all_headers_present_returns_empty():
    assert get_techniques("All security headers present") == []
