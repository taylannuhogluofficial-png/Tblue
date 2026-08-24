"""Tests for Cross-Domain Policy & Mobile App Link Security scanner."""

import pytest
from unittest.mock import MagicMock, patch

from tblue.scanner.crossdomain_policy import CrossDomainPolicyScanner


def _make_scanner():
    session = MagicMock()
    return CrossDomainPolicyScanner(session)


def _resp(text="", status_code=200, headers=None):
    r = MagicMock()
    r.text = text
    r.status_code = status_code
    r.headers = headers or {}
    return r


def _404():
    return _resp("Not Found", status_code=404)


# 1 — Unreachable target
def test_unreachable_target():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert len(results) == 1
    assert results[0]["status"] == "PASS"
    assert "unreachable" in results[0]["type"].lower()


# 2 — Clean target — no policy files present
def test_clean_target_no_policy_files():
    s = _make_scanner()

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    assert all(r["status"] == "PASS" for r in results)


# 3 — crossdomain.xml with wildcard domain → FAIL
def test_crossdomain_wildcard_fail():
    s = _make_scanner()
    crossdomain_body = """<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="*"/>
</cross-domain-policy>"""

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if url == "https://example.com/crossdomain.xml":
            return _resp(crossdomain_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_findings) >= 1
    assert "wildcard" in fail_findings[0]["type"].lower() or "*" in fail_findings[0]["detail"]


# 4 — crossdomain.xml with allow-http-request-headers-from wildcard → FAIL
def test_crossdomain_header_wildcard_fail():
    s = _make_scanner()
    crossdomain_body = """<?xml version="1.0"?>
<cross-domain-policy>
  <site-control permitted-cross-domain-policies="all"/>
  <allow-http-request-headers-from domain="*" headers="*"/>
</cross-domain-policy>"""

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if url == "https://example.com/crossdomain.xml":
            return _resp(crossdomain_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_findings) >= 1
    assert "header" in fail_findings[0]["detail"].lower()


# 5 — crossdomain.xml with secure=false → WARN
def test_crossdomain_insecure_false_warn():
    s = _make_scanner()
    crossdomain_body = """<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="partner.example.com" secure="false"/>
</cross-domain-policy>"""

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if url == "https://example.com/crossdomain.xml":
            return _resp(crossdomain_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_findings = [r for r in results if r["status"] == "WARN" and "http" in r["type"].lower()]
    assert len(warn_findings) >= 1


# 6 — crossdomain.xml with wildcard subdomain → WARN
def test_crossdomain_subdomain_wildcard_warn():
    s = _make_scanner()
    crossdomain_body = """<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="*.partner.com"/>
</cross-domain-policy>"""

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if url == "https://example.com/crossdomain.xml":
            return _resp(crossdomain_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_findings = [r for r in results if r["status"] == "WARN" and "subdomain" in r["type"].lower()]
    assert len(warn_findings) >= 1


# 7 — crossdomain.xml present but restricted → WARN (review)
def test_crossdomain_restricted_warn():
    s = _make_scanner()
    crossdomain_body = """<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="trusted.partner.com"/>
</cross-domain-policy>"""

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if url == "https://example.com/crossdomain.xml":
            return _resp(crossdomain_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_findings = [r for r in results if r["status"] == "WARN" and "review" in r["type"].lower()]
    assert len(warn_findings) >= 1


# 8 — HTML on crossdomain.xml path → not flagged (validation check)
def test_crossdomain_html_response_not_flagged():
    s = _make_scanner()

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "crossdomain.xml" in url:
            # Server returns HTML 404 with 200 status
            return _resp("<html><body>Not Found</body></html>")
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_warn = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert len(fail_warn) == 0


# 9 — clientaccesspolicy.xml with wildcard domain → FAIL
def test_clientaccesspolicy_wildcard_fail():
    s = _make_scanner()
    cap_body = """<?xml version="1.0" encoding="utf-8"?>
<access-policy>
  <cross-domain-access>
    <policy>
      <allow-from>
        <domain uri="*"/>
      </allow-from>
      <grant-to>
        <resource path="/" include-subpaths="true"/>
      </grant-to>
    </policy>
  </cross-domain-access>
</access-policy>"""

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "clientaccesspolicy.xml" in url:
            return _resp(cap_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_findings = [r for r in results if r["status"] == "FAIL" and "clientaccess" in r["type"].lower()]
    assert len(fail_findings) >= 1


# 10 — clientaccesspolicy.xml with all paths → WARN
def test_clientaccesspolicy_all_paths_warn():
    s = _make_scanner()
    cap_body = """<?xml version="1.0"?>
<access-policy>
  <cross-domain-access>
    <policy>
      <allow-from><domain uri="trusted.example.com"/></allow-from>
      <grant-to><resource path="/" include-subpaths="true"/></grant-to>
    </policy>
  </cross-domain-access>
</access-policy>"""

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "clientaccesspolicy.xml" in url:
            return _resp(cap_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_findings = [r for r in results if r["status"] == "WARN" and "path" in r["type"].lower()]
    assert len(warn_findings) >= 1


# 11 — clientaccesspolicy.xml present, no wildcard → WARN (review)
def test_clientaccesspolicy_restricted_warn():
    s = _make_scanner()
    cap_body = """<?xml version="1.0"?>
<access-policy>
  <cross-domain-access>
    <policy>
      <allow-from><domain uri="specific.partner.com"/></allow-from>
      <grant-to><resource path="/api/data" include-subpaths="false"/></grant-to>
    </policy>
  </cross-domain-access>
</access-policy>"""

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "clientaccesspolicy.xml" in url:
            return _resp(cap_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_findings = [r for r in results if r["status"] == "WARN" and "clientaccesspolicy" in r["type"].lower()]
    assert len(warn_findings) >= 1


# 12 — apple-app-site-association with app IDs → WARN
def test_aasa_with_app_ids_warn():
    s = _make_scanner()
    aasa_body = """{
  "applinks": {
    "apps": [],
    "details": [
      {
        "appID": "ABCDE12345.com.example.myapp",
        "paths": ["/shop/*", "/account/*"]
      }
    ]
  }
}"""

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "apple-app-site-association" in url:
            return _resp(aasa_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_findings = [r for r in results if r["status"] == "WARN" and "apple" in r["type"].lower()]
    assert len(warn_findings) >= 1
    assert "ABCDE12345" in warn_findings[0]["detail"]


# 13 — apple-app-site-association with empty apps array → WARN
def test_aasa_empty_apps_array_warn():
    s = _make_scanner()
    aasa_body = """{
  "applinks": {
    "apps": [],
    "details": []
  }
}"""

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "apple-app-site-association" in url:
            return _resp(aasa_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_findings = [r for r in results if r["status"] == "WARN"]
    assert len(warn_findings) >= 1


# 14 — assetlinks.json with missing fingerprints → FAIL
def test_assetlinks_missing_fingerprints_fail():
    s = _make_scanner()
    assetlinks_body = """[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.example.myapp",
    "sha256_cert_fingerprints": []
  }
}]"""

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "assetlinks.json" in url:
            return _resp(assetlinks_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_findings) >= 1
    assert "fingerprint" in fail_findings[0]["detail"].lower() or "sha" in fail_findings[0]["detail"].lower()


# 15 — assetlinks.json with package name and fingerprints → WARN (informational)
def test_assetlinks_with_package_and_fingerprints_warn():
    s = _make_scanner()
    assetlinks_body = """[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.example.myapp",
    "sha256_cert_fingerprints": [
      "14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5"
    ]
  }
}]"""

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "assetlinks.json" in url:
            return _resp(assetlinks_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_findings = [r for r in results if r["status"] == "WARN" and "android" in r["type"].lower()]
    assert len(warn_findings) >= 1
    assert "com.example.myapp" in warn_findings[0]["detail"]


# 16 — crossdomain.xml throws exception → handled gracefully
def test_crossdomain_exception_handled():
    s = _make_scanner()
    call_count = [0]

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        call_count[0] += 1
        raise ConnectionError("timeout")

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    assert call_count[0] > 0
    assert any(r["status"] == "PASS" for r in results)


# 18 — clientaccesspolicy.xml with HTML body → not flagged (invalid XML structure)
def test_clientaccesspolicy_html_body_not_flagged():
    s = _make_scanner()

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "clientaccesspolicy.xml" in url:
            return _resp("<html><body>Not Found</body></html>")
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_warn = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert len(fail_warn) == 0


# 19 — AASA with webcredentials key but no applinks → present warning
def test_aasa_webcredentials_only_present():
    s = _make_scanner()
    aasa_body = """{
  "webcredentials": {
    "apps": ["ABCDE12345.com.example.myapp"]
  }
}"""

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "apple-app-site-association" in url:
            return _resp(aasa_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_findings = [r for r in results if r["status"] == "WARN" and "apple" in r["type"].lower()]
    assert len(warn_findings) >= 1


# 20 — assetlinks.json without relation → not flagged (not valid assetlinks format)
def test_assetlinks_no_relation_not_flagged():
    s = _make_scanner()
    assetlinks_body = '{"key": "value", "some": "random json"}'

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "assetlinks.json" in url:
            return _resp(assetlinks_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_warn = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert len(fail_warn) == 0


# 21 — assetlinks.json with relation but no package names → WARN (else branch)
def test_assetlinks_no_packages_warn():
    s = _make_scanner()
    assetlinks_body = """[{
  "relation": ["delegate_permission/common.get_login_creds"],
  "target": {
    "namespace": "web",
    "site": "https://example.com"
  }
}]"""

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "assetlinks.json" in url:
            return _resp(assetlinks_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_findings = [r for r in results if r["status"] == "WARN" and "assetlinks" in r["type"].lower()]
    assert len(warn_findings) >= 1


# 17 — crossdomain.xml not at primary path but found at /flash/ path
def test_crossdomain_found_at_alternate_path():
    s = _make_scanner()
    crossdomain_body = """<?xml version="1.0"?>
<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>"""

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if url == "https://example.com/flash/crossdomain.xml":
            return _resp(crossdomain_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_findings) >= 1
