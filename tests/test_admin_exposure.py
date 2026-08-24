"""Tests for admin panel and debug interface exposure scanner."""

from unittest.mock import MagicMock
from tblue.scanner.admin_exposure import AdminExposureScanner, _MIN_BODY_LEN


def _scanner(path_responses: dict = None):
    """
    path_responses: {"/path": (status_code, body)}
    All other paths return 404.
    """
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 404
        resp.text = "Not Found"
        if path_responses:
            for path, (code, body) in path_responses.items():
                if url.endswith(path) or ("/" + path.lstrip("/")) in url:
                    resp.status_code = code
                    resp.text = body
                    break
        return resp

    session.request.side_effect = fake_request
    return AdminExposureScanner(session)


_REAL_BODY = "x" * (_MIN_BODY_LEN + 10)


# ── Clean scan ────────────────────────────────────────────────────────────────

def test_no_exposed_paths_passes():
    scanner = _scanner()
    results = scanner.scan("https://example.com")
    assert any("no sensitive paths" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


# ── Admin panels ──────────────────────────────────────────────────────────────

def test_exposed_admin_panel_fails():
    scanner = _scanner({"/admin": (200, _REAL_BODY)})
    results = scanner.scan("https://example.com")
    assert any("admin panel" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_exposed_wp_admin_fails():
    scanner = _scanner({"/wp-admin/": (200, _REAL_BODY)})
    results = scanner.scan("https://example.com")
    assert any("wordpress admin" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_exposed_phpmyadmin_fails():
    scanner = _scanner({"/phpmyadmin/": (200, _REAL_BODY)})
    results = scanner.scan("https://example.com")
    assert any("phpmyadmin" in r["type"].lower() and r["status"] == "FAIL" for r in results)


# ── Debug interfaces ──────────────────────────────────────────────────────────

def test_exposed_symfony_profiler_fails():
    scanner = _scanner({"/_profiler/": (200, _REAL_BODY)})
    results = scanner.scan("https://example.com")
    assert any("symfony profiler" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_exposed_laravel_telescope_fails():
    scanner = _scanner({"/telescope": (200, _REAL_BODY)})
    results = scanner.scan("https://example.com")
    assert any("laravel telescope" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_exposed_spring_actuator_env_fails():
    scanner = _scanner({"/actuator/env": (200, _REAL_BODY)})
    results = scanner.scan("https://example.com")
    assert any("spring boot env dump" in r["type"].lower() and r["status"] == "FAIL"
               for r in results)


# ── API docs ──────────────────────────────────────────────────────────────────

def test_exposed_swagger_warns():
    scanner = _scanner({"/swagger-ui.html": (200, _REAL_BODY)})
    results = scanner.scan("https://example.com")
    assert any("swagger" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_exposed_openapi_json_warns():
    scanner = _scanner({"/openapi.json": (200, _REAL_BODY)})
    results = scanner.scan("https://example.com")
    assert any("openapi" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Env files ─────────────────────────────────────────────────────────────────

def test_exposed_env_file_fails():
    env_body = "APP_SECRET=supersecretvalue123456\nDB_PASSWORD=hunter2\nAPI_KEY=abc123xyz\n"
    scanner = _scanner({"/.env": (200, env_body)})
    results = scanner.scan("https://example.com")
    assert any(".env file" in r["type"].lower() and r["status"] == "FAIL" for r in results)


# ── False positive suppression ────────────────────────────────────────────────

def test_spa_catch_all_not_flagged():
    # SPA returns 200 for every path with tiny body
    scanner = _scanner({"/admin": (200, "x" * 10)})
    results = scanner.scan("https://example.com")
    # Short body should be ignored — no FAIL
    assert not any("admin panel" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_404_in_body_not_flagged():
    body = "<html><title>404 Not Found</title><p>Page not found</p></html>"
    scanner = _scanner({"/admin": (200, body)})
    results = scanner.scan("https://example.com")
    # 200 response but body says 404 — should be ignored
    assert not any("admin panel" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_403_not_flagged():
    scanner = _scanner({"/admin": (403, "Forbidden")})
    results = scanner.scan("https://example.com")
    assert not any("admin panel" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_network_error_not_crash():
    session = MagicMock()
    session.request.side_effect = Exception("Connection refused")
    scanner = AdminExposureScanner(session)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)
