"""Extra branch coverage for tblue.scanner.spring_actuator."""

import json
from unittest.mock import MagicMock, patch
from tblue.scanner.spring_actuator import SpringActuatorScanner

URL = "https://example.com"


def _resp(body="", status=200):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    r.url = URL
    return r


def _scanner():
    session = MagicMock()
    return SpringActuatorScanner(session)


def test_no_actuator_passes():
    """No actuator endpoints found → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("", 404)):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_env_actuator_exposed_fails():
    """Exposed /actuator/env → FAIL."""
    s = _scanner()
    env_body = json.dumps({
        "activeProfiles": ["prod"],
        "propertySources": [{"name": "system", "properties": {"DB_PASSWORD": {"value": "secret"}}}]
    })

    def get_side(url, **kw):
        if "/actuator/env" in url:
            return _resp(env_body, 200)
        return _resp("", 404)

    with patch.object(s.http, "get", side_effect=get_side):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_health_only_passes():
    """Only /actuator/health exposed → PASS (health endpoint is safe)."""
    s = _scanner()
    health_body = json.dumps({"status": "UP"})

    def get_side(url, **kw):
        if "/actuator/health" in url:
            return _resp(health_body, 200)
        return _resp("", 404)

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
    with patch.object(s.http, "get", return_value=_resp("", 404)):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
