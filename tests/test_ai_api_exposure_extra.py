"""Extra branch coverage for tblue.scanner.ai_api_exposure."""

from unittest.mock import MagicMock, patch
from tblue.scanner.ai_api_exposure import AIAPIExposureScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return AIAPIExposureScanner(session)


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.text = text
    r.status_code = status
    r.headers = headers or {}
    return r


def _404():
    return _resp("Not Found", 404)


def test_result_structure_all_pass():
    """All results have required keys when target is clean."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_404()):
        results = s.scan(URL)
    for r in results:
        assert "type" in r and "status" in r and "url" in r


def test_hf_tgi_info_endpoint_exposed():
    """Covers HuggingFace TGI /info endpoint detection branch."""
    s = _scanner()
    tgi_body = '{"model_id": "meta-llama/Llama-3-8b", "max_batch_total_tokens": 32000}'

    def fake_get(url, **kw):
        if url == URL:
            return _resp("<html></html>")
        if "/info" in url:
            return _resp(tgi_body, 200)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert any(r["status"] in ("FAIL", "WARN") for r in results)


def test_ollama_version_endpoint_warns():
    """Covers /api/version WARN-level detection for Ollama."""
    s = _scanner()
    version_body = '{"version": "0.3.6"}'

    def fake_get(url, **kw):
        if url == URL:
            return _resp("<html></html>")
        if "/api/version" in url:
            return _resp(version_body, 200)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_litellm_health_endpoint_detected():
    """Covers LiteLLM /health endpoint branch."""
    s = _scanner()
    health_body = '{"healthy_endpoints": [{"model": "gpt-4"}], "unhealthy_endpoints": []}'

    def fake_get(url, **kw):
        if url == URL:
            return _resp("<html></html>")
        if "/health" in url:
            return _resp(health_body, 200)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert any(r["status"] in ("FAIL", "WARN") for r in results)


def test_non_matching_json_body_skipped():
    """Covers branch where probe returns 200 but body doesn't match validator."""
    s = _scanner()

    def fake_get(url, **kw):
        if url == URL:
            return _resp("<html></html>")
        # 200 response but not an AI API response
        return _resp('{"error": "endpoint not found"}', 200)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert all(r["status"] == "PASS" for r in results)


def test_generic_llm_model_list_detected():
    """Covers generic models response with known model names."""
    s = _scanner()
    generic_body = '{"models": [{"name": "llama3:8b"}, {"name": "mistral:7b"}]}'

    def fake_get(url, **kw):
        if url == URL:
            return _resp("<html></html>")
        if "/v1/models" in url or "/api/tags" in url:
            return _resp(generic_body, 200)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert any(r["status"] in ("FAIL", "WARN") for r in results)
