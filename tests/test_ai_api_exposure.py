"""Tests for AI/LLM API Endpoint Exposure scanner."""

import pytest
from unittest.mock import MagicMock, patch

from tblue.scanner.ai_api_exposure import AIAPIExposureScanner


def _make_scanner():
    session = MagicMock()
    return AIAPIExposureScanner(session)


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


# 2 — Clean target — no AI endpoints respond
def test_clean_target_no_ai_endpoints():
    s = _make_scanner()

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html><body>Normal website</body></html>")
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    assert all(r["status"] == "PASS" for r in results)


# 3 — Ollama /api/tags exposed → FAIL
def test_ollama_tags_exposed_fail():
    s = _make_scanner()
    ollama_resp = _resp("""{
  "models": [
    {"name": "llama3.2:latest", "size": 2019393189},
    {"name": "mistral:7b", "size": 4113301824}
  ]
}""")

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "/api/tags" in url:
            return ollama_resp
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_findings) >= 1
    assert "ollama" in fail_findings[0]["type"].lower() or "model" in fail_findings[0]["type"].lower()


# 4 — OpenAI-compatible /v1/models exposed → FAIL
def test_openai_compat_models_exposed_fail():
    s = _make_scanner()
    models_resp = _resp("""{
  "object": "list",
  "data": [
    {"id": "gpt-4o", "object": "model", "created": 1686935002, "owned_by": "openai"},
    {"id": "phi-3-medium", "object": "model", "created": 1686935002, "owned_by": "local"}
  ]
}""")

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "/v1/models" in url:
            return models_resp
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_findings) >= 1
    assert "model" in fail_findings[0]["detail"].lower()


# 5 — Hugging Face TGI /info exposed → FAIL
def test_hf_tgi_info_exposed_fail():
    s = _make_scanner()
    tgi_resp = _resp("""{
  "model_id": "meta-llama/Meta-Llama-3-8B-Instruct",
  "model_sha": "abc123",
  "tokenizer": {"type": "LlamaTokenizer"},
  "max_batch_total_tokens": 32768
}""")

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "/info" in url:
            return tgi_resp
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_findings) >= 1


# 6 — Ollama /api/version exposed → WARN
def test_ollama_version_exposed_warn():
    s = _make_scanner()
    version_resp = _resp('{"version": "0.3.12"}')

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "/api/version" in url:
            return version_resp
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_findings = [r for r in results if r["status"] == "WARN"]
    assert len(warn_findings) >= 1


# 7 — FlowiseAI chatflows exposed → FAIL
def test_flowise_chatflows_exposed_fail():
    s = _make_scanner()
    flowise_resp = _resp("""{
  "chatflows": [
    {"id": "abc123", "name": "Support Bot", "flowData": "{...}", "apikeyid": null}
  ]
}""")

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "/api/v1/chatflows" in url:
            return flowise_resp
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_findings) >= 1


# 8 — LiteLLM /health exposed → WARN
def test_litellm_health_exposed_warn():
    s = _make_scanner()
    health_resp = _resp("""{
  "status": "healthy",
  "healthy_endpoints": ["gpt-4", "claude-3"],
  "unhealthy_endpoints": []
}""")

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "/health" in url:
            return health_resp
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_or_fail = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert len(warn_or_fail) >= 1


# 9 — Root URL is an Ollama API response → FAIL
def test_root_is_ollama_api_fail():
    s = _make_scanner()
    # Some Ollama deployments serve the model list at root
    root_resp = _resp("""{
  "models": [
    {"name": "codellama:13b", "size": 7365960935},
    {"name": "gemma2:9b", "size": 5442873920}
  ]
}""")

    def fake_get(url, **kw):
        if url == "https://llm.internal.example.com":
            return root_resp
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://llm.internal.example.com")

    fail_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_findings) >= 1


# 10 — 404 on all probes → PASS
def test_all_probes_404_pass():
    s = _make_scanner()

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html><body>Hello</body></html>")
        r = MagicMock()
        r.status_code = 404
        r.text = "Not Found"
        r.headers = {}
        return r

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    assert all(r["status"] == "PASS" for r in results)


# 11 — Exception in probe → handled gracefully
def test_exception_in_probe_handled():
    s = _make_scanner()
    call_count = [0]

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        call_count[0] += 1
        raise ConnectionError("refused")

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    assert call_count[0] > 0
    assert any(r["status"] == "PASS" for r in results)


# 12 — Generic AI model names in /api/models → FAIL
def test_generic_model_names_in_api_models_fail():
    s = _make_scanner()
    models_resp = _resp("""{
  "models": [
    {"name": "llama3.1:latest"},
    {"name": "mistral:latest"},
    {"name": "deepseek-coder:7b"}
  ]
}""")

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "/api/models" in url:
            return models_resp
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_findings) >= 1


# 13 — Tabby /v1/health exposed → WARN
def test_tabby_health_exposed_warn():
    s = _make_scanner()
    tabby_resp = _resp("""{
  "device": "cuda",
  "arch": "x86_64",
  "cpu_info": "NVIDIA RTX 4090",
  "model": "TabbyML/DeepseekCoder-6.7B"
}""")

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "/v1/health" in url:
            return tabby_resp
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn_or_fail = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert len(warn_or_fail) >= 1


# 14 — Response body too short (< 5 chars) → not flagged
def test_short_body_not_flagged():
    s = _make_scanner()

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("{}")
        if "/api/tags" in url:
            return _resp("{}")  # 2 chars, too short
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    assert all(r["status"] == "PASS" for r in results)


# 15 — Model names in detail message
def test_model_names_in_detail():
    s = _make_scanner()
    ollama_resp = _resp("""{
  "models": [
    {"name": "llama3.2:latest", "size": 2019393189},
    {"name": "phi3:mini", "size": 2389348515}
  ]
}""")

    def fake_get(url, **kw):
        if url == "https://example.com":
            return _resp("<html></html>")
        if "/api/tags" in url:
            return ollama_resp
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    fail_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_findings) >= 1
    # Model names should appear in the detail
    assert "llama" in fail_findings[0]["detail"].lower() or "phi" in fail_findings[0]["detail"].lower()
