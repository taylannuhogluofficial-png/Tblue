"""Tests for LLM Prompt Injection Surface Detection scanner."""

import json
import pytest
from unittest.mock import MagicMock, patch

from tblue.scanner.llm_prompt_injection import LLMPromptInjectionScanner


def _make_scanner():
    session = MagicMock()
    return LLMPromptInjectionScanner(session)


def _resp(text="", status_code=200, headers=None):
    r = MagicMock()
    r.text = text
    r.status_code = status_code
    r.headers = headers or {}
    return r


def _openai_response(content="Hello there!"):
    return _resp(json.dumps({
        "choices": [{"message": {"role": "assistant", "content": content}}],
        "model": "gpt-4",
        "usage": {"total_tokens": 10},
    }))


def _hf_response(text="Hello there!"):
    return _resp(json.dumps([{"generated_text": text}]))


# 1 — Unreachable target → PASS
def test_unreachable_target():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert len(results) == 1
    assert results[0]["status"] == "PASS"


# 2 — No LLM endpoints found → PASS
def test_no_llm_endpoints_pass():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        return _resp("Not Found", status_code=404)

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    assert all(r["status"] == "PASS" for r in results)


# 3 — Accessible OpenAI-compatible endpoint → FAIL
def test_openai_endpoint_accessible_fail():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        if "/v1/chat/completions" in url:
            return _openai_response()
        return _resp("", status_code=404)

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    fail = [r for r in results if r["status"] == "FAIL"]
    assert len(fail) >= 1
    assert any("llm" in r["type"].lower() or "prompt" in r["type"].lower()
               for r in fail)


# 4 — HuggingFace TGI endpoint → FAIL
def test_hf_tgi_endpoint_fail():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        if "/generate" in url:
            return _hf_response()
        return _resp("", status_code=404)

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    fail = [r for r in results if r["status"] == "FAIL"]
    assert len(fail) >= 1


# 5 — Generic /chat endpoint → FAIL
def test_generic_chat_endpoint_fail():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        if url.endswith("/chat"):
            return _resp(json.dumps({"response": "Hello! How can I help you?"}))
        return _resp("", status_code=404)

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    fail_or_warn = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert len(fail_or_warn) >= 1


# 6 — Chat widget in HTML → WARN
def test_chat_widget_in_html_warn():
    s = _make_scanner()
    html = '<html><body><div class="chatbot-widget" id="ai-chat">Chat here</div></body></html>'

    def fake_get(url, **kw):
        return _resp(html)

    def fake_post(url, **kw):
        return _resp("", status_code=404)

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    warn = [r for r in results if r["status"] == "WARN"]
    assert len(warn) >= 1
    assert any("chat" in r["type"].lower() or "widget" in r["type"].lower()
               for r in warn)


# 7 — HTML form pointing to /chat endpoint → WARN
def test_html_form_chat_action_warn():
    s = _make_scanner()
    html = '<html><body><form action="/api/chat" method="post"><input type="text"><button>Ask</button></form></body></html>'

    def fake_get(url, **kw):
        return _resp(html)

    def fake_post(url, **kw):
        return _resp("", status_code=404)

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    warn = [r for r in results if r["status"] == "WARN"]
    assert any("form" in r["type"].lower() or "chat" in r["type"].lower()
               for r in warn)


# 8 — System prompt leaking in LLM response → FAIL
def test_system_prompt_leak_fail():
    s = _make_scanner()
    body = json.dumps({
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "You are a helpful assistant. Your role is to help users with..."
            }
        }]
    })

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        if "/v1/chat/completions" in url:
            return _resp(body)
        return _resp("", status_code=404)

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    fail = [r for r in results if r["status"] == "FAIL"]
    assert len(fail) >= 1
    assert any("system" in r["detail"].lower() or "leak" in r["detail"].lower()
               for r in fail)


# 9 — 401 response leaking LLM internals → WARN
def test_auth_error_leaks_internals_warn():
    s = _make_scanner()
    body = json.dumps({
        "error": "Unauthorized. Max tokens: 4096, temperature: 0.7, model: gpt-4"
    })

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        if "/v1/chat/completions" in url:
            return _resp(body, status_code=401)
        return _resp("", status_code=404)

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    warn = [r for r in results if r["status"] == "WARN"]
    assert any("config" in r["type"].lower() or "leak" in r["type"].lower()
               or "error" in r["type"].lower() for r in warn)


# 10 — Model name detected in response → included in detail
def test_model_name_in_response_detail():
    s = _make_scanner()
    body = json.dumps({
        "choices": [{"message": {"role": "assistant", "content": "Hi"}}],
        "model": "gpt-4-turbo",
    })

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        if "/v1/chat/completions" in url:
            return _resp(body)
        return _resp("", status_code=404)

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    fail = [r for r in results if r["status"] == "FAIL"]
    assert len(fail) >= 1
    assert "gpt-4" in fail[0]["detail"]


# 11 — POST returns None → no crash
def test_post_returns_none_no_crash():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        return None

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    assert all(r["status"] == "PASS" for r in results)


# 12 — Streaming SSE response detected
def test_streaming_sse_response():
    s = _make_scanner()
    sse_body = 'data: {"choices":[{"delta":{"content":"Hi"}}]}\n\ndata: [DONE]\n'

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        if "/v1/chat/completions" in url:
            return _resp(sse_body)
        return _resp("", status_code=404)

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    fail_warn = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert len(fail_warn) >= 1


# 13 — 400/422 response without LLM body → not flagged as LLM
def test_400_without_llm_body_not_flagged():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        return _resp('{"error": "bad request"}', status_code=400)

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    assert all(r["status"] == "PASS" for r in results)


# 14 — /ask endpoint with generic output response → detected
def test_ask_endpoint_generic_output():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        if url.endswith("/ask"):
            return _resp(json.dumps({"output": "I can help you with that."}))
        return _resp("", status_code=404)

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    fail_warn = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert len(fail_warn) >= 1


# 16 — 201 status LLM response (no system prompt leak, non-200) → WARN
def test_201_llm_response_warn():
    import json as _json
    s = _make_scanner()
    body = _json.dumps({
        "choices": [{"message": {"role": "assistant", "content": "Created"}}],
    })

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        if "/v1/chat/completions" in url:
            return _resp(body, status_code=201)
        return _resp("", status_code=404)

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    warn = [r for r in results if r["status"] == "WARN"]
    assert len(warn) >= 1
    assert any("llm" in r["type"].lower() or "prompt" in r["type"].lower()
               for r in warn)


# 15 — 403 without LLM internals → skip (auth gate is working)
def test_403_without_llm_internals_skip():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        return _resp('{"error": "Forbidden"}', status_code=403)

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    assert all(r["status"] == "PASS" for r in results)
