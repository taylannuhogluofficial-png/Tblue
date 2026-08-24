"""
AI/LLM API Endpoint Exposure Scanner.

As teams rapidly adopt local and self-hosted AI models, accidentally exposed
LLM inference endpoints are a growing class of security misconfiguration.

Risk categories:
  1. MODEL THEFT — exposed /v1/models or /api/tags reveals model names,
     allowing competitors to identify which proprietary fine-tuned models
     are deployed.
  2. UNAUTHORIZED INFERENCE — unprotected /api/generate or /v1/chat endpoints
     allow anyone to consume paid API quota or run prompts against the model.
  3. SENSITIVE DATA EXPOSURE — if chat history or context is stored server-side,
     unauthorized access can retrieve prior conversation content.
  4. INFRASTRUCTURE ENUMERATION — model list endpoints reveal backend
     architecture (GPU specs, quantization levels, model versions).
  5. PROMPT INJECTION STAGING — exposed endpoints can be used as relay
     points for indirect prompt injection attacks against downstream systems.

Affected stacks:
  • Ollama (https://ollama.ai) — most popular local LLM runtime
  • LM Studio — desktop LLM runner with OpenAI-compatible API
  • LocalAI — open-source OpenAI drop-in replacement
  • Hugging Face Text Generation Inference (TGI)
  • vLLM — high-throughput LLM serving
  • Xinference — distributed model serving
  • Open WebUI — Ollama front-end that also exposes an API
  • FlowiseAI / Langflow — visual LLM builders with API endpoints
  • Tabby — coding AI completion server
  • LiteLLM — LLM proxy with multi-provider support

CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
CWE-284: Improper Access Control
OWASP LLM Top 10 2025: LLM10 — Unbounded Consumption / Model Theft
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# ── Response validators ───────────────────────────────────────────────────────

# Ollama /api/tags response: {"models": [{"name": "...", "size": ...}]}
_OLLAMA_TAGS_RE = re.compile(
    r'"models"\s*:\s*\[\s*\{[^}]*"name"\s*:',
    re.I,
)
# Ollama /api/version: {"version": "0.x.x"}
_OLLAMA_VERSION_RE = re.compile(r'"version"\s*:\s*"\d+\.\d+', re.I)

# OpenAI-compatible /v1/models response
_OPENAI_MODELS_RE = re.compile(
    r'"object"\s*:\s*"list".*"data"\s*:\s*\[|"data"\s*:\s*\[.*"object"\s*:\s*"model"',
    re.I | re.S,
)

# OpenAI-compatible model entry
_OPENAI_MODEL_ENTRY_RE = re.compile(r'"id"\s*:\s*"[^"]+",\s*"object"\s*:\s*"model"', re.I)

# Hugging Face TGI /info endpoint
_HF_TGI_RE = re.compile(
    r'"model_id"\s*:\s*"[^"]+"|"tokenizer"\s*:\s*\{|"max_batch_total_tokens"',
    re.I,
)

# vLLM /v1/models or health endpoint
_VLLM_RE = re.compile(r'"max_model_len"\s*:|"gpu_memory_utilization"\s*:', re.I)

# FlowiseAI / Langflow indicators
_FLOWISE_RE = re.compile(r'"flowData"\s*:|"apikeyid"\s*:|"chatflow"', re.I)
_LANGFLOW_RE = re.compile(r'"flow_id"\s*:\s*"[0-9a-f-]{36}"|"langflow"', re.I)

# Generic "models" response with names
_GENERIC_MODELS_RE = re.compile(
    r'"models"\s*:\s*\[.*?"name"\s*:\s*"(?:llama|mistral|gpt|phi|gemma|qwen|codellama|'
    r'mixtral|falcon|vicuna|alpaca|wizard|orca|neural|deepseek|tinyllama)[^"]*"',
    re.I | re.S,
)

# LiteLLM /health endpoint
_LITELLM_RE = re.compile(r'"healthy_endpoints"\s*:|"unhealthy_endpoints"\s*:', re.I)

# Xinference /v1/models
_XINFERENCE_RE = re.compile(r'"model_type"\s*:\s*"(?:LLM|embedding|rerank)"', re.I)

# Tabby /v1/health
_TABBY_RE = re.compile(r'"device"\s*:\s*"(?:cuda|cpu|metal)"|"model"\s*:\s*"TabbyML/', re.I)

# ── Probe paths ────────────────────────────────────────────────────────────────

# Each entry: (path, description, validator_pattern, severity)
_PROBES = [
    # Ollama
    ("/api/tags",     "Ollama model list",         _OLLAMA_TAGS_RE,     "FAIL"),
    ("/api/version",  "Ollama version disclosure",  _OLLAMA_VERSION_RE,  "WARN"),
    ("/api/ps",       "Ollama running model list",  _OLLAMA_TAGS_RE,     "FAIL"),

    # OpenAI-compatible (LM Studio, LocalAI, LiteLLM, vLLM, Xinference)
    ("/v1/models",    "OpenAI-compatible model list",  _OPENAI_MODELS_RE,   "FAIL"),
    ("/models",       "Model list endpoint",            _OPENAI_MODELS_RE,   "FAIL"),

    # Hugging Face TGI
    ("/info",         "HF TGI info endpoint",       _HF_TGI_RE,          "FAIL"),

    # vLLM
    ("/v1/models",    "vLLM model list",            _VLLM_RE,            "FAIL"),

    # FlowiseAI
    ("/api/v1/chatflows",   "FlowiseAI chatflows",   _FLOWISE_RE,   "FAIL"),
    ("/api/v1/apikey",      "FlowiseAI API keys",    _FLOWISE_RE,   "FAIL"),

    # LiteLLM
    ("/health",       "LiteLLM health check",       _LITELLM_RE,         "WARN"),

    # Xinference
    ("/v1/models",    "Xinference model list",      _XINFERENCE_RE,      "FAIL"),

    # Tabby
    ("/v1/health",    "Tabby coding AI health",     _TABBY_RE,           "WARN"),

    # Generic LLM model names in model response
    ("/api/models",   "Generic AI model list",      _GENERIC_MODELS_RE,  "FAIL"),
    ("/api/v1/models","Versioned AI model list",    _OPENAI_MODELS_RE,   "FAIL"),
]

# Deduplicated path-to-probes map
_PATH_PROBES: Dict[str, list] = {}
for _path, _desc, _re, _sev in _PROBES:
    if _path not in _PATH_PROBES:
        _PATH_PROBES[_path] = []
    _PATH_PROBES[_path].append((_desc, _re, _sev))


class AIAPIExposureScanner(BaseScanner):
    """Detect exposed AI/LLM API endpoints (Ollama, LM Studio, HF TGI, vLLM, FlowiseAI, etc.)."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "AI API exposure — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        # Also check if the root itself is an Ollama/LLM API
        self._check_response(url, resp.text or "", "Root endpoint")

        for path, probes in _PATH_PROBES.items():
            probe_url = base + path
            try:
                r = self.http.get(probe_url)
                if r is None or r.status_code not in (200, 206):
                    continue
                body = r.text or ""
                if len(body) < 5:
                    continue
                for description, validator, severity in probes:
                    if validator.search(body):
                        self._report_finding(probe_url, description, severity, body)
                        break  # Only report first match per path
            except Exception:
                continue

        if not any(r["status"] in ("FAIL", "WARN") for r in self.results):
            log_pass(logger, f"AI API exposure — no exposed AI/LLM endpoints found on {base}")
            self.results.append(self._result(
                url,
                "AI API exposure — no exposed AI/LLM API endpoints found",
                "PASS",
                detail=(
                    "Probed common Ollama, LM Studio, LocalAI, HF TGI, vLLM, FlowiseAI, "
                    "Tabby, LiteLLM, and Xinference endpoints. "
                    "No publicly accessible AI inference API detected. "
                    "Fix: bind AI APIs to localhost only, require authentication, "
                    "and place them behind a reverse proxy with access controls."
                )
            ))

        return self.results

    def _check_response(self, url: str, body: str, context: str) -> None:
        """Check a response body against all validators."""
        if not body or len(body) < 5:
            return
        validators = [
            (_OLLAMA_TAGS_RE,    "Ollama model list",          "FAIL"),
            (_OLLAMA_VERSION_RE, "Ollama version disclosure",   "WARN"),
            (_OPENAI_MODELS_RE,  "OpenAI-compatible model list","FAIL"),
            (_HF_TGI_RE,         "HF TGI info endpoint",       "FAIL"),
            (_VLLM_RE,           "vLLM configuration",         "WARN"),
            (_LITELLM_RE,        "LiteLLM health endpoint",    "WARN"),
            (_GENERIC_MODELS_RE, "AI model list",              "FAIL"),
        ]
        for pattern, description, severity in validators:
            if pattern.search(body):
                self._report_finding(url, f"{context} — {description}", severity, body)
                break

    def _report_finding(self, url: str, description: str, severity: str, body: str) -> None:
        # Extract model names for the detail message
        model_names = re.findall(r'"(?:name|id)"\s*:\s*"([^"]{3,60})"', body[:1500])
        models_preview = ", ".join(model_names[:5]) if model_names else "(see response body)"

        log_fail(logger, f"AI API exposure: {description} at {url}") if severity == "FAIL" \
            else log_warn(logger, f"AI API exposure: {description} at {url}")

        self.results.append(self._result(
            url,
            f"AI API exposure — {description} accessible without authentication",
            severity,
            detail=(
                f"An AI/LLM API endpoint is publicly accessible at {url}: {description}. "
                f"Models/info found: {models_preview}. "
                "Exposed AI APIs allow unauthorized users to: enumerate deployed models "
                "(intellectual property), consume inference quota, access conversation history, "
                "and use the endpoint as a relay for prompt injection attacks. "
                "Fix: bind the AI server to 127.0.0.1 (not 0.0.0.0); add API key authentication; "
                "place behind a reverse proxy (nginx/traefik) with allowlist IP controls. "
                "CWE-200, CWE-284. OWASP LLM Top 10: LLM10 (Unbounded Consumption)."
            ),
        ))
