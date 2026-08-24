"""Tests for ai_analysis module — mocks Anthropic SDK."""
from unittest.mock import MagicMock, patch


def _sample_results():
    return {
        "cors": [{"status": "FAIL", "type": "CORS — wildcard origin", "detail": "Access-Control-Allow-Origin: *"}],
        "csp": [{"status": "WARN", "type": "CSP — missing script-src", "detail": "No script-src directive"}],
        "ssl": [{"status": "PASS", "type": "SSL — HTTPS enabled", "detail": "TLS 1.3"}],
        "jwt": [{"status": "FAIL", "type": "JWT — alg:none accepted", "detail": "Server accepted unsigned token"}],
    }


# ── SDK not available ─────────────────────────────────────────────────────────

def test_returns_none_if_sdk_missing():
    """Returns None gracefully when anthropic SDK not installed."""
    from tblue.ai_analysis import analyze_with_ai
    with patch("tblue.ai_analysis._sdk_available", return_value=False):
        result = analyze_with_ai(_sample_results(), "https://example.com", api_key="sk-ant-test")
    assert result is None


def test_returns_none_if_no_api_key():
    """Returns None gracefully when no API key provided."""
    from tblue.ai_analysis import analyze_with_ai
    with patch("tblue.ai_analysis._sdk_available", return_value=True):
        result = analyze_with_ai(_sample_results(), "https://example.com", api_key=None)
    assert result is None


def test_returns_none_if_no_findings():
    """Returns None when all results are PASS (nothing to analyze)."""
    from tblue.ai_analysis import analyze_with_ai
    all_pass = {"ssl": [{"status": "PASS", "type": "SSL OK", "detail": ""}]}
    with patch("tblue.ai_analysis._sdk_available", return_value=True):
        result = analyze_with_ai(all_pass, "https://example.com", api_key="sk-ant-test")
    assert result is None


# ── Successful analysis (mocked SDK) ─────────────────────────────────────────

def _mock_anthropic(response_text: str):
    """Build a mock anthropic module that returns the given text."""
    mock_content = MagicMock()
    mock_content.text = response_text

    mock_message = MagicMock()
    mock_message.content = [mock_content]

    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_message

    mock_anthropic = MagicMock()
    mock_anthropic.Anthropic.return_value = mock_client
    return mock_anthropic


def test_successful_analysis_returns_dict():
    """Mocked SDK call returns structured analysis dict."""
    from tblue.ai_analysis import analyze_with_ai

    fake_response = "## 1. ATTACK CHAIN ANALYSIS\n- Name: JWT + CORS = Account Takeover\n## 2. BUSINESS IMPACT\nCritical."

    with patch("tblue.ai_analysis._sdk_available", return_value=True):
        with patch.dict("sys.modules", {"anthropic": _mock_anthropic(fake_response)}):
            result = analyze_with_ai(
                _sample_results(), "https://example.com",
                api_key="sk-ant-test", model="claude-sonnet-4-6"
            )

    assert result is not None
    assert "raw_text" in result
    assert result["raw_text"] == fake_response
    assert "finding_count" in result
    assert result["finding_count"] == 3  # 2 FAIL + 1 WARN (not PASS)
    assert result["model"] == "claude-sonnet-4-6"


def test_sdk_exception_returns_none():
    """If the SDK raises, analysis returns None without crashing."""
    from tblue.ai_analysis import analyze_with_ai

    mock_anthropic = MagicMock()
    mock_anthropic.Anthropic.side_effect = Exception("API error")

    with patch("tblue.ai_analysis._sdk_available", return_value=True):
        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            result = analyze_with_ai(_sample_results(), "https://example.com", api_key="sk-ant-test")

    assert result is None


# ── Trim results ──────────────────────────────────────────────────────────────

def test_trim_results_excludes_pass():
    """_trim_results only includes FAIL and WARN findings."""
    from tblue.ai_analysis import _trim_results
    results = {
        "ssl": [{"status": "PASS", "type": "SSL OK", "detail": ""}],
        "cors": [{"status": "FAIL", "type": "CORS wildcard", "detail": "bad"}],
        "csp": [{"status": "WARN", "type": "CSP weak", "detail": "weak"}],
    }
    trimmed = _trim_results(results)
    statuses = {r["status"] for r in trimmed}
    assert "PASS" not in statuses
    assert "FAIL" in statuses
    assert "WARN" in statuses


def test_trim_results_fails_first():
    """_trim_results orders FAILs before WARNs."""
    from tblue.ai_analysis import _trim_results
    results = {
        "a": [{"status": "WARN", "type": "a", "detail": ""}],
        "b": [{"status": "FAIL", "type": "b", "detail": ""}],
    }
    trimmed = _trim_results(results)
    assert trimmed[0]["status"] == "FAIL"


# ── Format functions ──────────────────────────────────────────────────────────

def test_format_terminal_returns_string():
    """format_ai_analysis_terminal produces a non-empty string."""
    from tblue.ai_analysis import format_ai_analysis_terminal
    analysis = {"raw_text": "Attack chains found.", "finding_count": 3, "model": "claude-opus-4-8", "tech_stack": "nginx"}
    output = format_ai_analysis_terminal(analysis)
    assert isinstance(output, str)
    assert "AI" in output
    assert "Attack chains found." in output


def test_format_terminal_empty_on_none():
    """format_ai_analysis_terminal returns empty string for None."""
    from tblue.ai_analysis import format_ai_analysis_terminal
    assert format_ai_analysis_terminal(None) == ""


def test_format_html_returns_string():
    """format_ai_analysis_html produces an HTML div."""
    from tblue.ai_analysis import format_ai_analysis_html
    analysis = {"raw_text": "## 1. ATTACK CHAIN\nSome findings.", "finding_count": 2, "model": "claude-opus-4-8", "tech_stack": "Django"}
    html = format_ai_analysis_html(analysis)
    assert "ai-analysis-section" in html
    assert "ATTACK CHAIN" in html


def test_format_html_escapes_content():
    """format_ai_analysis_html HTML-escapes the raw text."""
    from tblue.ai_analysis import format_ai_analysis_html
    analysis = {"raw_text": "<script>alert(1)</script>", "finding_count": 1, "model": "m", "tech_stack": ""}
    html = format_ai_analysis_html(analysis)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
