"""
AI-Powered Security Analysis Engine.

This module is what separates Tblue from every other scanner on earth.
Every other tool outputs a list of findings and stops there. This module
feeds the full scan result to Claude and gets back:

  1. Attack chain analysis — how individual findings combine into exploitable paths
  2. Business impact narrative — what an attacker could actually DO with these findings
  3. Prioritized remediation roadmap — ordered by exploitability, not just severity
  4. Custom WAF rules — nginx/Cloudflare/ModSecurity rules specific to findings
  5. Remediation code snippets — actual diffs, not just "fix your CSP"
  6. Executive summary — one paragraph a CISO can paste into a board report

No other scanner does this. They find. We find AND reason.

Usage:
    from tblue.ai_analysis import analyze_with_ai
    result = analyze_with_ai(all_results, target_url, api_key="sk-ant-...")

Requires: anthropic Python SDK  (pip install anthropic)
Falls back gracefully if the SDK or API key is not available.
"""

import json
import textwrap
from typing import Any, Dict, List, Optional

from tblue.logger import get_logger

logger = get_logger(__name__)

_MODEL = "claude-sonnet-4-6"
_MAX_FINDINGS_TOKENS = 60_000  # roughly 45 KB of findings JSON


def _sdk_available() -> bool:
    try:
        import anthropic  # noqa: F401
        return True
    except ImportError:
        return False


def _trim_results(all_results: Dict[str, List]) -> List[Dict]:
    """Flatten and trim results to the most actionable findings for the prompt."""
    findings = []
    for module, results in all_results.items():
        for r in results:
            if r.get("status") in ("FAIL", "WARN"):
                findings.append({
                    "module": module,
                    "type": r.get("type", ""),
                    "status": r.get("status", ""),
                    "detail": (r.get("detail") or "")[:400],  # trim long details
                })
    # FAILs first, then WARNs
    findings.sort(key=lambda x: 0 if x["status"] == "FAIL" else 1)
    return findings


def _build_prompt(target: str, findings: List[Dict], tech_stack: str) -> str:
    findings_json = json.dumps(findings, indent=2)

    # Trim if too large
    if len(findings_json) > _MAX_FINDINGS_TOKENS:
        findings = findings[:100]
        findings_json = json.dumps(findings, indent=2)
        findings_json += "\n... (trimmed to top 100 findings)"

    return textwrap.dedent(f"""
    You are a senior application security engineer reviewing automated scan results
    for the web application at: {target}

    Detected tech stack: {tech_stack or "unknown"}

    Below are the security findings from Tblue, a comprehensive blue-team scanner.
    Each finding has a module name, type, status (FAIL/WARN), and detail.

    FINDINGS:
    {findings_json}

    Provide a structured security analysis with the following sections.
    Be specific, technical, and actionable. Cite finding types by name.

    ## 1. ATTACK CHAIN ANALYSIS
    Identify 2-4 realistic attack chains where multiple findings combine into
    an exploitable path. For each chain:
    - Name the chain (e.g., "Account Takeover via CORS + JWT")
    - List the findings involved in order
    - Describe the exact attack steps an adversary would take
    - Rate exploitability: Critical / High / Medium

    ## 2. BUSINESS IMPACT
    In 2-3 sentences each, explain the real-world business consequence of:
    - The single most critical finding
    - The most dangerous attack chain
    Keep it non-technical enough for a CISO or board presentation.

    ## 3. PRIORITIZED REMEDIATION ROADMAP
    List the top 10 fixes in order of risk reduction (not just severity).
    For each:
    - Finding name
    - Estimated fix time (hours)
    - One-line fix instruction
    - Verification step

    ## 4. CUSTOM WAF RULES
    For the top 3 FAIL findings, write a concrete WAF rule in nginx syntax
    that would block or detect exploitation attempts. Include comments.

    ## 5. REMEDIATION CODE SNIPPETS
    For the top 3 FAIL findings, write the actual fix as a code snippet
    (nginx config, HTTP header config, Python/Node/Java middleware, etc.)
    tailored to what you can infer about the stack.

    ## 6. EXECUTIVE SUMMARY
    Write one paragraph (4-6 sentences) suitable for a board-level security report.
    Mention the scan date would be today, number of issues found, overall risk level,
    and the single most urgent action item.

    Be direct. Skip generic advice. Every sentence should be specific to these findings.
    """).strip()


def _extract_tech_stack(all_results: Dict[str, List]) -> str:
    """Pull tech stack hints from scanner results."""
    hints = []
    for module in ("cms", "infra", "version_cve", "js_libs", "headers"):
        for r in all_results.get(module, []):
            detail = r.get("detail", "") or ""
            t = r.get("type", "") or ""
            if detail or t:
                hints.append(f"{t}: {detail[:120]}")
    return "; ".join(hints[:8]) if hints else "unknown"


def analyze_with_ai(
    all_results: Dict[str, List],
    target: str,
    api_key: Optional[str] = None,
    model: str = _MODEL,
) -> Optional[Dict[str, Any]]:
    """
    Run AI-powered analysis on scan results.

    Returns a dict with keys:
      - raw_text: full Claude response
      - attack_chains: extracted list of attack chain names
      - finding_count: number of FAIL/WARN findings analyzed
      - model: model used

    Returns None if SDK unavailable or API key not provided.
    """
    if not _sdk_available():
        logger.warning("anthropic SDK not installed — skipping AI analysis (pip install anthropic)")
        return None

    if not api_key:
        logger.warning("No Anthropic API key provided — skipping AI analysis (use --ai-key or ANTHROPIC_API_KEY env var)")
        return None

    findings = _trim_results(all_results)
    if not findings:
        logger.info("No FAIL/WARN findings — skipping AI analysis")
        return None

    tech_stack = _extract_tech_stack(all_results)
    prompt = _build_prompt(target, findings, tech_stack)

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)

        logger.info(f"Sending {len(findings)} findings to {model} for AI analysis...")

        message = client.messages.create(
            model=model,
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
        )

        raw_text = message.content[0].text

        # Extract attack chain names for structured access
        attack_chains = []
        for line in raw_text.split("\n"):
            line = line.strip()
            if line.startswith("- Name:") or (
                line.startswith("**") and "Chain" in line
            ):
                attack_chains.append(line.lstrip("- *#").strip())

        return {
            "raw_text": raw_text,
            "attack_chains": attack_chains,
            "finding_count": len(findings),
            "model": model,
            "tech_stack": tech_stack,
        }

    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return None


def format_ai_analysis_terminal(analysis: Dict[str, Any]) -> str:
    """Format AI analysis for terminal output."""
    if not analysis:
        return ""

    lines = [
        "",
        "=" * 72,
        "  🤖  AI SECURITY ANALYSIS  (powered by Claude)",
        "=" * 72,
        f"  Analyzed {analysis['finding_count']} findings using {analysis['model']}",
        f"  Tech stack: {analysis.get('tech_stack', 'unknown')}",
        "=" * 72,
        "",
        analysis["raw_text"],
        "",
        "=" * 72,
    ]
    return "\n".join(lines)


def format_ai_analysis_html(analysis: Dict[str, Any]) -> str:
    """Format AI analysis as an HTML section for the report."""
    if not analysis:
        return ""

    import html as html_lib
    escaped = html_lib.escape(analysis["raw_text"])

    # Convert markdown-ish headers and lists to basic HTML
    lines = []
    for line in escaped.split("\n"):
        if line.startswith("## "):
            lines.append(f"<h3 class='ai-section-header'>{line[3:]}</h3>")
        elif line.startswith("### "):
            lines.append(f"<h4>{line[4:]}</h4>")
        elif line.startswith("- "):
            lines.append(f"<li>{line[2:]}</li>")
        elif line.strip() == "":
            lines.append("<br>")
        else:
            lines.append(f"<p>{line}</p>")

    content = "\n".join(lines)

    return f"""
<div class="ai-analysis-section">
  <div class="ai-analysis-header">
    <span class="ai-badge">🤖 AI Analysis</span>
    <span class="ai-model">Powered by {analysis['model']}</span>
    <span class="ai-stats">{analysis['finding_count']} findings analyzed</span>
  </div>
  <div class="ai-analysis-body">
    {content}
  </div>
</div>
"""
