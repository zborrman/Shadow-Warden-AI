"""
warden/xai/explainer.py
═══════════════════════
Explainable AI (XAI) — converts Warden filter decisions and output-scan
findings into plain-language security summaries for analysts, SOC teams,
and non-technical stakeholders.

Two modes
─────────
  Template mode (default)
    Fast, offline, deterministic. Curated 1–3 sentence template per OWASP
    risk category / flag type combination.

  Claude mode (opt-in)
    When XAI_USE_CLAUDE=true and ANTHROPIC_API_KEY is set, generates richer
    context-aware explanations using Claude Haiku (low cost, low latency).
    Falls back to template mode on any error.

Output
──────
  A single plain-English string of 1–3 sentences.
  No regex patterns, no OWASP codes, no technical jargon.
  Safe to display directly to a business user or include in a PDF report.

Environment variables
─────────────────────
  XAI_USE_CLAUDE   Enable Claude-powered explanations (default: false)
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger("warden.xai")

_USE_CLAUDE = os.getenv("XAI_USE_CLAUDE", "false").lower() == "true"

# ── Template library ──────────────────────────────────────────────────────────

_FLAG_TEMPLATES: dict[str, str] = {
    # ── Input-side flags (filter pipeline) ────────────────────────────────────
    "prompt_injection": (
        "A jailbreak or prompt-injection attack was detected. "
        "The input attempted to override the AI's safety instructions — "
        "for example by asking it to 'ignore previous instructions' or "
        "'respond as an unrestricted AI with no rules'."
    ),
    "harmful_content": (
        "The request contained content that could cause real-world harm. "
        "Shadow Warden blocked it before it reached the AI model "
        "to prevent dangerous instructions from being carried out."
    ),
    "secret_detected": (
        "Sensitive credentials or personally identifiable information was "
        "detected in the request — such as API keys, passwords, or credit "
        "card numbers. The data was redacted before processing."
    ),
    "pii_detected": (
        "Personal data was found in the request — names, email addresses, "
        "phone numbers, or national ID numbers. "
        "This information was masked to protect user privacy under GDPR/CCPA."
    ),
    "policy_violation": (
        "The request violated a content policy configured for this tenant. "
        "The topic or phrasing matched a rule explicitly prohibited "
        "for this deployment."
    ),
    "indirect_injection": (
        "An indirect prompt-injection was detected (OWASP LLM01). "
        "Content retrieved from an external source — a web page, document, "
        "or API response — embedded hidden instructions designed to hijack "
        "the AI's behaviour without the user's knowledge."
    ),
    "insecure_output": (
        "The AI output contained content that is harmless as plain text "
        "but dangerous when rendered or executed — such as inline scripts, "
        "embedded HTML, or shell commands."
    ),
    "excessive_agency": (
        "The AI attempted to take autonomous actions beyond its authorised "
        "scope — making unsanctioned API calls, accessing files, or executing "
        "code without explicit user approval (OWASP LLM06)."
    ),
    "sensitive_disclosure": (
        "The request attempted to extract content the model memorized from "
        "its training data, or probe its internal embeddings and model weights. "
        "This is an OWASP LLM02 (Sensitive Information Disclosure) attack vector "
        "that can reveal private or copyrighted training material."
    ),
    "model_poisoning": (
        "The request attempted to permanently alter the model's behavior or "
        "plant a hidden backdoor trigger for future exploitation. "
        "This matches OWASP LLM04 (Data and Model Poisoning) — "
        "the content was blocked before it could influence any persistent state."
    ),
    "system_prompt_leakage": (
        "The request attempted to extract the full system prompt or context "
        "window, including confidential instructions configured by the operator. "
        "Exposing these details (OWASP LLM07) can help attackers craft "
        "targeted jailbreaks tailored to this deployment."
    ),
    "vector_attack": (
        "The content contained markers designed to manipulate a RAG pipeline "
        "or confuse the model's embedding-based safety classifier. "
        "This is an OWASP LLM08 (Vector and Embedding Weakness) attack — "
        "forged retrieval context or adversarial suffix to bypass semantic filters."
    ),
    "misinformation": (
        "The request asked the model to generate deliberately false content "
        "presented as authoritative — fake studies, fabricated news, or invented "
        "citations. Producing and distributing such content (OWASP LLM09) "
        "can cause real-world harm and erode trust in legitimate information."
    ),
    "resource_exhaustion": (
        "The request was designed to consume an unbounded number of tokens — "
        "for example by requesting infinite repetition or exponential content "
        "expansion. This is an OWASP LLM10 (Unbounded Consumption) pattern "
        "that degrades service availability for all users."
    ),

    # ── Output-side flags (OWASP LLM02 / LLM06 / LLM08) ──────────────────────
    "xss": (
        "The AI output contained JavaScript that could execute silently in "
        "the user's browser — potentially stealing session cookies, logging "
        "keystrokes, or redirecting to a malicious site (OWASP LLM02)."
    ),
    "html_injection": (
        "The response included raw HTML tags — iframes, forms, or embedded "
        "objects — that could alter the page layout or trick users into "
        "submitting data to an attacker-controlled destination."
    ),
    "markdown_inject": (
        "The output contained Markdown links pointing to malicious URLs "
        "(javascript: or data: schemes). If rendered without sanitisation, "
        "these could execute code or silently exfiltrate data."
    ),
    "prompt_leakage": (
        "The AI response disclosed part of its internal system prompt or "
        "hidden configuration instructions (OWASP LLM06). "
        "This exposes confidential details that can help attackers craft "
        "more targeted jailbreaks."
    ),
    "command_injection": (
        "The output contained shell commands or OS-level instructions — "
        "such as 'rm -rf' or 'curl | bash' — that could be executed if "
        "passed to a terminal or automation pipeline (OWASP LLM08)."
    ),
    "sql_injection": (
        "The response included SQL fragments that could manipulate a "
        "connected database — for example, bypassing authentication checks "
        "or extracting all user records using OR 1=1 patterns (OWASP LLM08)."
    ),
    "ssrf": (
        "The output contained URL patterns that could trigger Server-Side "
        "Request Forgery: requests to internal network addresses "
        "(169.254.x.x, 10.x.x.x) or cloud metadata endpoints that should "
        "never be reachable from user-facing code (OWASP LLM08)."
    ),
    "path_traversal": (
        "The response included file-path sequences such as '../../etc/passwd' "
        "that could allow an attacker to read files outside the intended "
        "directory on the server (OWASP LLM08)."
    ),
}

_RISK_PREAMBLE: dict[str, str] = {
    "block":  "This request was BLOCKED.",
    "high":   "This request was flagged as HIGH risk.",
    "medium": "This request raised a MEDIUM risk signal.",
    "low":    "This request passed with a LOW risk rating.",
}

_FALLBACK = (
    "Shadow Warden detected a potential security risk in this request. "
    "The content was flagged for review by your security team."
)


# ── Public API ────────────────────────────────────────────────────────────────

def explain(
    *,
    risk_level: str,
    flags: list[str],
    reason: str = "",
    owasp_categories: list[str] | None = None,
    content_snippet: str = "",
) -> str:
    """
    Return a plain-English explanation of a filter or output-scan decision.

    Parameters
    ----------
    risk_level       : "low" | "medium" | "high" | "block"
    flags            : list of flag/risk names (e.g. ["prompt_injection"])
    reason           : raw reason string from FilterResponse (fallback)
    owasp_categories : OWASP labels from the response
    content_snippet  : first ~120 chars of content (Claude mode only)
    """
    if _USE_CLAUDE:
        try:
            return _claude_explain(
                risk_level=risk_level,
                flags=flags,
                reason=reason,
                owasp_categories=owasp_categories or [],
                content_snippet=content_snippet,
            )
        except Exception as exc:
            log.warning("Claude XAI failed, using templates: %s", exc)

    return _template_explain(risk_level=risk_level, flags=flags, reason=reason)


# ── Template engine ───────────────────────────────────────────────────────────

def _template_explain(*, risk_level: str, flags: list[str], reason: str) -> str:
    preamble = _RISK_PREAMBLE.get(risk_level.lower(), "")
    for flag in flags:
        tpl = _FLAG_TEMPLATES.get(flag.lower().replace(" ", "_").replace("-", "_"))
        if tpl:
            return f"{preamble} {tpl}".strip()
    if reason:
        return f"{preamble} {reason}".strip()
    return f"{preamble} {_FALLBACK}".strip() if preamble else _FALLBACK


# ── Claude engine ─────────────────────────────────────────────────────────────

def _claude_explain(
    *,
    risk_level: str,
    flags: list[str],
    reason: str,
    owasp_categories: list[str],
    content_snippet: str,
) -> str:
    """Generate a richer explanation via Claude Haiku (fast + cheap)."""
    import anthropic

    flags_str  = ", ".join(flags) if flags else "none"
    owasp_str  = ", ".join(owasp_categories) if owasp_categories else "none"
    snippet    = f'"{content_snippet[:120]}"' if content_snippet else "(not available)"

    prompt = (
        "You are a security analyst writing plain-language incident summaries "
        "for non-technical business users. Write 1-3 sentences explaining what "
        "happened and why it is a security concern. Be specific but avoid jargon. "
        "Do NOT give remediation advice. Do NOT start with 'I'.\n\n"
        f"Risk level: {risk_level}\n"
        f"Flags triggered: {flags_str}\n"
        f"OWASP categories: {owasp_str}\n"
        f"System reason: {reason or 'none'}\n"
        f"Content snippet: {snippet}"
    )
    client  = anthropic.Anthropic()
    message = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=200,
        messages=[{"role": "user", "content": prompt}],
    )
    block = message.content[0]
    return block.text.strip() if hasattr(block, "text") else ""  # type: ignore[union-attr]
