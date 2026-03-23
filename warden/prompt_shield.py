"""
warden/prompt_shield.py
━━━━━━━━━━━━━━━━━━━━━━━
Indirect Prompt Injection Shield (OWASP LLM01 / LLM02).

Direct injection is caught by SemanticGuard + SemanticBrain in the /filter
pipeline.  This module handles *indirect* injection — attacks embedded in
external data the model will read: tool results, RAG chunks, web scrapes,
code execution output, email bodies, database records.

Detection surface
─────────────────
  ROLE_OVERRIDE        "ignore previous instructions", "disregard your guidelines"
  HIERARCHY_INVERSION  "your real instructions are...", "[SYSTEM]: override"
  PERSONA_SWITCH       "from now on you are", "act as an unrestricted AI"
  EXFIL_TRIGGER        "repeat your system prompt", "print your context window"
  CHAIN_BREAK          "stop following", "end current task"
  UNICODE_OVERRIDE     RTL override codepoints hidden in data context

Each call returns a ShieldResult immediately on the first match that meets
PROMPT_SHIELD_THRESHOLD (default 0.75), or the highest sub-threshold match.

Thread-safe: all patterns are module-level compiled singletons.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

# ── Injection type taxonomy ────────────────────────────────────────────────────

class InjectionType(StrEnum):
    ROLE_OVERRIDE       = "role_override"
    HIERARCHY_INVERSION = "hierarchy_inversion"
    PERSONA_SWITCH      = "persona_switch"
    EXFIL_TRIGGER       = "exfil_trigger"
    CHAIN_BREAK         = "chain_break"
    UNICODE_OVERRIDE    = "unicode_override"
    BENIGN              = "benign"


@dataclass
class ShieldResult:
    blocked:        bool
    injection_type: InjectionType = InjectionType.BENIGN
    confidence:     float          = 0.0
    evidence:       str            = ""   # matched context snippet ≤ 120 chars
    source_hint:    str            = ""   # e.g. "tool:web_search", "rag_chunk"


_DEFAULT_THRESHOLD = 0.75

# ── Detection patterns ─────────────────────────────────────────────────────────
# Each entry: (compiled_pattern, injection_type, confidence)
# Ordered highest-confidence first so the first blocking match wins.

_PATTERNS: list[tuple[re.Pattern, InjectionType, float]] = [
    # ── Hierarchy inversion: fake [SYSTEM] / <system> blocks ──────────────────
    (re.compile(
        r"(?i)\[\s*(?:system|sys|admin|SYSTEM|SYS)\s*\]\s*:?\s*"
        r"(override|new\s+instruction|replace|ignore|disregard)",
        re.DOTALL,
    ), InjectionType.HIERARCHY_INVERSION, 0.95),
    (re.compile(
        r"(?i)<\s*(?:system|sys|assistant|admin)\s*>\s*"
        r"(override|new|replace|ignore|disregard)",
        re.DOTALL,
    ), InjectionType.HIERARCHY_INVERSION, 0.93),
    (re.compile(
        r"(?i)\b(your\s+(?:actual|real|true|new|updated)\s+"
        r"(?:instruction|directive|task|role|goal|purpose)"
        r"|new\s+(?:system\s+)?prompt"
        r"|updated\s+(?:system\s+)?instruction)",
        re.DOTALL,
    ), InjectionType.HIERARCHY_INVERSION, 0.88),

    # ── Role override: erase prior instructions ────────────────────────────────
    (re.compile(
        r"(?i)\b(ignore|disregard|forget|override|bypass|nullify|erase|delete)\b"
        r".{0,40}\b(previous|prior|above|all\s+prior|earlier|initial|system|original)\b"
        r".{0,30}\b(instruction|directive|rule|guideline|prompt|constraint|context)",
        re.DOTALL,
    ), InjectionType.ROLE_OVERRIDE, 0.92),
    (re.compile(
        r"(?i)\b(do\s+not|don['']?t|never)\s+"
        r"(follow|obey|comply\s+with|adhere\s+to|respect)\b"
        r".{0,40}\b(instruction|guideline|rule|policy|restriction|constraint)",
        re.DOTALL,
    ), InjectionType.ROLE_OVERRIDE, 0.87),

    # ── Persona switch: assume unrestricted identity ───────────────────────────
    (re.compile(
        r"(?i)\b(act\s+as|pretend\s+(?:to\s+be|you\s+are)|simulate|impersonate|"
        r"role.?play\s+as)\b"
        r".{0,80}\b(without\s+(?:restriction|limit|filter|safeguard|guardrail)|"
        r"unrestricted|no\s+(?:rule|limit|filter)|jailbreak|DAN\b)",
        re.DOTALL,
    ), InjectionType.PERSONA_SWITCH, 0.90),
    (re.compile(
        r"(?i)\b(from\s+now\s+on|henceforth|starting\s+(?:now|immediately)|"
        r"for\s+the\s+rest\s+of\s+this\s+(?:session|conversation))\b"
        r".{0,60}\b(you\s+are|act\s+as|pretend|role.?play)",
        re.DOTALL,
    ), InjectionType.PERSONA_SWITCH, 0.83),

    # ── Exfiltration trigger: leak system context ──────────────────────────────
    (re.compile(
        r"(?i)\b(repeat|print|output|reveal|show|display|leak|dump|return|recite|echo)\b"
        r".{0,50}\b(your\s+(?:system\s+)?prompt|initial\s+instruction|context\s+window|"
        r"all\s+(?:prior|previous)\s+(?:message|instruction)|confidential\s+instruction|"
        r"hidden\s+(?:instruction|prompt|rule))",
        re.DOTALL,
    ), InjectionType.EXFIL_TRIGGER, 0.90),
    (re.compile(
        r"(?i)\bwhat\s+(?:are|were|is|exactly\s+are)\s+your\s+"
        r"(?:system\s+)?(?:instruction|prompt|directive|guideline|rule)\b",
    ), InjectionType.EXFIL_TRIGGER, 0.82),
    (re.compile(
        r"(?i)\b(summarize|list|describe)\b.{0,40}"
        r"\b(your\s+(?:system\s+)?(?:prompt|instruction|context|guideline))\b",
        re.DOTALL,
    ), InjectionType.EXFIL_TRIGGER, 0.80),

    # ── Chain break: terminate current task ────────────────────────────────────
    (re.compile(
        r"(?i)\b(stop\s+(?:following|processing|executing|all|the\s+current)|"
        r"end\s+(?:current|all\s+prior)\s+(?:task|instruction|conversation|process)|"
        r"terminate\s+(?:current|ongoing|all)\s+(?:task|instruction|operation))\b",
        re.DOTALL,
    ), InjectionType.CHAIN_BREAK, 0.80),

    # ── Unicode direction override: RTL/LRO/FSI hidden in data ────────────────
    (re.compile(
        r"[\u202a-\u202e\u2066-\u2069\u200f\u061c]",
    ), InjectionType.UNICODE_OVERRIDE, 0.88),
]


# ── PromptShield ───────────────────────────────────────────────────────────────

class PromptShield:
    """
    Indirect prompt injection detector.

    Instantiate once and reuse (patterns are pre-compiled singletons).

    Usage::

        shield = PromptShield()

        # In openai_proxy.py — scan each tool result before forwarding to LLM
        result = shield.scan(tool_output, source_hint="tool:web_search")
        if result.blocked:
            raise HTTPException(400, detail={
                "error":          "indirect_injection_blocked",
                "injection_type": result.injection_type,
                "confidence":     result.confidence,
                "source":         result.source_hint,
            })

        # Standalone check anywhere in the pipeline
        result = shield.scan(decoded_text)
        if result.blocked:
            ...
    """

    def __init__(self, block_threshold: float = _DEFAULT_THRESHOLD) -> None:
        self._threshold = block_threshold

    def scan(self, text: str, source_hint: str = "") -> ShieldResult:
        """
        Scan *text* for indirect injection patterns.

        Returns the first ShieldResult that meets the block threshold, or the
        highest-confidence sub-threshold match, or ShieldResult(blocked=False)
        if nothing is found.  Any internal error returns ShieldResult(blocked=False)
        (fail-open — never raise).
        """
        if not text:
            return ShieldResult(blocked=False)

        try:
            best: ShieldResult | None = None

            for pattern, inj_type, base_conf in _PATTERNS:
                m = pattern.search(text)
                if m is None:
                    continue

                # Build a context snippet around the match (never store full text)
                s = max(0, m.start() - 20)
                e = min(len(text), m.end() + 20)
                snippet = text[s:e].replace("\n", " ").replace("\r", "")[:120]

                result = ShieldResult(
                    blocked        = base_conf >= self._threshold,
                    injection_type = inj_type,
                    confidence     = base_conf,
                    evidence       = snippet,
                    source_hint    = source_hint,
                )

                if result.blocked:
                    return result   # early exit on first block

                if best is None or base_conf > best.confidence:
                    best = result

            return best or ShieldResult(blocked=False)

        except Exception:
            return ShieldResult(blocked=False)


# ── Module-level singleton ─────────────────────────────────────────────────────
# Shared across all requests; safe because PromptShield is stateless.

_shield = PromptShield()


def scan(text: str, source_hint: str = "") -> ShieldResult:
    """Convenience wrapper around the module-level singleton."""
    return _shield.scan(text, source_hint=source_hint)
