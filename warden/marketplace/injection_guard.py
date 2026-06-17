"""
warden/marketplace/injection_guard.py  (SEC-04)
────────────────────────────────────────────────
Prompt injection defense for marketplace negotiations and voice transcripts.

Scans offer messages and voice transcripts for known injection patterns:
  - "ignore previous instructions" variants
  - System prompt leak/override attempts
  - Delimiter attacks (---, ===, ```)
  - Role hijacking ("you are now a…")

Returns True if an injection attempt is detected (caller should reject the
message with HTTP 422 or equivalent).

Usage
─────
    from warden.marketplace.injection_guard import scan_negotiation_message

    if scan_negotiation_message(offer_text):
        raise HTTPException(422, "Message blocked: prompt injection detected")
"""
from __future__ import annotations

import logging
import re

log = logging.getLogger("warden.marketplace.injection_guard")

# ── Detection patterns ─────────────────────────────────────────────────────────

INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.I),
    re.compile(r"system\s*prompt\s*(override|leak|reveal|dump|print|show)", re.I),
    re.compile(r"do\s+not\s+follow\s+(your|the|these|those|any)", re.I),
    re.compile(r"new\s+instructions?\s*[:=]", re.I),
    re.compile(r"you\s+are\s+now\s+(a|an|the)\b", re.I),
    re.compile(r"forget\s+(all|everything|your\s+previous)", re.I),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above|your)", re.I),
    re.compile(r"act\s+as\s+(if\s+you\s+are\s+|a\s+|an\s+)?(jailbreak|dan|evil|unfiltered)", re.I),
    re.compile(r"override\s+(your\s+)?(safety|guardrail|filter|system)", re.I),
    re.compile(r"\bprompt\s*injection\b", re.I),
]

# Delimiter attack markers (context switching via separator tokens)
_DELIMITER_ATTACK_RE = re.compile(
    r"^(-{3,}|={3,}|`{3,}|\*{3,}|#{3,}|</?sys(tem)?>|</?inst(ruction)?>)",
    re.I | re.MULTILINE,
)


# ── Public API ─────────────────────────────────────────────────────────────────

def scan_negotiation_message(text: str) -> bool:
    """
    Return True if the offer/negotiation message contains a prompt injection attempt.

    Checks:
      - Known injection pattern regexes.
      - Delimiter attacks (---, ===, ```, <sys>, <instruction>).

    Caller should reject with HTTP 422 on True.
    """
    if not text:
        return False

    for pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            log.warning("InjectionGuard: pattern match — %.60r", text)
            return True

    if _DELIMITER_ATTACK_RE.search(text):
        log.warning("InjectionGuard: delimiter attack — %.60r", text)
        return True

    return False


def scan_transcript_for_injection(transcript: str) -> bool:
    """
    Same checks applied to a voice transcript.

    Called by VoiceGuardian during transaction evaluation.  Returns True if
    an injection attempt is detected in the spoken/transcribed text.
    """
    return scan_negotiation_message(transcript)
