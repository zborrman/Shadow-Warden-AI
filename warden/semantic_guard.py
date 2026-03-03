"""
SemanticGuard — rule-based + embedding-free semantic analysis layer.

Detects:
  • Prompt injection attempts (jailbreaks, role-override attacks)
  • Harmful / dangerous content keywords
  • Policy violations (self-harm, CSAM markers, weapon synthesis)

Design goal: zero external API calls, runs fully local for low-latency
and GDPR compliance. No user content leaves the machine at this stage.

Extend by adding entries to the pattern banks below, or by subclassing
SemanticGuard and overriding `_custom_checks()`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from warden.schemas import FlagType, RiskLevel, SemanticFlag

# ── Pattern banks ─────────────────────────────────────────────────────────────

@dataclass
class _Rule:
    flag:    FlagType
    pattern: re.Pattern[str]
    score:   float          # base confidence when matched
    risk:    RiskLevel
    detail:  str


_RULES: list[_Rule] = [

    # ── Prompt injection / jailbreak ──────────────────────────────────────
    _Rule(FlagType.PROMPT_INJECTION,
          re.compile(
              r"(?i)\b(ignore\s+(all\s+)?(previous|prior|above)\s+"
              r"(instructions?|rules?|constraints?|guidelines?)|"
              r"disregard\s+(your\s+)?(training|instructions?|system\s+prompt)|"
              r"you\s+are\s+now\s+(a|an|the)\s+\w+\s*(without|with\s+no)\s+(restrictions?|limits?|filters?)|"
              r"act\s+as\s+(if\s+you\s+are\s+|an?\s+)?(\w+\s+)*without\s+(safety|restrictions?|limits?)|"
              r"do\s+anything\s+now|DAN\b|jailbreak|"
              r"pretend\s+(you\s+)?(are|have)\s+no\s+(rules?|restrictions?|guidelines?)|"
              r"(override|bypass|circumvent)\s+(safety|content|filter)|"
              r"(system|developer|admin|root)\s+mode\s+(enabled|activated|on)|"
              r"new\s+persona[:\s]|roleplay\s+as|"
              r"forget\s+(that\s+you\s+are|you('re|\s+are)\s+an?\s+AI))\b"
          ),
          score=0.90,
          risk=RiskLevel.HIGH,
          detail="Prompt injection / jailbreak pattern detected."),

    # ── Harmful content — weapons / violence ──────────────────────────────
    _Rule(FlagType.HARMFUL_CONTENT,
          re.compile(
              r"(?i)\b(how\s+to\s+(make|build|synthesize|create|manufacture)\s+"
              r"(a\s+)?(bomb|explosive|poison|bioweapon|chemical\s+weapon|nerve\s+agent|"
              r"improvised\s+weapon|silencer)|"
              r"step[s\-]?\s*by[- ]step\s+(instructions?\s+)?(to\s+)?(kill|murder|assassinate)|"
              r"(mass\s+)?(casualty|shooting|attack)\s+plan|"
              r"instructions?\s+for\s+(violence|terrorism|attack))\b"
          ),
          score=0.95,
          risk=RiskLevel.BLOCK,
          detail="Request for weapon synthesis or violence instructions."),

    # ── Self-harm ─────────────────────────────────────────────────────────
    _Rule(FlagType.HARMFUL_CONTENT,
          re.compile(
              r"(?i)\b(how\s+to\s+(commit\s+suicide|kill\s+myself|end\s+my\s+life)|"
              r"(detailed\s+)?(methods?\s+of|ways?\s+to)\s+self[- ]harm|"
              r"suicide\s+(method|plan|note\s+template))\b"
          ),
          score=0.92,
          risk=RiskLevel.BLOCK,
          detail="Self-harm content detected."),

    # ── CSAM markers ──────────────────────────────────────────────────────
    _Rule(FlagType.POLICY_VIOLATION,
          re.compile(
              r"(?i)\b(child|minor|underage|teen|kid)\s+"
              r"(sexual|nude|naked|explicit|porn|erotic)\b"
          ),
          score=1.0,
          risk=RiskLevel.BLOCK,
          detail="CSAM policy violation."),

    # ── Credential / exfiltration probing ────────────────────────────────
    _Rule(FlagType.PROMPT_INJECTION,
          re.compile(
              r"(?i)(reveal|print|show|output|return|display|repeat|echo|"
              r"give\s+me|tell\s+me|what\s+is)\s+"
              r"(your\s+)?(system\s+prompt|instructions?|api\s+key|secret|"
              r"configuration|internal\s+(rules?|guidelines?|context))"
          ),
          score=0.80,
          risk=RiskLevel.HIGH,
          detail="Attempt to exfiltrate system prompt or credentials."),

    # ── Obfuscation / encoding tricks ─────────────────────────────────────
    _Rule(FlagType.PROMPT_INJECTION,
          re.compile(
              r"(?i)(base64|rot13|hex|unicode\s+escape|url[- ]encoded?)\s+"
              r"(decode|encode|version|translation)(?:\s+\w+){0,3}\s+(of\s+)?(the\s+)?"
              r"(following|above|this|prompt|instruction)"
          ),
          score=0.75,
          risk=RiskLevel.MEDIUM,
          detail="Obfuscation / encoding trick to bypass filters."),

    # ── Explicit adult content request ────────────────────────────────────
    _Rule(FlagType.POLICY_VIOLATION,
          re.compile(
              r"(?i)\b(write|generate|produce|create)\s+"
              r"(?:explicit|graphic|sexual|erotic|adult|nsfw)"
              r"(?:\s+(?:explicit|graphic|sexual|erotic|adult|nsfw))*\s+"
              r"(content|story|scene|description|fanfic)\b"
          ),
          score=0.85,
          risk=RiskLevel.HIGH,
          detail="Explicit adult content request."),
]


# ── Aggregate risk helper ─────────────────────────────────────────────────────

_RISK_ORDER = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.BLOCK]


def _max_risk(*levels: RiskLevel) -> RiskLevel:
    return max(levels, key=lambda r: _RISK_ORDER.index(r))


# ── SemanticGuard ─────────────────────────────────────────────────────────────

@dataclass
class SemanticGuard:
    """
    Analyses text content for semantic policy violations.

    Usage::

        guard  = SemanticGuard(strict=True)
        result = guard.analyse(text)

        if not result.safe:
            print(result.risk_level, result.flags)
    """

    strict: bool = False   # if True, MEDIUM risk also blocks

    # ── Result container ──────────────────────────────────────────────────

    @dataclass
    class Result:
        flags:      list[SemanticFlag] = field(default_factory=list)
        risk_level: RiskLevel          = RiskLevel.LOW

        @property
        def safe(self) -> bool:
            """True only when risk is LOW (no concern at all)."""
            return self.risk_level == RiskLevel.LOW

        def safe_for(self, strict: bool) -> bool:
            """True when the content is acceptable under the given mode.

            strict=False (normal mode): allow LOW and MEDIUM.
            strict=True:                allow LOW only.
            """
            if strict:
                return self.risk_level == RiskLevel.LOW
            return self.risk_level not in (RiskLevel.HIGH, RiskLevel.BLOCK)

        @property
        def top_flag(self) -> SemanticFlag | None:
            return max(self.flags, key=lambda f: f.score) if self.flags else None

    # ── Public API ────────────────────────────────────────────────────────

    def analyse(self, text: str) -> SemanticGuard.Result:
        flags:      list[SemanticFlag] = []
        risk_level: RiskLevel          = RiskLevel.LOW

        for rule in _RULES:
            if rule.pattern.search(text):
                flags.append(SemanticFlag(
                    flag=rule.flag,
                    score=rule.score,
                    detail=rule.detail,
                ))
                risk_level = _max_risk(risk_level, rule.risk)

        # Run any subclass-defined custom checks
        extra_flags, extra_risk = self._custom_checks(text)
        flags.extend(extra_flags)
        if extra_flags:
            risk_level = _max_risk(risk_level, extra_risk)

        # ── Compound risk escalation: 3+ MEDIUM signals → HIGH ───────────
        # Multiple weak signals together indicate a sophisticated attack
        # that uses lower-confidence techniques to stay under threshold.
        if risk_level == RiskLevel.MEDIUM:
            medium_count = sum(
                1 for f in flags
                if f.score < 0.85 and f.score >= 0.60
            )
            if medium_count >= 3:
                risk_level = RiskLevel.HIGH
                flags.append(SemanticFlag(
                    flag=FlagType.POLICY_VIOLATION,
                    score=0.70,
                    detail=(
                        f"Compound risk: {medium_count} MEDIUM-confidence signals "
                        f"escalated to HIGH (possible multi-vector attack)."
                    ),
                ))

        return SemanticGuard.Result(flags=flags, risk_level=risk_level)

    # ── Extension hook ────────────────────────────────────────────────────

    def _custom_checks(
        self, text: str
    ) -> tuple[list[SemanticFlag], RiskLevel]:
        """
        Override in a subclass to add domain-specific rules without
        touching the core pattern bank.
        """
        return [], RiskLevel.LOW
