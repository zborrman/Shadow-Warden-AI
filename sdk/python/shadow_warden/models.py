"""shadow_warden/models.py — Response models for the Shadow Warden AI client."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SecretFinding:
    kind:    str
    token:   str
    start:   int
    end:     int

    @classmethod
    def from_dict(cls, d: dict) -> SecretFinding:
        return cls(kind=d["kind"], token=d["token"], start=d["start"], end=d["end"])


@dataclass
class SemanticFlag:
    flag:   str
    score:  float
    detail: str

    @classmethod
    def from_dict(cls, d: dict) -> SemanticFlag:
        return cls(flag=d["flag"], score=d["score"], detail=d.get("detail", ""))


@dataclass
class FilterResult:
    """Structured response from ``POST /filter``."""

    allowed:          bool
    risk_level:       str                        # low | medium | high | block
    filtered_content: str                        # content after redaction
    secrets_found:    list[SecretFinding]        = field(default_factory=list)
    semantic_flags:   list[SemanticFlag]         = field(default_factory=list)
    processing_ms:    dict[str, float]           = field(default_factory=dict)

    # Convenience helpers
    @property
    def blocked(self) -> bool:
        return not self.allowed

    @property
    def has_secrets(self) -> bool:
        return bool(self.secrets_found)

    @property
    def has_pii(self) -> bool:
        return any(f.flag == "pii_detected" for f in self.semantic_flags)

    @property
    def flag_names(self) -> list[str]:
        return [f.flag for f in self.semantic_flags]

    @classmethod
    def from_dict(cls, d: dict) -> FilterResult:
        return cls(
            allowed          = d["allowed"],
            risk_level       = d["risk_level"],
            filtered_content = d.get("filtered_content", ""),
            secrets_found    = [SecretFinding.from_dict(s) for s in d.get("secrets_found", [])],
            semantic_flags   = [SemanticFlag.from_dict(f)  for f in d.get("semantic_flags",  [])],
            processing_ms    = d.get("processing_ms", {}),
        )
