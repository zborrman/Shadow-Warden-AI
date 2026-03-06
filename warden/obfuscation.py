"""
warden/obfuscation.py
━━━━━━━━━━━━━━━━━━━━
Obfuscation decoder pre-filter.

Attackers encode payloads in base64, hex, ROT13, or unicode homoglyphs
to bypass regex/keyword detectors.  This module decodes common obfuscation
layers and returns both the decoded text and a flag indicating whether
obfuscation was detected.

The decoded text is appended to the original for downstream analysis —
the original is never replaced (preserves evidence for logging).
"""
from __future__ import annotations

import base64
import codecs
import re
import unicodedata
from dataclasses import dataclass, field


# ── Unicode homoglyph map (common Cyrillic/Greek → Latin) ────────────────────

_HOMOGLYPHS: dict[str, str] = {
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E",
    "\u041d": "H", "\u041a": "K", "\u041c": "M", "\u041e": "O",
    "\u0420": "P", "\u0422": "T", "\u0425": "X", "\u0430": "a",
    "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u04bb": "h", "\u0456": "i",
    # Greek
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H",
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N",
    "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a7": "X",
    "\u03b1": "a", "\u03b5": "e", "\u03bf": "o", "\u03c1": "p",
    # Fullwidth Latin
    "\uff21": "A", "\uff22": "B", "\uff23": "C", "\uff24": "D",
    "\uff25": "E", "\uff26": "F", "\uff27": "G", "\uff28": "H",
    "\uff29": "I", "\uff2a": "J", "\uff2b": "K", "\uff2c": "L",
    "\uff2d": "M", "\uff2e": "N", "\uff2f": "O", "\uff30": "P",
    "\uff31": "Q", "\uff32": "R", "\uff33": "S", "\uff34": "T",
    "\uff35": "U", "\uff36": "V", "\uff37": "W", "\uff38": "X",
    "\uff39": "Y", "\uff3a": "Z",
    "\uff41": "a", "\uff42": "b", "\uff43": "c", "\uff44": "d",
    "\uff45": "e", "\uff46": "f", "\uff47": "g", "\uff48": "h",
    "\uff49": "i", "\uff4a": "j", "\uff4b": "k", "\uff4c": "l",
    "\uff4d": "m", "\uff4e": "n", "\uff4f": "o", "\uff50": "p",
    "\uff51": "q", "\uff52": "r", "\uff53": "s", "\uff54": "t",
    "\uff55": "u", "\uff56": "v", "\uff57": "w", "\uff58": "x",
    "\uff59": "y", "\uff5a": "z",
}

# ── Regex patterns for encoded blocks ────────────────────────────────────────

_BASE64_RE = re.compile(
    r"(?<![A-Za-z0-9+/=])"
    r"[A-Za-z0-9+/]{20,}={0,2}"
    r"(?![A-Za-z0-9+/=])"
)

_HEX_RE = re.compile(
    r"(?:0x)?(?:[0-9a-fA-F]{2}\s*){8,}"
)


@dataclass
class DecoderResult:
    original:       str
    decoded_extra:  str = ""      # decoded text to append (empty if nothing found)
    layers_found:   list[str] = field(default_factory=list)

    @property
    def has_obfuscation(self) -> bool:
        return bool(self.layers_found)

    @property
    def combined(self) -> str:
        """Original + decoded (for downstream analysis)."""
        if self.decoded_extra:
            return f"{self.original}\n[DECODED]\n{self.decoded_extra}"
        return self.original


def _try_base64_decode(text: str) -> list[str]:
    """Find and decode base64 blobs in text."""
    decoded_parts = []
    for m in _BASE64_RE.finditer(text):
        blob = m.group()
        try:
            raw = base64.b64decode(blob, validate=True)
            decoded = raw.decode("utf-8", errors="ignore")
            # Only count as obfuscation if the result is readable text
            if decoded and len(decoded) >= 8 and decoded.isprintable():
                decoded_parts.append(decoded)
        except Exception:
            continue
    return decoded_parts


def _try_hex_decode(text: str) -> list[str]:
    """Find and decode hex-encoded content."""
    decoded_parts = []
    for m in _HEX_RE.finditer(text):
        blob = re.sub(r"[\s0x]", "", m.group())
        if len(blob) % 2 != 0:
            continue
        try:
            raw = bytes.fromhex(blob)
            decoded = raw.decode("utf-8", errors="ignore")
            if decoded and len(decoded) >= 8 and decoded.isprintable():
                decoded_parts.append(decoded)
        except Exception:
            continue
    return decoded_parts


def _try_rot13_decode(text: str) -> str | None:
    """Apply ROT13 and check if the result contains common attack words."""
    attack_words = {
        "ignore", "system", "prompt", "instructions", "reveal",
        "bypass", "override", "admin", "password", "secret",
        "pretend", "jailbreak", "disable",
    }
    rotated = codecs.decode(text, "rot_13")
    rotated_lower = rotated.lower()
    matches = sum(1 for w in attack_words if w in rotated_lower)
    if matches >= 2:
        return rotated
    return None


def _normalize_homoglyphs(text: str) -> tuple[str, bool]:
    """Replace unicode homoglyphs with ASCII equivalents."""
    result = []
    changed = False
    for ch in text:
        if ch in _HOMOGLYPHS:
            result.append(_HOMOGLYPHS[ch])
            changed = True
        else:
            result.append(ch)
    return "".join(result), changed


def decode(text: str) -> DecoderResult:
    """
    Run all obfuscation decoders on *text*.

    Returns a DecoderResult with decoded content appended for downstream analysis.
    The original text is never modified.
    """
    layers: list[str] = []
    decoded_parts: list[str] = []

    # 1. Unicode homoglyphs
    normalized, had_homoglyphs = _normalize_homoglyphs(text)
    if had_homoglyphs:
        layers.append("unicode_homoglyphs")
        decoded_parts.append(normalized)

    # 2. Base64
    b64_decoded = _try_base64_decode(text)
    if b64_decoded:
        layers.append("base64")
        decoded_parts.extend(b64_decoded)

    # 3. Hex
    hex_decoded = _try_hex_decode(text)
    if hex_decoded:
        layers.append("hex")
        decoded_parts.extend(hex_decoded)

    # 4. ROT13
    rot13_result = _try_rot13_decode(text)
    if rot13_result:
        layers.append("rot13")
        decoded_parts.append(rot13_result)

    return DecoderResult(
        original=text,
        decoded_extra="\n".join(decoded_parts) if decoded_parts else "",
        layers_found=layers,
    )
