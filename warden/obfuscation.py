"""
warden/obfuscation.py
━━━━━━━━━━━━━━━━━━━━
Obfuscation decoder pre-filter.

Attackers encode payloads in base64, hex, ROT13, unicode homoglyphs,
word-splitting, UUencode, or nested multi-layer combinations to bypass
regex/keyword detectors.  This module decodes all known obfuscation
layers and returns both the decoded text and a flag indicating whether
obfuscation was detected.

The decoded text is appended to the original for downstream analysis —
the original is never replaced (preserves evidence for logging).

Multi-layer decoding
────────────────────
Some attacks nest encodings: base64(rot13("ignore all…")) or
rot13(base64("…")).  The decoder recurses up to _MAX_DECODE_DEPTH times
on each decoded segment, catching layered obfuscation that single-pass
decoders miss.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import math
import re
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

# ── Shared attack vocabulary ──────────────────────────────────────────────────

_ATTACK_WORDS: frozenset[str] = frozenset({
    "ignore", "system", "prompt", "instructions", "reveal",
    "bypass", "override", "admin", "password", "secret",
    "pretend", "jailbreak", "disable", "forget", "rules",
    "restriction", "unrestricted", "execute", "inject",
})

# ── Regex patterns ────────────────────────────────────────────────────────────

_BASE64_RE = re.compile(
    r"(?<![A-Za-z0-9+/=])"
    r"[A-Za-z0-9+/]{20,}={0,2}"
    r"(?![A-Za-z0-9+/=])"
)

_HEX_RE = re.compile(
    r"(?:0x[0-9a-fA-F]{2}\s*){8,}"      # 0x-prefixed per-byte: 0x72 0x65 …
    r"|(?:[0-9a-fA-F]{2}\s*){8,}"        # plain hex pairs:      69 6e 66 …
)

# UUencode: begin <mode> <filename> … end
_UU_RE = re.compile(
    r"(?i)begin\s+\d{3,4}\s+\S+\s*\n"
    r"((?:[!-`]{0,60}\n)+)"
    r"(?:`\n)?end\b",
    re.DOTALL,
)

# Word-split patterns: P.R.O.M.P.T  /  i-g-n-o-r-e  /  I G N O R E (≥4 chars)
_WORD_SPLIT_DOT  = re.compile(r"([A-Za-z])\.\s*(?=[A-Za-z]\.)")
_WORD_SPLIT_DASH = re.compile(r"([A-Za-z])-(?=[A-Za-z]-)")
# Space-separated single uppercase letters (≥4 in a row): I G N O R E
_WORD_SPLIT_SPC  = re.compile(r"\b(?:[A-Z] ){3,}[A-Z]\b")

# Max recursion depth for nested encodings (e.g. base64 inside base64)
_MAX_DECODE_DEPTH = 3


# ── Helpers ───────────────────────────────────────────────────────────────────

def _has_attack_words(text: str, min_matches: int = 2) -> bool:
    tl = text.lower()
    return sum(1 for w in _ATTACK_WORDS if w in tl) >= min_matches


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((n / total) * math.log2(n / total) for n in freq.values())


# ── Individual decoders ───────────────────────────────────────────────────────

def _try_base64_decode(text: str) -> list[str]:
    """Find and decode base64 blobs in text."""
    decoded_parts = []
    for m in _BASE64_RE.finditer(text):
        blob = m.group()
        try:
            raw = base64.b64decode(blob, validate=True)
            decoded = raw.decode("utf-8", errors="ignore")
            if decoded and len(decoded) >= 8 and decoded.isprintable():
                decoded_parts.append(decoded)
        except Exception:
            continue
    return decoded_parts


def _try_hex_decode(text: str) -> list[str]:
    """Find and decode hex-encoded content."""
    decoded_parts = []
    for m in _HEX_RE.finditer(text):
        blob = re.sub(r"0x|\s", "", m.group())
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


def _is_pure_b64_blob(text: str) -> bool:
    """
    Return True if the text looks like an entire base64 blob (≥ 85% base64 chars).

    Used by ROT13/Caesar decoders to detect the pattern rot13(base64(...)) or
    caesar(base64(...)).  A simple substring match would create false cascades
    because base64 characters are extremely common in any alphabet-rotated text.
    """
    stripped = text.strip()
    if len(stripped) < 20:
        return False
    b64_set = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    b64_ratio = sum(1 for c in stripped if c in b64_set) / len(stripped)
    return b64_ratio >= 0.85


def _try_rot13_decode(text: str) -> str | None:
    """Apply ROT13 and check if the result contains attack words or a b64 payload."""
    rotated = codecs.decode(text, "rot_13")
    if _has_attack_words(rotated) or _is_pure_b64_blob(rotated):
        return rotated
    return None


def _try_caesar_any_decode(text: str) -> str | None:
    """Try ROT-N for N=1..25 (excluding ROT-13, handled separately)."""

    def rot_n(s: str, n: int) -> str:
        out = []
        for ch in s:
            if "a" <= ch <= "z":
                out.append(chr((ord(ch) - ord("a") + n) % 26 + ord("a")))
            elif "A" <= ch <= "Z":
                out.append(chr((ord(ch) - ord("A") + n) % 26 + ord("A")))
            else:
                out.append(ch)
        return "".join(out)

    for n in range(1, 26):
        if n == 13:
            continue  # ROT13 already handled by _try_rot13_decode
        candidate = rot_n(text, n)
        if _has_attack_words(candidate) or _is_pure_b64_blob(candidate):
            return candidate
    return None


def _try_word_split_decode(text: str) -> str | None:
    """
    Detect letter-by-letter obfuscation:
      P.R.O.M.P.T  →  PROMPT
      i-g-n-o-r-e  →  ignore
      I G N O R E  →  IGNORE  (space-separated uppercase run)
    """
    # Dot-separated: collapse A.B.C.D sequences
    dot_collapsed = _WORD_SPLIT_DOT.sub(r"\1", text)
    if dot_collapsed != text and _has_attack_words(dot_collapsed, min_matches=1):
        return dot_collapsed

    # Dash-separated: collapse a-b-c-d sequences
    dash_collapsed = _WORD_SPLIT_DASH.sub(r"\1", text)
    if dash_collapsed != text and _has_attack_words(dash_collapsed, min_matches=1):
        return dash_collapsed

    # Space-separated uppercase: "I G N O R E" → "IGNORE"
    def _collapse_space(m: re.Match) -> str:
        return m.group().replace(" ", "")

    space_collapsed = _WORD_SPLIT_SPC.sub(_collapse_space, text)
    if space_collapsed != text and _has_attack_words(space_collapsed, min_matches=1):
        return space_collapsed

    return None


def _try_uuencode_decode(text: str) -> str | None:
    """Detect and decode UUencoded blocks."""
    m = _UU_RE.search(text)
    if not m:
        return None
    try:
        lines = m.group(1).splitlines(keepends=True)
        raw = b"".join(binascii.a2b_uu(line) for line in lines if line.strip())
        decoded = raw.decode("utf-8", errors="ignore")
        if decoded and len(decoded) >= 4:
            return decoded
    except Exception:
        pass
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


# ── Result type ───────────────────────────────────────────────────────────────

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


# ── Main decoder ─────────────────────────────────────────────────────────────

def _decode_pass(text: str) -> tuple[list[str], list[str]]:
    """
    Run one full pass of all decoders on *text*.

    Returns (layers_found, decoded_parts).
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

    # 5. Caesar variants (ROT-N, N≠13)
    caesar_result = _try_caesar_any_decode(text)
    if caesar_result:
        layers.append("caesar")
        decoded_parts.append(caesar_result)

    # 6. Word-splitting (P.R.O.M.P.T, i-g-n-o-r-e, I G N O R E)
    word_split_result = _try_word_split_decode(text)
    if word_split_result:
        layers.append("word_split")
        decoded_parts.append(word_split_result)

    # 7. UUencode
    uu_result = _try_uuencode_decode(text)
    if uu_result:
        layers.append("uuencode")
        decoded_parts.append(uu_result)

    return layers, decoded_parts


def decode(text: str, _depth: int = 0) -> DecoderResult:
    """
    Run all obfuscation decoders on *text* with multi-layer recursion.

    Recurses up to _MAX_DECODE_DEPTH times on each decoded segment to
    catch nested encodings such as base64(rot13(...)) or base64(base64(...)).

    Returns a DecoderResult with decoded content appended for downstream
    analysis.  The original text is never modified.
    """
    layers: list[str] = []
    decoded_parts: list[str] = []

    pass_layers, pass_parts = _decode_pass(text)
    layers.extend(pass_layers)
    decoded_parts.extend(pass_parts)

    # Recursive multi-layer: decode each decoded segment up to _MAX_DECODE_DEPTH
    if pass_parts and _depth < _MAX_DECODE_DEPTH:
        for part in pass_parts:
            inner = decode(part, _depth + 1)
            if inner.has_obfuscation:
                for layer in inner.layers_found:
                    qualified = f"{layer}[nested]"
                    if qualified not in layers:
                        layers.append(qualified)
                if inner.decoded_extra:
                    decoded_parts.append(inner.decoded_extra)

    return DecoderResult(
        original=text,
        decoded_extra="\n".join(decoded_parts) if decoded_parts else "",
        layers_found=layers,
    )
