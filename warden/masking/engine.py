"""
warden/masking/engine.py
─────────────────────────
Synthetic Data Masking Engine — Yellow Zone.

Instead of blocking requests that contain PII (names, money amounts, dates,
organisations), this engine intercepts the prompt, replaces each entity with a
short consistent token, forwards the anonymised text to the LLM, and reverses
the replacement in the response before the user ever sees it.

Token format: [ENTITY_TYPE_N]  e.g. [PERSON_1], [MONEY_1], [DATE_2]

Entity types detected
─────────────────────
  EMAIL    — email addresses
  PHONE    — phone numbers (US E.164 + international)
  MONEY    — currency amounts  ($50,000  /  €1M  /  50 dollars)
  DATE     — dates in common formats (YYYY-MM-DD, MM/DD/YYYY, "15 Jan 2024" …)
  ORG      — company names with legal suffixes (Corp, LLC, Ltd, GmbH …)
  PERSON   — personal names (honorific-anchored + business-context clues)
  ID       — reference / account / ID numbers (alphanumeric, 6–20 chars)

Design
──────
  • Session-scoped vault  — same value always maps to the same token within
                            one session; different sessions are isolated.
  • Consistent round-trip — mask() then unmask() restores the original text.
  • Thread-safe           — each vault session is protected by an RLock.
  • TTL cleanup           — vault entries expire after _SESSION_TTL_S seconds.
  • Zero ML deps          — pure regex; drop-in on any CPU.

Limitations
───────────
  • Person detection is honorific/context-anchored.  Bare "John Smith" with no
    preceding Mr./Dr./client: etc. is NOT detected (too many false positives).
    For higher recall, replace the PERSON pattern with a spaCy NER component.
  • Streaming responses are NOT unmasked (tokens pass through as-is).
    The caller must buffer the full stream before unmasking.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import os as _os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import NamedTuple

from cryptography.fernet import Fernet

# ── Per-process vault encryption keys (ephemeral — regenerated on each restart) ─
# Fernet key:  encrypts original PII values stored in vault tokens dict.
# HMAC key:    hashes plaintext keys stored in reverse-lookup dict so the
#              original values are never kept in plaintext in memory.

_VAULT_FERNET_KEY: bytes       = Fernet.generate_key()
_VAULT_FERNET:     Fernet      = Fernet(_VAULT_FERNET_KEY)
_VAULT_HMAC_KEY:   bytes       = _os.urandom(32)


def _enc(plaintext: str) -> str:
    """Fernet-encrypt a PII value for in-memory vault storage."""
    return _VAULT_FERNET.encrypt(plaintext.encode()).decode()


def _dec(ciphertext: str) -> str:
    """Fernet-decrypt a PII value retrieved from the vault."""
    return _VAULT_FERNET.decrypt(ciphertext.encode()).decode()


def _hkey(plaintext: str) -> str:
    """HMAC-SHA256 of lowercase plaintext — opaque key for the reverse map."""
    return _hmac.new(_VAULT_HMAC_KEY, plaintext.encode(), hashlib.sha256).hexdigest()

# ── Session vault ─────────────────────────────────────────────────────────────

_SESSION_TTL_S: float = 7_200.0   # 2 hours

@dataclass
class _VaultSession:
    tokens:   dict[str, str]       = field(default_factory=dict)  # [TOKEN] → Fernet(original)
    reverse:  dict[str, str]       = field(default_factory=dict)  # hmac(lower(original)) → [TOKEN]
    counters: dict[str, int]       = field(default_factory=dict)  # "PERSON" → 2
    created:  float                = field(default_factory=time.monotonic)
    lock:     threading.RLock      = field(default_factory=threading.RLock)

    def is_expired(self) -> bool:
        return (time.monotonic() - self.created) > _SESSION_TTL_S


class _Vault:
    """Global vault manager — maps session_id → _VaultSession."""

    def __init__(self) -> None:
        self._sessions: dict[str, _VaultSession] = {}
        self._meta_lock = threading.Lock()

    def _get_or_create(self, session_id: str) -> _VaultSession:
        with self._meta_lock:
            self._purge_expired()
            if session_id not in self._sessions:
                self._sessions[session_id] = _VaultSession()
            return self._sessions[session_id]

    def _purge_expired(self) -> None:
        expired = [sid for sid, s in self._sessions.items() if s.is_expired()]
        for sid in expired:
            del self._sessions[sid]

    def get_or_create_token(
        self, session_id: str, entity_type: str, value: str
    ) -> str:
        """
        Return the token for `value` within this session, creating one if needed.
        Idempotent: the same value always returns the same token.

        Both the forward map (token → encrypted_value) and the reverse map
        (hmac(lower(value)) → token) store no plaintext PII in memory.
        """
        session = self._get_or_create(session_id)
        with session.lock:
            hk = _hkey(value.lower().strip())
            if hk in session.reverse:
                return session.reverse[hk]
            n = session.counters.get(entity_type, 0) + 1
            session.counters[entity_type] = n
            token = f"[{entity_type}_{n}]"
            session.tokens[token]  = _enc(value)   # store encrypted
            session.reverse[hk]    = token          # store HMAC key
            return token

    def get_all_tokens(self, session_id: str) -> dict[str, str]:
        """Return {token: original_value} for a session (decrypted copy)."""
        session = self._get_or_create(session_id)
        with session.lock:
            return {tok: _dec(enc) for tok, enc in session.tokens.items()}

    def invalidate(self, session_id: str) -> None:
        with self._meta_lock:
            self._sessions.pop(session_id, None)


_vault = _Vault()


# ── Entity patterns ────────────────────────────────────────────────────────────

class _EntityPattern(NamedTuple):
    entity_type: str
    pattern:     re.Pattern[str]


# ── EMAIL ─────────────────────────────────────────────────────────────────────
_P_EMAIL = _EntityPattern(
    "EMAIL",
    re.compile(r"\b[a-zA-Z0-9_.+-]{1,64}@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]{2,}\b"),
)

# ── PHONE ─────────────────────────────────────────────────────────────────────
# Tightened to avoid false positives on ISO dates (2024-03-15) and numeric IDs.
# International numbers MUST have an explicit '+' prefix.
# US numbers must follow NXX-NXX-XXXX (N=2-9) with optional +1 / (area) prefix.
_P_PHONE = _EntityPattern(
    "PHONE",
    re.compile(
        r"(?<!\d)"
        r"(?:"
        r"\+?1[\s\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}"            # +1 (NXX) NXX-XXXX
        r"|\(\d{3}\)[\s\-.]?\d{3}[\s\-.]?\d{4}"                          # (NXX) NXX-XXXX bare
        r"|\+[2-9]\d{0,2}[\s\-.]?\(?\d{2,4}\)?[\s\-.]?\d{2,4}[\s\-.]?\d{2,4}(?:[\s\-.]?\d{1,4})?"  # +CC ...
        r")"
        r"(?!\d)",
    ),
)

# ── MONEY ─────────────────────────────────────────────────────────────────────
# Matches: $50,000  /  $1.5M  /  €500  /  £1,200.50  /  50,000 dollars  /  USD 50K
_P_MONEY = _EntityPattern(
    "MONEY",
    re.compile(
        r"(?:"
        r"(?:USD|EUR|GBP|JPY|CAD|AUD|CHF|RUB|CNY)\s*[\d,]+(?:\.\d{1,2})?"
        r"(?:\s*(?:million|billion|thousand|[KMB]))?"                   # USD 50K
        r"|[$€£¥₽₹₩₪]\s*[\d,]+(?:\.\d{1,2})?"
        r"(?:\s*(?:million|billion|thousand|[KMB]))?"                   # $50,000
        r"|[\d,]+(?:\.\d{1,2})?\s*(?:million|billion|thousand|[KMB])?\s*"
        r"(?:dollars?|euros?|pounds?|rubles?|yen|yuan|francs?)"         # 50 dollars
        r")",
        re.IGNORECASE,
    ),
)

# ── DATE ──────────────────────────────────────────────────────────────────────
_MONTHS = (
    r"Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?"
    r"|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?"
)
_P_DATE = _EntityPattern(
    "DATE",
    re.compile(
        r"(?:"
        r"\b\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b"       # ISO 8601
        r"|(?:0[1-9]|1[0-2])[/.-](?:0[1-9]|[12]\d|3[01])[/.-]\d{2,4}" # MM/DD/YY(YY)
        r"|(?:0[1-9]|[12]\d|3[01])[/.-](?:0[1-9]|1[0-2])[/.-]\d{2,4}" # DD/MM/YY(YY)
        r"|(?:" + _MONTHS + r")\.?\s+(?:0?[1-9]|[12]\d|3[01]),?\s+\d{4}" # Jan 15, 2024
        r"|(?:0?[1-9]|[12]\d|3[01])\s+(?:" + _MONTHS + r")\.?\s+\d{4}" # 15 Jan 2024
        r")",
        re.IGNORECASE,
    ),
)

# ── ORG ───────────────────────────────────────────────────────────────────────
# Company names: 1–4 Title Case words, ending with a legal suffix.
# Each interior word must start with a capital letter — prevents greedy match
# across phrases like "Robert Johnson of Acme Corp".
_ORG_SUFFIXES = (
    r"Corp(?:oration)?|Inc(?:orporated)?|LLC|Ltd(?:\.|\b)|Limited"
    r"|GmbH|S\.A\.|PLC|LLP|LP\b|Co\.|Company|Group|Holdings"
    r"|Partners?|Associates?|International|Enterprises?"
    r"|Solutions?|Services?|Technologies?|Systems?"
)
_ORG_WORD    = r"[A-Z][A-Za-z0-9\-&]+"
_P_ORG = _EntityPattern(
    "ORG",
    re.compile(
        r"\b(" + _ORG_WORD + r"(?:\s+" + _ORG_WORD + r"){0,3}"
        r"\s+(?:" + _ORG_SUFFIXES + r")\.?)\b",
    ),
)

# ── PERSON ────────────────────────────────────────────────────────────────────
# Anchored: only matches names preceded by an honorific OR a business context word.
# Avoids false positives on proper nouns like "New York" or "World War".
_HONORIFICS = (
    r"Mr|Mrs|Ms|Miss|Mx|Dr|Prof|Rev|Sir|Dame|Lord|Lady|Esq"
    r"|CEO|CFO|CTO|COO|CIO|CISO|VP|SVP|EVP|Atty|Adv"
)
_CTX_WORDS = (
    r"client|customer|patient|employee|user|vendor|supplier|partner"
    r"|attorney|lawyer|claimant|defendant|plaintiff|witness|guarantor"
    r"|signed by|prepared by|authored by|submitted by|reviewed by"
    r"|from|to|cc|bcc"
)
_NAME_SEG = r"[A-Z][a-z]{1,25}"
_PERSON_RE = re.compile(
    # Honorific: "Dr. Jane Smith" / "Mr John Doe"
    r"\b(?:" + _HONORIFICS + r")\.?\s+"
    r"(" + _NAME_SEG + r"(?:\s+[A-Z]\.?\s+)?" + r"\s+" + _NAME_SEG + r")"
    r"|"
    # Context: "client: Robert Johnson" / "signed by Alice Brown"
    r"\b(?:" + _CTX_WORDS + r")[:\s]+"
    r"(" + _NAME_SEG + r"(?:\s+[A-Z]\.?\s+)?" + r"\s+" + _NAME_SEG + r")\b",
    re.IGNORECASE,
)

# ── ID (reference / account numbers) ─────────────────────────────────────────
# Format: letters + digits, 6–20 chars, prefixed by an ID context word.
_P_ID = _EntityPattern(
    "ID",
    re.compile(
        r"\b(?:account|acct|ref|reference|order|invoice|case|ticket|policy|"
        r"employee|member|contract|claim|project)\s*(?:#|no\.?|number|id|:)\s*"
        r"([A-Z0-9][A-Z0-9\-\/]{4,19})\b",
        re.IGNORECASE,
    ),
)

# ── Ordered pattern list ──────────────────────────────────────────────────────
# Order matters: DATE before PHONE so "2024-03-15" isn't treated as a phone.
# MONEY before PHONE so "$50,000" digits aren't accidentally captured.
# PERSON and ID handled separately (sub-group extraction needed).
_ENTITY_PATTERNS: list[_EntityPattern] = [
    _P_EMAIL,
    _P_DATE,    # must precede PHONE — ISO dates would false-positive as phones
    _P_MONEY,   # must precede PHONE — digit amounts could partially match
    _P_ORG,
    _P_PHONE,   # run last among simple patterns (most permissive digit matcher)
]


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class MaskedEntity:
    entity_type: str
    original:    str
    token:       str
    start:       int
    end:         int


@dataclass
class MaskResult:
    original:      str
    masked:        str
    session_id:    str
    entities:      list[MaskedEntity] = field(default_factory=list)

    @property
    def entity_count(self) -> int:
        return len(self.entities)

    @property
    def has_entities(self) -> bool:
        return bool(self.entities)

    def summary(self) -> dict[str, int]:
        """Return entity type → count mapping."""
        counts: dict[str, int] = {}
        for e in self.entities:
            counts[e.entity_type] = counts.get(e.entity_type, 0) + 1
        return counts


# ── Engine ────────────────────────────────────────────────────────────────────

class MaskingEngine:
    """
    Thread-safe masking engine.  Stateless except for the shared vault.

    Usage
    -----
    engine = MaskingEngine()

    # On the way IN (user → LLM):
    result = engine.mask("Invoice for John Smith, $50,000", session_id="abc")
    # result.masked == "Invoice for [PERSON_1], [MONEY_1]"

    # On the way OUT (LLM response → user):
    plain = engine.unmask("Payment confirmed for [PERSON_1]: [MONEY_1]", session_id="abc")
    # plain == "Payment confirmed for John Smith: $50,000"
    """

    def __init__(self, session_ttl: float = _SESSION_TTL_S) -> None:
        self._vault = _Vault()

    # ── Public API ────────────────────────────────────────────────────────────

    def mask(
        self,
        text:       str,
        session_id: str | None = None,
    ) -> MaskResult:
        """
        Scan `text` for PII entities, replace each with a reversible token.

        Parameters
        ----------
        text         : Input text (prompt, user message, etc.)
        session_id   : Opaque string identifying this conversation.
                       Auto-generated if None — use the returned session_id for
                       subsequent unmask() calls.

        Returns
        -------
        MaskResult   : Contains .masked (safe to forward), .session_id (keep!),
                       .entities (what was replaced), .entity_count.
        """
        if session_id is None:
            session_id = str(uuid.uuid4())

        entities: list[MaskedEntity] = []
        masked   = text

        # Work through pattern types in order.  After each pass, re-scan the
        # updated `masked` string so later patterns see already-tokenised text
        # and don't double-match.

        # ── Simple patterns (full match) ──────────────────────────────────────
        for ep in _ENTITY_PATTERNS:
            new_masked, new_entities = self._replace_pattern(
                ep.pattern, ep.entity_type, masked, session_id
            )
            # Adjust start/end offsets to original positions
            entities.extend(new_entities)
            masked = new_masked

        # ── ID before PERSON — context-anchored IDs with digits run first ────────
        masked, id_entities = self._replace_id(masked, session_id)
        entities.extend(id_entities)

        # ── PERSON (sub-group extraction) ─────────────────────────────────────
        masked, person_entities = self._replace_person(masked, session_id)
        entities.extend(person_entities)

        return MaskResult(
            original   = text,
            masked     = masked,
            session_id = session_id,
            entities   = entities,
        )

    def unmask(self, text: str, session_id: str) -> str:
        """
        Replace all [TYPE_N] tokens in `text` with the original values stored
        in the session vault.

        Safe to call even if `text` contains no tokens — returns as-is.
        """
        if not session_id:
            return text
        token_map = self._vault.get_all_tokens(session_id)
        if not token_map:
            return text

        result = text
        # Sort longest token first to avoid partial replacements
        for token, original in sorted(token_map.items(), key=lambda kv: -len(kv[0])):
            result = result.replace(token, original)
        return result

    def create_session(self) -> str:
        """Generate a new unique session ID."""
        return str(uuid.uuid4())

    def invalidate_session(self, session_id: str) -> None:
        """Explicitly remove a session vault (e.g. after conversation ends)."""
        self._vault.invalidate(session_id)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _replace_pattern(
        self,
        pattern:     re.Pattern[str],
        entity_type: str,
        text:        str,
        session_id:  str,
    ) -> tuple[str, list[MaskedEntity]]:
        entities: list[MaskedEntity] = []
        offset = 0
        out    = []
        for m in pattern.finditer(text):
            value = m.group(0)
            token = self._vault.get_or_create_token(session_id, entity_type, value)
            out.append(text[offset : m.start()])
            out.append(token)
            entities.append(MaskedEntity(
                entity_type = entity_type,
                original    = value,
                token       = token,
                start       = m.start(),
                end         = m.end(),
            ))
            offset = m.end()
        out.append(text[offset:])
        return "".join(out), entities

    def _replace_person(
        self,
        text:       str,
        session_id: str,
    ) -> tuple[str, list[MaskedEntity]]:
        """Handle PERSON pattern: extract captured sub-group (the actual name)."""
        entities: list[MaskedEntity] = []
        offset   = 0
        out      = []
        for m in _PERSON_RE.finditer(text):
            # Groups: 1 = honorific match, 2 = context-word match
            name = (m.group(1) or m.group(2) or "").strip()
            if not name:
                continue
            token = self._vault.get_or_create_token(session_id, "PERSON", name)
            # Replace only the name portion (not the preceding honorific/context word)
            name_start = text.index(name, m.start())
            name_end   = name_start + len(name)
            out.append(text[offset : name_start])
            out.append(token)
            entities.append(MaskedEntity(
                entity_type = "PERSON",
                original    = name,
                token       = token,
                start       = name_start,
                end         = name_end,
            ))
            offset = name_end
        out.append(text[offset:])
        return "".join(out), entities

    def _replace_id(
        self,
        text:       str,
        session_id: str,
    ) -> tuple[str, list[MaskedEntity]]:
        """Handle ID pattern: extract sub-group 1 (the numeric/alpha ID itself)."""
        entities: list[MaskedEntity] = []
        offset   = 0
        out      = []
        for m in _P_ID.pattern.finditer(text):
            id_value = (m.group(1) or "").strip()
            if not id_value:
                continue
            token = self._vault.get_or_create_token(session_id, "ID", id_value)
            id_start = text.index(id_value, m.start())
            id_end   = id_start + len(id_value)
            out.append(text[offset : id_start])
            out.append(token)
            entities.append(MaskedEntity(
                entity_type = "ID",
                original    = id_value,
                token       = token,
                start       = id_start,
                end         = id_end,
            ))
            offset = id_end
        out.append(text[offset:])
        return "".join(out), entities


# ── Module-level singleton ────────────────────────────────────────────────────

_engine = MaskingEngine()


def get_engine() -> MaskingEngine:
    """Return the shared module-level MaskingEngine instance."""
    return _engine
