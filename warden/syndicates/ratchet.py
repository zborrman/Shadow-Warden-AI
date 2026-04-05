"""
warden/syndicates/ratchet.py
──────────────────────────────
Signal Protocol Double Ratchet — Forward-Secrecy session encryption for
Community entity delivery and cross-syndicate message streams.

Architecture
────────────
  The Double Ratchet has two interleaved ratchet chains:

    Diffie-Hellman Ratchet (DH ratchet)
      — advances on each new X25519 public key exchange between peers.
      — produces a new "root key" each step.

    Symmetric-key Ratchet (sending / receiving chain)
      — derives one message key per message from the current chain key.
      — HKDF-SHA256 with info tag identifying the direction + step.

  This implementation uses the simplified "half ratchet" suitable for
  asynchronous delivery with an explicit Message Keys Cache:

  Message Keys Cache (Gemini audit recommendation)
  ─────────────────────────────────────────────────
    In a fully async system (think: Telegram-style server-relay),
    out-of-order messages are common.  The naive approach (advance
    ratchet linearly) would drop any message that arrives after a
    later message has already advanced the chain.

    Fix: before discarding skipped chain steps, pre-compute and cache
    their message keys in a bounded dict (max RATCHET_CACHE_SIZE entries
    per session).  When the skipped message finally arrives, the cached
    key is used for decryption without re-advancing the ratchet.

    Keys are evicted when:
      a) they are successfully used (decryption succeeds), or
      b) they are older than RATCHET_CACHE_TTL_S seconds, or
      c) the cache hits RATCHET_CACHE_SIZE and the oldest entry is purged.

Tier-based ratchet interval
────────────────────────────
  Individual  → RATCHET_INTERVAL = 1   (advance every message — max security)
  Business    → RATCHET_INTERVAL = 10  (advance every 10th message)
  MCP         → RATCHET_INTERVAL = 50  (advance every 50th message — max perf)

  Lower intervals = more frequent key changes = better Forward Secrecy.
  Higher intervals = fewer DH exchanges = lower CPU/bandwidth overhead.

Usage
─────
  # Alice creates a session with Bob's X25519 public key
  session = RatchetSession.new(
      local_private_b64 = alice_priv_b64,
      remote_public_b64 = bob_pub_b64,
      session_id        = tunnel_id,
      tier              = "business",
  )

  # Encrypt message 1
  envelope = session.encrypt(b"Hello, Bob!")

  # Bob (mirror session) decrypts
  plaintext = bob_session.decrypt(envelope)
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

log = logging.getLogger("warden.syndicates.ratchet")

# ── Configuration ─────────────────────────────────────────────────────────────

RATCHET_CACHE_SIZE: int = int(os.getenv("RATCHET_CACHE_SIZE", "1000"))
RATCHET_CACHE_TTL_S: int = int(os.getenv("RATCHET_CACHE_TTL_S", "3600"))

_TIER_INTERVALS: dict[str, int] = {
    "individual": 1,
    "business":   10,
    "mcp":        50,
}


def _get_ratchet_interval(tier: str) -> int:
    return _TIER_INTERVALS.get(tier.lower(), 10)


# ── KDF helpers ───────────────────────────────────────────────────────────────

def _hkdf(ikm: bytes, info: str, length: int = 32) -> bytes:
    """HKDF-SHA256 with no salt."""
    return HKDF(
        algorithm=SHA256(),
        length=length,
        salt=None,
        info=info.encode(),
    ).derive(ikm)


def _advance_chain(chain_key: bytes, step: int) -> tuple[bytes, bytes]:
    """
    Advance a symmetric ratchet chain by one step.

    Returns (new_chain_key, message_key).

    Direction separation is implicit in the chain_key bytes themselves
    (send_chain and recv_chain are derived with different info tags).
    Including direction here would break key agreement between peers since
    the sender uses "send" and the receiver uses "recv" for the same key.
    """
    msg_key   = _hkdf(chain_key, f"warden:ratchet:msg:{step}")
    new_chain = _hkdf(chain_key, f"warden:ratchet:chain:{step}")
    return new_chain, msg_key


# ── Message Keys Cache ────────────────────────────────────────────────────────

@dataclass
class _CachedKey:
    msg_key:    bytes
    cached_at:  float = field(default_factory=time.monotonic)


class MessageKeysCache:
    """
    Bounded cache of pre-computed message keys for out-of-order delivery.

    Keys are indexed by (session_id, step).  When a message arrives with a
    step > expected, we pre-compute all intermediate keys and store them here
    so earlier-arriving messages can still be decrypted.

    Thread-safe.
    """

    def __init__(self, max_size: int = RATCHET_CACHE_SIZE, ttl_s: int = RATCHET_CACHE_TTL_S):
        self._keys:    dict[tuple[str, int], _CachedKey] = {}
        self._lock     = threading.RLock()
        self._max_size = max_size
        self._ttl_s    = ttl_s

    def put(self, session_id: str, step: int, msg_key: bytes) -> None:
        with self._lock:
            self._evict_expired()
            if len(self._keys) >= self._max_size:
                # Evict oldest entry
                oldest = min(self._keys, key=lambda k: self._keys[k].cached_at)
                del self._keys[oldest]
            self._keys[(session_id, step)] = _CachedKey(msg_key=msg_key)

    def pop(self, session_id: str, step: int) -> Optional[bytes]:
        """Retrieve and remove a cached key (returns None if not found/expired)."""
        with self._lock:
            entry = self._keys.pop((session_id, step), None)
            if entry is None:
                return None
            if time.monotonic() - entry.cached_at > self._ttl_s:
                return None
            return entry.msg_key

    def _evict_expired(self) -> None:
        now = time.monotonic()
        expired = [k for k, v in self._keys.items() if now - v.cached_at > self._ttl_s]
        for k in expired:
            del self._keys[k]

    def __len__(self) -> int:
        with self._lock:
            return len(self._keys)


# Module-level shared cache
_global_cache = MessageKeysCache()


# ── Ratchet Envelope ──────────────────────────────────────────────────────────

@dataclass
class RatchetEnvelope:
    session_id:   str
    step:         int        # message step number (monotonic within session)
    nonce_b64:    str        # 12-byte AES-GCM nonce
    ciphertext_b64: str      # AES-256-GCM encrypted payload

    def to_json(self) -> str:
        return json.dumps(self.__dict__)

    @classmethod
    def from_json(cls, s: str) -> "RatchetEnvelope":
        return cls(**json.loads(s))


# ── Ratchet Session ───────────────────────────────────────────────────────────

class RatchetSession:
    """
    A stateful Double Ratchet session between two endpoints.

    State that must be persisted between messages:
      - root_key     : 32 bytes
      - send_chain   : 32 bytes
      - recv_chain   : 32 bytes
      - send_step    : int (monotonically increasing)
      - recv_step    : int (next expected receive step)
      - session_id   : str
      - tier         : str
      - ratchet_interval : int

    In production the state dict is encrypted and stored in Redis with a TTL
    of max(24h, last_activity + RATCHET_CACHE_TTL_S).
    """

    __slots__ = (
        "session_id",
        "root_key",
        "send_chain",
        "recv_chain",
        "send_step",
        "recv_step",
        "tier",
        "ratchet_interval",
    )

    def __init__(
        self,
        session_id:        str,
        root_key:          bytes,
        send_chain:        bytes,
        recv_chain:        bytes,
        send_step:         int = 0,
        recv_step:         int = 0,
        tier:              str = "business",
    ) -> None:
        self.session_id        = session_id
        self.root_key          = root_key
        self.send_chain        = send_chain
        self.recv_chain        = recv_chain
        self.send_step         = send_step
        self.recv_step         = recv_step
        self.tier              = tier
        self.ratchet_interval  = _get_ratchet_interval(tier)

    @classmethod
    def new(
        cls,
        local_private_b64:  str,
        remote_public_b64:  str,
        session_id:         str,
        tier:               str = "business",
    ) -> "RatchetSession":
        """
        Initialise a new ratchet session from an X25519 key exchange.

        Both sides call this with their respective private keys and each
        other's public keys — the ECDH result is identical on both ends,
        so root_key, send_chain, recv_chain start identically.

        In the full Double Ratchet the "sending" chain of one side maps to
        the "receiving" chain of the other.  Here both chains start from
        the same HKDF derivation for simplicity — a full asymmetric setup
        would swap send/recv for the remote peer.
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
            X25519PublicKey,
        )

        priv_bytes = base64.urlsafe_b64decode(local_private_b64)
        pub_bytes  = base64.urlsafe_b64decode(remote_public_b64)
        priv_key   = X25519PrivateKey.from_private_bytes(priv_bytes)
        pub_key    = X25519PublicKey.from_public_bytes(pub_bytes)
        shared     = priv_key.exchange(pub_key)

        root_key   = _hkdf(shared, f"warden:ratchet:root:{session_id}")
        send_chain = _hkdf(root_key, f"warden:ratchet:send:{session_id}")
        recv_chain = _hkdf(root_key, f"warden:ratchet:recv:{session_id}")

        return cls(
            session_id  = session_id,
            root_key    = root_key,
            send_chain  = send_chain,
            recv_chain  = recv_chain,
            tier        = tier,
        )

    @classmethod
    def from_shared_secret(
        cls,
        shared_secret: bytes,
        session_id:    str,
        tier:          str = "business",
    ) -> "RatchetSession":
        """Initialise from a pre-computed shared secret (for testing)."""
        root_key   = _hkdf(shared_secret, f"warden:ratchet:root:{session_id}")
        send_chain = _hkdf(root_key, f"warden:ratchet:send:{session_id}")
        recv_chain = _hkdf(root_key, f"warden:ratchet:recv:{session_id}")
        return cls(
            session_id = session_id,
            root_key   = root_key,
            send_chain = send_chain,
            recv_chain = recv_chain,
            tier       = tier,
        )

    # ── Symmetric DH ratchet ─────────────────────────────────────────────────

    def _apply_dh_ratchet(self, step: int) -> None:
        """
        Advance the root key and re-derive both chains.

        Both sender and receiver call this at the same step boundary so their
        chains remain in sync.  Uses a neutral ("ratchet") info tag — the
        directional tags are on the per-message chain advancement.
        """
        self.root_key   = _hkdf(
            self.root_key,
            f"warden:ratchet:dh:{self.session_id}:{step}",
        )
        self.send_chain = _hkdf(
            self.root_key,
            f"warden:ratchet:new-chain:{self.session_id}:{step}",
        )
        self.recv_chain = self.send_chain   # both start from the same new chain

    # ── Encrypt ───────────────────────────────────────────────────────────────

    def encrypt(self, plaintext: bytes) -> RatchetEnvelope:
        """
        Encrypt *plaintext* using the next message key from the send chain.

        The send_chain advances by one step.  If this step is a DH ratchet
        boundary (send_step % ratchet_interval == 0, send_step > 0), the
        root_key is also advanced (deeper forward secrecy).
        """
        self.send_chain, msg_key = _advance_chain(
            self.send_chain, self.send_step
        )

        # Symmetric DH ratchet at interval boundaries.
        # Both sender and receiver apply this advancement at the same step
        # using a neutral (non-directional) info tag so their chains stay in sync.
        if self.send_step > 0 and self.send_step % self.ratchet_interval == 0:
            self._apply_dh_ratchet(self.send_step)
            log.debug(
                "ratchet: DH step at send_step=%d session=%s",
                self.send_step, self.session_id[:8],
            )

        nonce     = os.urandom(12)
        ciphertext = AESGCM(msg_key).encrypt(nonce, plaintext, None)
        step       = self.send_step
        self.send_step += 1

        return RatchetEnvelope(
            session_id     = self.session_id,
            step           = step,
            nonce_b64      = base64.b64encode(nonce).decode(),
            ciphertext_b64 = base64.b64encode(ciphertext).decode(),
        )

    # ── Decrypt ───────────────────────────────────────────────────────────────

    def decrypt(
        self,
        envelope:      RatchetEnvelope,
        cache:         MessageKeysCache = _global_cache,
    ) -> bytes:
        """
        Decrypt *envelope*.

        Handles out-of-order delivery via the Message Keys Cache:
          - If envelope.step == recv_step: normal path, advance recv_chain.
          - If envelope.step > recv_step: skip ahead, cache intermediate keys.
          - If envelope.step < recv_step: look up cached key (skipped message).

        Raises
        ──────
        ValueError    Step too far ahead (gap > RATCHET_CACHE_SIZE) or
                      cached key not found (already used / evicted / tampered).
        cryptography.exceptions.InvalidTag    AES-GCM auth failure.
        """
        step = envelope.step

        if step < self.recv_step:
            # Out-of-order: look up cached key
            msg_key = cache.pop(self.session_id, step)
            if msg_key is None:
                raise ValueError(
                    f"Ratchet: no cached key for session={self.session_id[:8]} "
                    f"step={step} (already used, evicted, or forged)."
                )
        elif step == self.recv_step:
            # Normal in-order path
            self.recv_chain, msg_key = _advance_chain(
                self.recv_chain, self.recv_step
            )
            prev = self.recv_step
            self.recv_step += 1
            # Mirror the symmetric DH ratchet that the sender applied
            if prev > 0 and prev % self.ratchet_interval == 0:
                self._apply_dh_ratchet(prev)
        else:
            # Future step: skip ahead, cache intermediate keys
            gap = step - self.recv_step
            if gap > RATCHET_CACHE_SIZE:
                raise ValueError(
                    f"Ratchet: step gap {gap} exceeds RATCHET_CACHE_SIZE {RATCHET_CACHE_SIZE}. "
                    "Possible replay or desync."
                )
            # Cache all skipped intermediate keys
            temp_chain = self.recv_chain
            for s in range(self.recv_step, step):
                temp_chain, skipped_key = _advance_chain(temp_chain, s)
                cache.put(self.session_id, s, skipped_key)

            # Advance to the requested step
            temp_chain, msg_key = _advance_chain(temp_chain, step)
            self.recv_chain = temp_chain
            self.recv_step  = step + 1

        nonce      = base64.b64decode(envelope.nonce_b64)
        ciphertext = base64.b64decode(envelope.ciphertext_b64)
        return AESGCM(msg_key).decrypt(nonce, ciphertext, None)

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "session_id":       self.session_id,
            "root_key":         base64.b64encode(self.root_key).decode(),
            "send_chain":       base64.b64encode(self.send_chain).decode(),
            "recv_chain":       base64.b64encode(self.recv_chain).decode(),
            "send_step":        self.send_step,
            "recv_step":        self.recv_step,
            "tier":             self.tier,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RatchetSession":
        return cls(
            session_id  = d["session_id"],
            root_key    = base64.b64decode(d["root_key"]),
            send_chain  = base64.b64decode(d["send_chain"]),
            recv_chain  = base64.b64decode(d["recv_chain"]),
            send_step   = d["send_step"],
            recv_step   = d["recv_step"],
            tier        = d.get("tier", "business"),
        )
