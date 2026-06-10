"""
warden/marketplace/tokenizer.py
─────────────────────────────────
Asset tokenizer — packages detection assets into signed UECIID containers
suitable for community M2M trade.

Each container is:
  • Content-addressed: SHA-256 over canonical JSON payload
  • Signed: 64-byte Ed25519 signature (via CommunityKeypair.sign)
  • Identified: UECIID (SEP-{11 base-62}) from sep.new_ueciid()
  • Optionally pinned to IPFS (falls back to SHA-256 CID simulation)

Supported asset types
─────────────────────
  rule     — Evolution Engine detection rule (keyword or regex_pattern)
             Regex rules are screened by EvolutionEngine._validate_regex_safety
             to reject ReDoS-vulnerable patterns before tokenization.
  model    — Semantic Layer model in OSI 1.0 format (JSON schema check only)
  signals  — Timed batch of threat signal dicts
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from warden.communities.keypair import CommunityKeypair

log = logging.getLogger("warden.marketplace.tokenizer")

_OSI_REQUIRED_FIELDS = {"osi_version", "id", "metrics", "dimensions"}


# ── Internal helpers ──────────────────────────────────────────────────────────

def _canonical_json(obj: dict | list) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sign_b64(keypair: "CommunityKeypair", data: bytes) -> str:
    sig_bytes = keypair.sign(data)
    return base64.b64encode(sig_bytes).decode()


def _upload_ipfs(payload: dict) -> str:
    try:
        from warden.blockchain.ipfs_storage import IPFSStorage
        return IPFSStorage().store_mandate(payload)
    except Exception:
        digest = _sha256_hex(_canonical_json(payload))
        return f"Qm{digest[:44]}"   # CID-shaped fallback


def _build_container(
    asset_type: str,
    payload: dict,
    keypair: "CommunityKeypair",
    agent_id: str,
    community_id: str,
) -> dict:
    from warden.communities.sep import new_ueciid
    _, ueciid = new_ueciid()

    canonical = _canonical_json(payload)
    sha256 = _sha256_hex(canonical)
    signature = _sign_b64(keypair, sha256.encode())
    ipfs_hash = _upload_ipfs(payload)

    return {
        "ueciid":           ueciid,
        "asset_type":       asset_type,
        "sha256":           sha256,
        "signature":        signature,
        "signer_public_key": keypair.ed25519_pub_b64,
        "ipfs_hash":        ipfs_hash,
        "payload":          payload,
        "metadata": {
            "created_at":      datetime.now(UTC).isoformat(),
            "community_id":    community_id,
            "seller_agent_id": agent_id,
        },
    }


# ── Public API ────────────────────────────────────────────────────────────────

class AssetTokenizer:
    """Stateless tokenizer — instantiate per call or reuse freely."""

    def tokenize_rule(
        self,
        rule_data: dict,
        keypair: "CommunityKeypair",
        agent_id: str,
        community_id: str,
    ) -> dict:
        """Tokenize an Evolution Engine detection rule.

        Raises ValueError if rule_data contains an unsafe regex_pattern.
        """
        if "regex_pattern" in rule_data:
            try:
                from warden.brain.evolve import EvolutionEngine
                ok, reason = EvolutionEngine._validate_regex_safety(rule_data["regex_pattern"])
                if not ok:
                    raise ValueError(f"Unsafe regex pattern rejected: {reason}")
            except ImportError:
                log.warning("EvolutionEngine not available; regex safety check skipped")

        return _build_container("rule", rule_data, keypair, agent_id, community_id)

    def tokenize_model(
        self,
        model_data: dict,
        keypair: "CommunityKeypair",
        agent_id: str,
        community_id: str,
    ) -> dict:
        """Tokenize a Semantic Layer model (OSI 1.0 schema check).

        Raises ValueError if required OSI 1.0 fields are missing.
        """
        missing = _OSI_REQUIRED_FIELDS - set(model_data.keys())
        if missing:
            raise ValueError(f"model_data missing OSI 1.0 fields: {missing}")
        return _build_container("model", model_data, keypair, agent_id, community_id)

    def tokenize_signals(
        self,
        signals: list[dict],
        keypair: "CommunityKeypair",
        agent_id: str,
        community_id: str,
    ) -> dict:
        """Tokenize a batch of threat signal dicts."""
        payload = {
            "signals":    signals,
            "window_end": datetime.now(UTC).isoformat(),
            "count":      len(signals),
        }
        return _build_container("signals", payload, keypair, agent_id, community_id)
