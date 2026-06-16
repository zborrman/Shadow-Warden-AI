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
import os
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


def _sign_b64(keypair: CommunityKeypair, data: bytes) -> str:
    sig_bytes = keypair.sign(data)
    return base64.b64encode(sig_bytes).decode()


def _hsm_attest_b64(data: bytes) -> str:
    """Return an HSM attestation signature (base64) if HSM is active, else empty string."""
    try:
        from warden.crypto.hsm import get_signer
        signer = get_signer()
        if signer.is_available():
            return base64.b64encode(signer.sign(data)).decode()
    except Exception:
        pass
    return ""


def _pqc_sign_b64(keypair, data: bytes) -> str:
    """
    Return an ML-DSA-65 hybrid signature (base64) when PQC_ENABLED=true and
    the community keypair supports it, else empty string.
    """
    if os.getenv("PQC_ENABLED", "false").lower() != "true":
        return ""
    try:
        from warden.crypto.pqc import is_pqc_available
        if not is_pqc_available():
            return ""
        if not getattr(keypair, "is_hybrid", False):
            return ""
        sig_bytes = keypair.hybrid_sign(data)
        return base64.b64encode(sig_bytes).decode()
    except Exception:
        return ""


def verify_asset_signature(container: dict, keypair=None) -> bool:
    """
    Verify container signatures.

    - Always checks Ed25519 `signature` against `signer_public_key`.
    - If `pqc_signature` is present and PQC_ENABLED=true, also verifies ML-DSA-65.
    - At least one valid signature is required for success.
    """
    sha256_hex = container.get("sha256", "")
    if not sha256_hex:
        return False
    data = sha256_hex.encode()

    # Ed25519 verification
    ed25519_ok = False
    try:
        pub_b64 = container.get("signer_public_key", "")
        sig_b64 = container.get("signature", "")
        if pub_b64 and sig_b64:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
            pub.verify(base64.b64decode(sig_b64), data)
            ed25519_ok = True
    except Exception:
        pass

    # PQC verification (optional — only if both field and env flag present)
    pqc_ok = False
    pqc_sig = container.get("pqc_signature", "")
    if pqc_sig and os.getenv("PQC_ENABLED", "false").lower() == "true":
        try:
            from warden.crypto.pqc import is_pqc_available
            if keypair and getattr(keypair, "is_hybrid", False) and is_pqc_available():
                sig_bytes = base64.b64decode(pqc_sig)
                keypair.hybrid_verify(data, sig_bytes)
                pqc_ok = True
        except Exception:
            pass

    return ed25519_ok or pqc_ok


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
    keypair: CommunityKeypair,
    agent_id: str,
    community_id: str,
) -> dict:
    from warden.communities.sep import new_ueciid
    _, ueciid = new_ueciid()

    canonical = _canonical_json(payload)
    sha256 = _sha256_hex(canonical)
    sig_data = sha256.encode()
    signature = _sign_b64(keypair, sig_data)
    hsm_attestation = _hsm_attest_b64(sig_data)
    pqc_signature = _pqc_sign_b64(keypair, sig_data)
    ipfs_hash = _upload_ipfs(payload)

    return {
        "ueciid":           ueciid,
        "asset_type":       asset_type,
        "sha256":           sha256,
        "signature":        signature,
        "signer_public_key": keypair.ed25519_pub_b64,
        "hsm_attestation":  hsm_attestation,
        "pqc_signature":    pqc_signature,
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
        keypair: CommunityKeypair,
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
        keypair: CommunityKeypair,
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
        keypair: CommunityKeypair,
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
