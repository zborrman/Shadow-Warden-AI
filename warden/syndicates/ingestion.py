"""
warden/syndicates/ingestion.py
──────────────────────────────
Pre-flight pipeline for documents and prompts sent through Zero-Trust Tunnels.

Two-stage "Double Shield" before any content leaves the source gateway:

  Stage 1 — RAG Worm Guard (Security)
      Scans the document for hidden RAG-poisoning instructions, prompt
      injection chains, and AI-worm replication payloads.  A poisoned
      document is rejected before it ever reaches the encryption step.

  Stage 2 — PII Masking (Privacy)
      Replaces all detected PII (names, emails, phone numbers, monetary
      amounts, IDs, organisations) with deterministic tokens:
          "Invoice for John Doe ($50k)"  →  "Invoice for [PERSON_1] ([MONEY_1])"
      The original values are stored in a per-session vault.
      The session_id is returned so the caller can later unmask the LLM
      response from the receiving gateway.

On the receiving side (see router.py / receive_document):

  Stage 3 — Decrypt + WormGuard (Receiving side)
      The receiving gateway decrypts the payload and re-runs its own
      WormGuard scan — the sending side is trusted, but we apply
      "Trust, but Verify" in case the sender's guard was bypassed.
      If a worm is detected, the tunnel is immediately revoked (Kill-Switch).

Data flow
─────────
  [raw document]
      → Stage 1: inspect_for_ingestion()   (worm_guard)
      → Stage 2: engine.mask()             (masking.engine)
      → [masked_text + session_id]
      → TunnelCrypto.encrypt(masked_text)  (caller)
      → [encrypted envelope]
      → HTTP POST to peer /tunnels/receive
"""
from __future__ import annotations

import logging
import uuid

log = logging.getLogger("warden.syndicates.ingestion")


class TunnelIngestionError(Exception):
    """Raised when a document is blocked before entering the tunnel."""

    def __init__(self, reason: str, stage: str) -> None:
        self.reason = reason
        self.stage  = stage
        super().__init__(f"[{stage}] {reason}")


def prepare_for_tunnel(
    content: str,
    tunnel_id: str,
    session_id: str | None = None,
) -> tuple[str, str]:
    """
    Run the full pre-flight pipeline and return (masked_text, session_id).

    Parameters
    ----------
    content     : Raw document or prompt text to be sent through the tunnel.
    tunnel_id   : UUID of the active tunnel (for logging).
    session_id  : Optional caller-supplied session ID.  Auto-generated if None.
                  Pass the same session_id to unmask the response later.

    Returns
    -------
    (masked_text, session_id)
        masked_text  — PII-replaced text safe to encrypt and transmit.
        session_id   — Pass to masking_engine.unmask() to reverse tokens in
                       the response received back from the peer gateway.

    Raises
    ------
    TunnelIngestionError  — document blocked at Stage 1 (worm) or
                            Stage 2 (masking failure).
    """
    if not session_id:
        session_id = f"tunnel-{tunnel_id}-{uuid.uuid4().hex[:8]}"

    # ── Stage 1: RAG Worm Guard ─────────────────────���─────────────────────────
    try:
        from warden.worm_guard import inspect_for_ingestion
        result = inspect_for_ingestion(content)
        if result.is_poisoned:
            log.warning(
                "Tunnel ingestion blocked (worm): tunnel=%s reason=%s",
                tunnel_id, result.reason,
            )
            raise TunnelIngestionError(
                reason=f"RAG poisoning attempt detected: {result.reason}",
                stage="WormGuard",
            )
    except TunnelIngestionError:
        raise
    except ImportError:
        log.debug("worm_guard not available — skipping Stage 1 scan")
    except Exception as exc:
        # WormGuard errors are fail-open — don't block valid documents
        log.warning("WormGuard scan error (fail-open): tunnel=%s error=%s", tunnel_id, exc)

    # ── Stage 2: PII Masking ──────────────────────────────���───────────────────
    try:
        from warden.masking.engine import get_engine
        engine = get_engine()
        mask_result = engine.mask(content, session_id=session_id)
        masked_text = mask_result.masked

        if mask_result.has_entities:
            log.info(
                "Tunnel ingestion masked %d entities: tunnel=%s session=%s types=%s",
                mask_result.entity_count,
                tunnel_id,
                session_id,
                mask_result.summary(),
            )
        else:
            masked_text = content  # no PII found, pass through as-is

    except TunnelIngestionError:
        raise
    except Exception as exc:
        log.error(
            "Masking engine error: tunnel=%s error=%s — sending unmasked (fail-open)",
            tunnel_id, exc,
        )
        masked_text = content  # fail-open: transmit original if masking fails

    return masked_text, session_id


def unmask_response(
    response_text: str,
    session_id: str,
    tunnel_id: str,
) -> str:
    """
    Reverse PII tokens in the peer gateway's response.

    Called by Platform A after receiving and decrypting Platform B's response.
    Uses the same session_id that was returned by prepare_for_tunnel().

    Parameters
    ----------
    response_text : Decrypted response from Platform B (may contain [PERSON_1] etc.)
    session_id    : Session ID returned by prepare_for_tunnel().
    tunnel_id     : UUID of the tunnel (for logging).

    Returns
    -------
    Original plaintext with all tokens replaced by their real values.
    Falls back to response_text unchanged if unmasking fails.
    """
    try:
        from warden.masking.engine import get_engine
        engine = get_engine()
        return engine.unmask(response_text, session_id=session_id)
    except Exception as exc:
        log.error(
            "Unmask failed: tunnel=%s session=%s error=%s — returning masked response",
            tunnel_id, session_id, exc,
        )
        return response_text


def scan_received_document(content: str, tunnel_id: str) -> None:
    """
    Stage 3 (receiver-side): re-run WormGuard on decrypted incoming content.

    Even though the sender's gateway should have scanned before transmitting,
    we apply "Trust, but Verify" in case the sender was compromised.

    Raises
    ------
    TunnelIngestionError  — worm detected; caller must revoke the tunnel.
    """
    try:
        from warden.worm_guard import inspect_for_ingestion
        result = inspect_for_ingestion(content)
        if result.is_poisoned:
            log.critical(
                "WORM DETECTED in tunnel receive: tunnel=%s reason=%s — revoking",
                tunnel_id, result.reason,
            )
            raise TunnelIngestionError(
                reason=f"AI worm detected in received payload: {result.reason}",
                stage="ReceiverWormGuard",
            )
    except TunnelIngestionError:
        raise
    except ImportError:
        log.debug("worm_guard not available — skipping receiver-side Stage 3 scan")
    except Exception as exc:
        log.warning("Receiver WormGuard error (fail-open): tunnel=%s error=%s", tunnel_id, exc)
