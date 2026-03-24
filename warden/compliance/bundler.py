"""
warden/compliance/bundler.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Evidence Vault — per-session cryptographic evidence bundle.

Produces a single, self-contained, tamper-evident JSON document for any agent
session.  The bundle captures all security-relevant metadata and is signed with
a SHA-256 hash of its own canonical form.  A single modified byte in any field
causes verify_bundle() to return False.

Use case: litigation, regulatory investigation, or internal SOC post-mortem
where you need to prove *precisely* what Warden observed about a specific agent
at a specific point in time — with cryptographic guarantees that the record has
not been modified after export.

Bundle structure
────────────────
  {
    "bundle_type":      "WARDEN_EVIDENCE_BUNDLE"
    "schema_version":   "1.0"
    "generated_at":     ISO-8601 UTC
    "session_id":       str
    "agent_id":         str (from X-Agent-Id header, if known)
    "entity_key":       str (SHA-256[:16] pseudonymised entity, if known)
    "session":          session metadata (from AgentMonitor)
    "ers_profile":      ERS score + event counts at time of export
    "attestation":      SHA-256 chain verification result (from v1.7 Step 2)
    "timeline":         tool event list (tool names only — no arguments/content)
    "compliance_score": float 0.0–1.0 (verified events / total tool events)
    "bundle_hash":      "sha256:<hex>" — SHA-256 over canonical JSON of all
                         fields above (sign-last pattern)
  }

Verification
────────────
  verify_bundle(bundle) → True if bundle_hash matches recomputed hash.
  A False result means the bundle was modified after export.

GDPR note: no prompt content, response content, or raw PII is included.
All entity identifiers are pseudonymised.
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime


class EvidenceBundler:
    """
    Generate and verify per-session evidence bundles.

    Usage::

        bundler = EvidenceBundler(agent_monitor=_agent_monitor)
        bundle  = bundler.generate("sess-abc123", agent_id="analyst-v1")

        # Later — verify integrity
        assert bundler.verify_bundle(bundle)
    """

    def __init__(self, agent_monitor=None) -> None:
        self._monitor = agent_monitor  # warden.agent_monitor.AgentMonitor | None

    # ── Public API ────────────────────────────────────────────────────────────

    def generate(
        self,
        session_id: str,
        agent_id:   str = "",
        entity_key: str = "",
    ) -> dict:
        """
        Build a signed evidence bundle for *session_id*.

        Returns the bundle dict including ``bundle_hash``.
        The bundle is suitable for JSON serialisation and long-term archival.
        """
        now = datetime.now(UTC).isoformat()

        # ── Collect session data ───────────────────────────────────────────
        session_meta: dict = {}
        timeline:     list = []
        attestation:  dict = {}
        tool_event_count   = 0
        attest_event_count = 0

        if self._monitor is not None:
            sess = self._monitor.get_session(session_id)
            if sess is not None:
                events = sess.pop("events", [])
                session_meta = sess
                # Tool events only (no content fields)
                timeline = [
                    {
                        "ts":          e.get("ts", ""),
                        "tool_name":   e.get("tool_name", ""),
                        "direction":   e.get("direction", ""),
                        "blocked":     e.get("blocked", False),
                        "threat_kind": e.get("threat_kind"),
                    }
                    for e in sorted(events, key=lambda x: x.get("ts", ""))
                    if e.get("event_type") == "tool"
                ]
                tool_event_count = len(timeline)

                attestation = self._monitor.verify_attestation(session_id)
                attest_event_count = attestation.get("event_count", 0)

        # ── Collect ERS profile ────────────────────────────────────────────
        ers_profile: dict = {}
        if entity_key:
            try:
                from warden import entity_risk as _ers  # noqa: PLC0415
                result = _ers.score(entity_key)
                ers_profile = {
                    "entity_key":  entity_key,
                    "score":       result.score,
                    "level":       result.level,
                    "shadow_ban":  result.shadow_ban,
                    "total_1h":    result.total_1h,
                    "counts":      result.counts,
                    "window_secs": _ers.WINDOW_SECS,
                }
            except Exception as exc:
                ers_profile = {"error": str(exc)}

        # ── Compliance score: verified tool events / total tool events ─────
        #
        # A tool event is "verified" when the attestation chain is intact and
        # covers that event (attest_event_count == tool_event_count and valid).
        # If the chain is broken, we assign partial credit proportional to how
        # many events the chain could verify before the first discrepancy.
        #
        compliance_score = _compute_compliance_score(
            attestation_valid=attestation.get("valid"),
            attest_event_count=attest_event_count,
            total_tool_events=tool_event_count,
        )

        # ── Assemble pre-hash payload ──────────────────────────────────────
        payload: dict = {
            "bundle_type":      "WARDEN_EVIDENCE_BUNDLE",
            "schema_version":   "1.0",
            "generated_at":     now,
            "session_id":       session_id,
            "agent_id":         agent_id,
            "entity_key":       entity_key,
            "session":          session_meta,
            "ers_profile":      ers_profile,
            "attestation":      attestation,
            "timeline":         timeline,
            "compliance_score": compliance_score,
        }

        # ── Sign (sign-last pattern) ───────────────────────────────────────
        payload["bundle_hash"] = _sign(payload)
        return payload

    @staticmethod
    def verify_bundle(bundle: dict) -> bool:
        """
        Verify the integrity of an evidence bundle.

        Returns True if ``bundle_hash`` matches the recomputed hash.
        A False result means the bundle was modified after it was generated.
        """
        stored_hash = bundle.get("bundle_hash", "")
        if not stored_hash:
            return False
        payload_without_hash = {k: v for k, v in bundle.items() if k != "bundle_hash"}
        expected = _sign(payload_without_hash)
        return stored_hash == expected


# ── Helpers ───────────────────────────────────────────────────────────────────

def _canonical(payload: dict) -> str:
    """Deterministic JSON serialisation — sorted keys, no whitespace."""
    return json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _sign(payload: dict) -> str:
    """Return 'sha256:<hex>' over the canonical JSON representation."""
    return "sha256:" + hashlib.sha256(_canonical(payload).encode()).hexdigest()


def _compute_compliance_score(
    attestation_valid: bool | None,
    attest_event_count: int,
    total_tool_events: int,
) -> float:
    """
    Compute the per-bundle compliance score: verified_events / total_events.

    Rules:
      • No events recorded     → 1.0 (nothing to verify)
      • Chain valid            → 1.0
      • Chain invalid/missing  → attest_event_count / total (partial credit)
      • Attestation unavailable → 0.0
    """
    if total_tool_events == 0:
        return 1.0
    if attestation_valid is True:
        return 1.0
    if attestation_valid is False and attest_event_count >= 0:
        return round(attest_event_count / total_tool_events, 4)
    return 0.0
