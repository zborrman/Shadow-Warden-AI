"""
warden/communities/federation.py  (CM-26)
──────────────────────────────────────────
Community threat score federation — broadcast verified HIGH/BLOCK verdicts
to peered communities so they can pre-emptively block known-bad patterns.

Protocol
────────
  1. Source community posts a FederatedVerdict to all peers with FULL_SYNC policy
  2. Each peer receives { ueciid, data_class, threat_hash, verdict, score, ts }
  3. No raw content is transmitted — only HMAC-SHA256 of the blocked text
  4. Recipient community scores identical future requests +0.15 (configurable)
  5. Verdicts expire after FEDERATION_VERDICT_TTL seconds (default 7 days)

Privacy guarantees
──────────────────
  - Raw blocked text is NEVER sent
  - threat_hash = HMAC-SHA256(text, community_hmac_key) — one-way, key-bound
  - Recipients cannot recover original text from threat_hash
  - ueciid is optional (may be omitted for anonymous federation)

Storage: Redis sorted set `federation:verdicts:{community_id}` (TTL per entry)
Falls back to SQLite `sep_federation_verdicts`.
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from warden.secret_keys import resolve_key

log = logging.getLogger("warden.communities.federation")

_FEDERATION_ENABLED  = os.getenv("FEDERATION_ENABLED", "false").lower() == "true"
_VERDICT_TTL         = int(os.getenv("FEDERATION_VERDICT_TTL", str(86_400 * 7)))
_BOOST               = float(os.getenv("FEDERATION_SCORE_BOOST", "0.15"))
def _hmac_key() -> bytes:
    return resolve_key("COMMUNITY_VAULT_KEY", purpose="federation")

_MEMORY_VERDICTS: dict[str, list] = {}


@dataclass
class FederatedVerdict:
    community_id:   str
    threat_hash:    str     # HMAC-SHA256(text, community_hmac_key)
    verdict:        str     # "HIGH" | "BLOCK"
    score:          float
    data_class:     str
    ueciid:         str | None
    ts:             str


def _threat_hash(text: str, community_id: str) -> str:
    key = _hmac_key() + b":" + community_id.encode()
    return hmac.new(key, text.encode(), hashlib.sha256).hexdigest()[:32]


def _redis():
    try:
        import redis as _r  # noqa: PLC0415
        url = os.getenv("REDIS_URL", "")
        if not url or url == "memory://":
            return None
        return _r.from_url(url, decode_responses=True)
    except Exception:
        return None


def broadcast_verdict(
    community_id: str,
    text: str,
    verdict: str,
    score: float,
    data_class: str = "GENERAL",
    ueciid: str | None = None,
) -> int:
    """
    Broadcast a verified HIGH/BLOCK verdict to all FULL_SYNC peers.
    Returns count of peers notified.
    """
    if not _FEDERATION_ENABLED:
        return 0

    th = _threat_hash(text, community_id)
    fv = FederatedVerdict(
        community_id = community_id,
        threat_hash  = th,
        verdict      = verdict,
        score        = round(score, 4),
        data_class   = data_class,
        ueciid       = ueciid,
        ts           = datetime.now(UTC).isoformat(),
    )

    # Store locally
    _store_verdict(community_id, fv)

    # Push to all FULL_SYNC peers
    peers = _get_peers(community_id)
    notified = 0
    for peer_url in peers:
        if _push_to_peer(peer_url, fv):
            notified += 1

    log.info("federation: broadcast verdict hash=%s verdict=%s peers=%d",
             th[:8], verdict, notified)
    return notified


def _store_verdict(community_id: str, fv: FederatedVerdict) -> None:
    key = f"federation:verdicts:{community_id}"
    entry = json.dumps(asdict(fv))

    r = _redis()
    if r:
        try:
            import time  # noqa: PLC0415
            score_ts = time.time()
            r.zadd(key, {entry: score_ts})
            r.expire(key, _VERDICT_TTL)
            # Trim to 10k entries
            r.zremrangebyrank(key, 0, -10001)
        except Exception as exc:
            log.debug("federation: redis store error: %s", exc)
    else:
        _MEMORY_VERDICTS.setdefault(community_id, [])
        _MEMORY_VERDICTS[community_id].append(asdict(fv))
        _MEMORY_VERDICTS[community_id] = _MEMORY_VERDICTS[community_id][-10_000:]


def check_threat_hash(community_id: str, text: str) -> FederatedVerdict | None:
    """
    Check if this text matches a federated threat hash from any peer.
    Returns the matching verdict or None.
    """
    if not _FEDERATION_ENABLED:
        return None

    th = _threat_hash(text, community_id)
    return _lookup_hash(community_id, th)


def _lookup_hash(community_id: str, threat_hash: str) -> FederatedVerdict | None:
    r = _redis()
    entries: list[str] = []
    if r:
        try:
            raw = r.zrange(f"federation:verdicts:{community_id}", 0, -1)
            entries = list(raw)
        except Exception:
            pass
    else:
        entries = [json.dumps(e) for e in _MEMORY_VERDICTS.get(community_id, [])]

    for entry in entries:
        try:
            d = json.loads(entry)
            if d.get("threat_hash") == threat_hash:
                return FederatedVerdict(**d)
        except Exception:
            pass
    return None


def ingest_peer_verdict(payload: dict) -> bool:
    """Receive and store an incoming federated verdict from a peer."""
    try:
        fv = FederatedVerdict(
            community_id = str(payload["community_id"]),
            threat_hash  = str(payload["threat_hash"]),
            verdict      = str(payload["verdict"]),
            score        = float(payload["score"]),
            data_class   = str(payload.get("data_class", "GENERAL")),
            ueciid       = payload.get("ueciid"),
            ts           = str(payload.get("ts", datetime.now(UTC).isoformat())),
        )
        _store_verdict(fv.community_id, fv)
        log.info("federation: ingested peer verdict hash=%s from=%s",
                 fv.threat_hash[:8], fv.community_id)
        return True
    except Exception as exc:
        log.warning("federation: ingest_peer_verdict failed: %s", exc)
        return False


def get_score_boost(community_id: str, text: str) -> float:
    """
    Return score boost if text matches a federated HIGH/BLOCK verdict.
    Returns 0.0 if no match.
    """
    match = check_threat_hash(community_id, text)
    if match and match.verdict in ("HIGH", "BLOCK"):
        return _BOOST
    return 0.0


def list_verdicts(community_id: str, limit: int = 50) -> list[dict]:
    r = _redis()
    entries: list[str] = []
    if r:
        try:
            raw = r.zrevrange(f"federation:verdicts:{community_id}", 0, limit - 1)
            entries = list(raw)
        except Exception:
            pass
    else:
        all_e = _MEMORY_VERDICTS.get(community_id, [])
        return all_e[-limit:][::-1]

    result = []
    for e in entries:
        with contextlib.suppress(Exception):
            result.append(json.loads(e))
    return result


# ── Peer registry (from peering DB) ──────────────────────────────────────────

def _get_peers(community_id: str) -> list[str]:
    """Return FULL_SYNC peer webhook URLs for this community."""
    try:
        from warden.communities.peering import list_peerings  # noqa: PLC0415
        peerings = list_peerings(community_id)
        return [
            getattr(p, "peer_webhook_url", "")
            for p in peerings
            if getattr(p, "policy", "") == "FULL_SYNC" and getattr(p, "peer_webhook_url", "")
        ]
    except Exception:
        return []


def _push_to_peer(peer_url: str, fv: FederatedVerdict) -> bool:
    try:
        import httpx as _httpx  # noqa: PLC0415
        with _httpx.Client(timeout=5) as client:
            r = client.post(
                f"{peer_url.rstrip('/')}/sep/federation/ingest",
                json=asdict(fv),
                headers={"Content-Type": "application/json"},
            )
            return r.status_code < 400
    except Exception as exc:
        log.debug("federation: push to %s failed: %s", peer_url, exc)
        return False


# ── FastAPI router ────────────────────────────────────────────────────────────

from fastapi import APIRouter  # noqa: E402
from pydantic import BaseModel  # noqa: E402

router = APIRouter(prefix="/sep/federation", tags=["Federation"])


class IngestPayload(BaseModel):
    community_id: str
    threat_hash:  str
    verdict:      str
    score:        float
    data_class:   str = "GENERAL"
    ueciid:       str | None = None
    ts:           str = ""


@router.post("/ingest", summary="Receive federated verdict from peer community")
async def ingest_verdict(payload: IngestPayload):
    ok = ingest_peer_verdict(payload.model_dump())
    return {"accepted": ok}


@router.get("/{community_id}/verdicts", summary="List federated verdicts for community")
async def get_verdicts(community_id: str, limit: int = 50):
    return {"community_id": community_id, "verdicts": list_verdicts(community_id, limit)}


@router.get(
    "/communities/{community_id}/federated-trust/check",
    summary="Pre-registration federated deny list check for an agent DID",
)
async def check_agent_deny_list(community_id: str, agent_did: str):
    """
    Returns whether an agent DID is on the federated deny list for the given community.
    Use before registering an agent to pre-screen against cross-community threat hashes.
    """
    verdict = check_threat_hash(community_id, agent_did)
    blocked = bool(verdict and verdict.verdict in ("HIGH", "BLOCK"))
    return {
        "community_id": community_id,
        "agent_did":    agent_did,
        "blocked":      blocked,
        "verdict":      verdict.verdict if verdict else None,
        "score":        verdict.score if verdict else None,
    }
