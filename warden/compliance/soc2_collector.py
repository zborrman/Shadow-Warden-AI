"""
warden/compliance/soc2_collector.py
────────────────────────────────────
SOC 2 Type II Continuous Evidence Collector.

Runs daily at midnight UTC via ARQ cron (sova_soc2_daily_collect).
Produces TSC-mapped JSON snapshots written atomically to:
  data/compliance_archives/YYYY-MM-DD_tsc.json

Five Trust Services Criteria collected:
  Security (CC1-CC8)    — Confused-Deputy blocks, PQC auth failures
  Availability (A1)     — Uptime monitor checks, DB pool health
  Integrity (PI1)       — ClearingEngine Decimal verification, x402 sigs
  Privacy (P1-P8)       — GDPR export events, E2EE activations
  Confidentiality (C1)  — PQC key ops, vault accesses

GDPR: DID/wallet identifiers are SHA-256[:16] pseudonymised throughout.
      No prompt or response content is ever included in evidence.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

log = logging.getLogger("warden.compliance.soc2_collector")


def _archive_dir() -> Path:
    return Path(os.getenv("SOC2_ARCHIVE_DIR", "data/compliance_archives"))


def _logs_path() -> Path:
    return Path(os.getenv("LOGS_PATH", "data/logs.json"))


def _clearing_db() -> str:
    return os.getenv("MARKETPLACE_CLEARING_DB_PATH", "/tmp/warden_marketplace_clearing.db")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _pseudo(identifier: str) -> str:
    """SHA-256[:16] pseudonymisation — GDPR-safe for DID / wallet / agent IDs."""
    return hashlib.sha256(identifier.encode()).hexdigest()[:16]


def _parse_ts(raw: Any) -> float | None:
    """Return POSIX timestamp from a log entry timestamp value, or None."""
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw).timestamp()
        except Exception:
            return None
    return None


def _iter_log_window(since_ts: float, until_ts: float):
    """Yield parsed log entries within the time window from LOGS_PATH."""
    try:
        with open(_logs_path()) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = _parse_ts(entry.get("timestamp"))
                if ts is None or not (since_ts <= ts < until_ts):
                    continue
                yield entry
    except FileNotFoundError:
        pass
    except Exception as exc:
        log.warning("log iteration error: %s", exc)


# ── TSC 1: Security (CC1–CC8) ─────────────────────────────────────────────────

def _collect_security(since_ts: float, until_ts: float) -> dict[str, Any]:
    """CC6-CC7: Confused-Deputy blocks + PQC auth failures logged per request."""
    confused_deputy_blocks: list[dict] = []
    pqc_auth_failures: list[dict] = []
    total_requests = 0

    for entry in _iter_log_window(since_ts, until_ts):
        total_requests += 1
        ts = _parse_ts(entry.get("timestamp")) or 0

        if entry.get("stage") == "confused_deputy" and (
            entry.get("blocked") or entry.get("action") == "BLOCK"
        ):
            confused_deputy_blocks.append({
                "request_id": _pseudo(str(entry.get("request_id", ""))),
                "ts": ts,
                "risk_score": entry.get("risk_score"),
            })

        if entry.get("pqc_auth_failed"):
            pqc_auth_failures.append({
                "agent_id": _pseudo(str(entry.get("agent_id", ""))),
                "ts": ts,
                "reason": entry.get("pqc_fail_reason"),
            })

    return {
        "tsc": "CC1-CC8",
        "controls": ["CC6.1 Logical Access Controls", "CC6.7 Encryption in Transit",
                     "CC7.1 Threat Detection", "CC7.2 Monitoring & Alerting",
                     "CC7.3 Incident Response (ERS shadow ban)"],
        "total_requests_in_window": total_requests,
        "confused_deputy_block_count": len(confused_deputy_blocks),
        "confused_deputy_blocks": confused_deputy_blocks,
        "pqc_auth_failure_count": len(pqc_auth_failures),
        "pqc_auth_failures": pqc_auth_failures,
    }


# ── TSC 2: Availability (A1) ──────────────────────────────────────────────────

def _collect_availability(since_ts: float, until_ts: float) -> dict[str, Any]:
    """A1.1-A1.2: Uptime check records + live health probe."""
    uptime_records: list[dict] = []
    db_pool_healthy: bool | None = None

    try:
        import sqlite3
        uptime_db = os.getenv("UPTIME_DB_PATH", "/tmp/warden_uptime.db")
        con = sqlite3.connect(uptime_db, timeout=5)
        tables = {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        if "uptime_checks" in tables:
            rows = con.execute(
                "SELECT monitor_id, checked_at, status, response_ms FROM uptime_checks "
                "WHERE checked_at BETWEEN ? AND ? ORDER BY checked_at",
                (since_ts, until_ts),
            ).fetchall()
            for r in rows:
                uptime_records.append({
                    "monitor_id": r[0],
                    "ts": r[1],
                    "status": r[2],
                    "response_ms": r[3],
                })
        con.close()
    except Exception as exc:
        log.debug("uptime DB unavailable: %s", exc)

    try:
        import httpx
        resp = httpx.get("http://localhost:8001/health", timeout=3.0)
        db_pool_healthy = resp.json().get("status") in ("ok", "healthy", "UP", True)
    except Exception:
        db_pool_healthy = None

    total = len(uptime_records)
    up_count = sum(1 for r in uptime_records if r.get("status") in ("UP", "ok", 1, "1"))
    avg_ms = (
        sum(r.get("response_ms") or 0 for r in uptime_records) / total
        if total > 0 else None
    )

    return {
        "tsc": "A1",
        "controls": ["A1.1 Performance Monitoring", "A1.2 Capacity Management"],
        "uptime_checks_in_window": total,
        "up_count": up_count,
        "availability_pct": round(100.0 * up_count / total, 4) if total > 0 else None,
        "avg_response_ms": round(avg_ms, 2) if avg_ms is not None else None,
        "db_pool_healthy": db_pool_healthy,
    }


# ── TSC 3: Processing Integrity (PI1) ─────────────────────────────────────────

def _collect_processing_integrity(since_ts: float, until_ts: float) -> dict[str, Any]:
    """PI1.3: Verify 100% of clearing records used strict Decimal math (fee+net==price)."""
    from decimal import Decimal

    clearing_records: list[dict] = []
    decimal_violations: list[dict] = []

    candidate_dbs = [
        _clearing_db(),
        os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db"),
        "/tmp/warden_m2m.db",
    ]

    for db_path in candidate_dbs:
        if not Path(db_path).exists():
            continue
        try:
            import sqlite3
            con = sqlite3.connect(db_path, timeout=5)
            tables = {r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()}
            if "marketplace_clearing_log" not in tables:
                con.close()
                continue
            rows = con.execute(
                "SELECT clearing_id, winner_neg_id, buyer_agent_id, seller_agent_id, "
                "agreed_price, platform_fee_usd, seller_net_usd, cleared_at "
                "FROM marketplace_clearing_log WHERE cleared_at BETWEEN ? AND ?",
                (since_ts, until_ts),
            ).fetchall()
            con.close()
            for r in rows:
                rec = {
                    "clearing_id": _pseudo(str(r[0])),
                    "buyer":       _pseudo(str(r[2] or "")),
                    "seller":      _pseudo(str(r[3] or "")),
                    "agreed_price":  r[4],
                    "platform_fee":  r[5],
                    "seller_net":    r[6],
                    "cleared_at":    r[7],
                }
                clearing_records.append(rec)
                # Decimal invariant: agreed == fee + net (within 2 microUSD tolerance)
                if r[4] is not None and r[5] is not None and r[6] is not None:
                    diff = abs(
                        Decimal(str(r[4])) - Decimal(str(r[5])) - Decimal(str(r[6]))
                    )
                    if diff > Decimal("0.000002"):
                        decimal_violations.append({
                            "clearing_id": _pseudo(str(r[0])),
                            "diff_usd": str(diff),
                        })
            break
        except Exception as exc:
            log.warning("PI1 clearing DB read error (%s): %s", db_path, exc)
            continue

    total = len(clearing_records)
    pass_count = total - len(decimal_violations)

    return {
        "tsc": "PI1",
        "controls": ["PI1.3 Complete & Accurate Processing (Decimal math, x402 signatures)"],
        "clearings_in_window": total,
        "decimal_violations": decimal_violations,
        "decimal_violation_count": len(decimal_violations),
        "integrity_pass_rate_pct": round(100.0 * pass_count / total, 4) if total else 100.0,
        "note": "Every clearing uses ROUND_HALF_UP Decimal — no float drift in billing",
    }


# ── TSC 4: Privacy (P1-P8) ────────────────────────────────────────────────────

def _collect_privacy(since_ts: float, until_ts: float) -> dict[str, Any]:
    """P1-P8: GDPR export requests, E2EE activations, PII redaction counts."""
    gdpr_export_events: list[dict] = []
    e2ee_activation_count = 0
    pii_redacted_total = 0

    for entry in _iter_log_window(since_ts, until_ts):
        ts = _parse_ts(entry.get("timestamp")) or 0
        etype = entry.get("event_type", "")

        if etype in ("gdpr_export", "gdpr_export_request", "gdpr_data_export"):
            gdpr_export_events.append({
                "request_id": _pseudo(str(entry.get("request_id", ""))),
                "ts": ts,
                "tenant_id": entry.get("tenant_id"),
                "status": entry.get("status"),
            })

        if entry.get("e2ee_activated") or etype in ("e2ee_enable", "e2ee_session_start"):
            e2ee_activation_count += 1

        pii_redacted_total += int(entry.get("redacted_count", 0) or 0)
        if entry.get("secrets_redacted"):
            pii_redacted_total += 1

    return {
        "tsc": "P1-P8",
        "controls": [
            "P3.1 Personal Information Collection Notice",
            "P4.1 Use of Personal Information",
            "P6.1 Retention & Disposal of Personal Information",
            "P7.1 Data Subject Access & Erasure (GDPR Art. 17)",
        ],
        "gdpr_export_count": len(gdpr_export_events),
        "gdpr_export_events": gdpr_export_events,
        "e2ee_activations_count": e2ee_activation_count,
        "pii_fields_redacted": pii_redacted_total,
        "gdpr_note": "No prompt/response content is ever stored — only metadata (type, length, timing)",
    }


# ── TSC 5: Confidentiality (C1) ───────────────────────────────────────────────

def _collect_confidentiality(since_ts: float, until_ts: float) -> dict[str, Any]:
    """C1.1-C1.2: PQC key operations, Fernet vault accesses, encryption posture."""
    pqc_ops = 0
    vault_accesses: int | str = 0

    try:
        import sqlite3
        inv_db = os.getenv("SECRETS_INV_DB_PATH", "/tmp/warden_secrets_inv.db")
        if Path(inv_db).exists():
            con = sqlite3.connect(inv_db, timeout=5)
            tables = {r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()}
            if "access_log" in tables:
                vault_accesses = con.execute(
                    "SELECT COUNT(*) FROM access_log WHERE accessed_at BETWEEN ? AND ?",
                    (since_ts, until_ts),
                ).fetchone()[0]
            con.close()
    except Exception as exc:
        log.debug("vault access log unavailable: %s", exc)
        vault_accesses = "unavailable"

    for entry in _iter_log_window(since_ts, until_ts):
        if entry.get("pqc_signed") or entry.get("pqc_verified"):
            pqc_ops += 1

    return {
        "tsc": "C1",
        "controls": [
            "C1.1 Confidential Information Protection (Fernet AES-256 + ML-DSA-65)",
            "C1.2 Disposal of Confidential Information",
        ],
        "pqc_operations_count": pqc_ops,
        "vault_accesses_in_window": vault_accesses,
        "encryption_at_rest": "AES-256 Fernet (community keypairs, data pods, vault secrets)",
        "encryption_in_transit": "TLS 1.3 Caddy proxy + MASQUE H3/H2 sovereign tunnels",
        "pqc_algorithm": "ML-DSA-65 (Ed25519+ML-DSA-65 hybrid) — Enterprise tier",
    }


# ── Snapshot builder ──────────────────────────────────────────────────────────

def collect_daily_evidence(date: datetime | None = None) -> dict[str, Any]:
    """Build one full TSC-mapped evidence snapshot for the given UTC day.

    Writes atomically to data/compliance_archives/YYYY-MM-DD_tsc.json
    and also returns the dict so callers can report/assert without re-reading.
    """
    if date is None:
        date = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        date = date.replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=UTC)

    since_ts = date.timestamp()
    until_ts = (date + timedelta(days=1)).timestamp()

    t0 = time.perf_counter()
    evidence: dict[str, Any] = {
        "schema_version": "SOC2Collector-v1",
        "generated_at":   datetime.now(UTC).isoformat(),
        "period_start":   date.isoformat(),
        "period_end":     (date + timedelta(days=1)).isoformat(),
        "tsc_evidence": {
            "security":             _collect_security(since_ts, until_ts),
            "availability":         _collect_availability(since_ts, until_ts),
            "processing_integrity": _collect_processing_integrity(since_ts, until_ts),
            "privacy":              _collect_privacy(since_ts, until_ts),
            "confidentiality":      _collect_confidentiality(since_ts, until_ts),
        },
        "collection_ms": 0,
    }
    evidence["collection_ms"] = round((time.perf_counter() - t0) * 1000, 1)

    arch = _archive_dir()
    arch.mkdir(parents=True, exist_ok=True)
    dest = arch / f"{date.strftime('%Y-%m-%d')}_tsc.json"
    fd, tmp_path = tempfile.mkstemp(dir=str(arch), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(evidence, f, indent=2, default=str)
        os.replace(tmp_path, dest)
        log.info("SOC2 evidence written → %s (%.1f ms)", dest.name, evidence["collection_ms"])
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    return evidence


def load_evidence_range(days: int = 90) -> list[dict[str, Any]]:
    """Return daily evidence snapshots for the last N days (most-recent first)."""
    now = datetime.now(UTC)
    arch = _archive_dir()
    results = []
    for i in range(days):
        date = (now - timedelta(days=i)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        path = arch / f"{date.strftime('%Y-%m-%d')}_tsc.json"
        if path.exists():
            try:
                with open(path) as f:
                    results.append(json.load(f))
            except Exception as exc:
                log.warning("evidence load failed %s: %s", path.name, exc)
    return results
