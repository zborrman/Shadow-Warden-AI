"""
warden/compliance/evidence_bundle.py  (TC-04)
──────────────────────────────────────────────
SOC 2 Type II Evidence Bundle generator.

Collects:
  1. STIX 2.1 audit chain export (last 12 months)
  2. Compliance posture snapshot (all frameworks + gaps)
  3. Employee training records for the tenant
  4. Vendor DPA report for all AI subprocessors
  5. ISO 27001:2022 control report (if available)

Bundles everything into a ZIP, uploads to MinIO evidence vault, and
returns a presigned download URL (1-hour TTL).

Usage
-----
    from warden.compliance.evidence_bundle import generate_evidence_bundle
    result = await generate_evidence_bundle(tenant_id="acme")
    # result["url"]  → presigned download URL
    # result["key"]  → MinIO object key
    # result["size"] → bytes
"""
from __future__ import annotations

import io
import json
import logging
import os
import zipfile
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger("warden.compliance.evidence_bundle")

_SEP_DB_PATH      = os.getenv("SEP_DB_PATH", "/tmp/warden_sep.db")
_VENDOR_DB_PATH   = os.getenv("VENDOR_GOV_DB_PATH", "/tmp/warden_vendor_gov.db")
_TRAINING_DB_PATH = os.getenv("TRAINING_RECORDS_DB_PATH", "/tmp/warden_training.db")
_LOGS_PATH        = os.getenv("LOGS_PATH", "data/logs.json")


# ── Data collectors ────────────────────────────────────────────────────────────

def _collect_stix_chain(community_id: str) -> list[dict[str, Any]]:
    try:
        import sqlite3
        con = sqlite3.connect(_SEP_DB_PATH)
        rows = con.execute(
            "SELECT bundle_json FROM sep_stix_chain WHERE community_id=? ORDER BY seq",
            (community_id,),
        ).fetchall()
        con.close()
        return [json.loads(r[0]) for r in rows]
    except Exception as exc:
        log.warning("STIX chain collect failed: %s", exc)
        return []


def _collect_posture(tenant_id: str) -> dict[str, Any]:
    try:
        from warden.compliance.posture_service import CompliancePostureService  # noqa: PLC0415
        svc = CompliancePostureService()
        import asyncio
        report = asyncio.get_event_loop().run_until_complete(
            svc.get_posture(tenant_id)
        ) if not hasattr(asyncio, "_get_running_loop") else svc._compute_posture_sync(tenant_id)
        return report.__dict__ if hasattr(report, "__dict__") else {}
    except Exception as exc:
        log.warning("Posture collect failed: %s", exc)
        return {"error": str(exc)}


def _collect_posture_sync(tenant_id: str) -> dict[str, Any]:
    try:
        import asyncio  # noqa: PLC0415

        from warden.compliance.posture_service import CompliancePostureService  # noqa: PLC0415
        svc = CompliancePostureService()
        loop = asyncio.new_event_loop()
        try:
            report = loop.run_until_complete(svc.get_posture(tenant_id))
        finally:
            loop.close()
        if hasattr(report, "model_dump"):
            return report.model_dump()
        return {"frameworks": getattr(report, "frameworks", {}), "overall_score": getattr(report, "overall_score", 0)}
    except Exception as exc:
        log.warning("Posture collect failed: %s", exc)
        return {"error": str(exc)}


def _collect_training(tenant_id: str) -> list[dict[str, Any]]:
    try:
        import sqlite3
        con = sqlite3.connect(_TRAINING_DB_PATH)
        rows = con.execute(
            "SELECT record_json FROM training_records WHERE tenant_id=? ORDER BY completed_at DESC",
            (tenant_id,),
        ).fetchall()
        con.close()
        return [json.loads(r[0]) for r in rows]
    except Exception as exc:
        log.warning("Training records collect failed: %s", exc)
        return []


def _collect_vendor_dpa(tenant_id: str) -> list[dict[str, Any]]:
    try:
        import sqlite3
        con = sqlite3.connect(_VENDOR_DB_PATH)
        rows = con.execute(
            "SELECT vendor_json FROM vendor_records WHERE tenant_id=? OR tenant_id IS NULL",
            (tenant_id,),
        ).fetchall()
        con.close()
        return [json.loads(r[0]) for r in rows]
    except Exception as exc:
        log.warning("Vendor DPA collect failed: %s", exc)
        return []


def _collect_iso27001_report() -> dict[str, Any]:
    try:
        from warden.api.compliance import _ISO27001_CONTROLS_V2  # noqa: PLC0415
        return {
            "standard": "ISO 27001:2022",
            "controls_count": len(_ISO27001_CONTROLS_V2),
            "controls": [
                {"id": c[0], "theme": c[1], "domain": c[2], "status": c[3], "evidence": c[4]}
                for c in _ISO27001_CONTROLS_V2
            ],
        }
    except Exception as exc:
        log.warning("ISO 27001 report failed: %s", exc)
        return {"error": str(exc)}


# ── Bundle builder ──────────────────────────────────────────────────────────────

async def generate_evidence_bundle(tenant_id: str) -> dict[str, Any]:
    """Generate a SOC 2 Type II evidence bundle ZIP and upload to MinIO.

    Returns
    -------
    {"url": str, "key": str, "size": int, "generated_at": str}
    """
    now      = datetime.now(UTC)
    date_str = now.strftime("%Y-%m-%d")
    key      = f"warden-evidence/soc2-bundles/{tenant_id}/SOC2_Evidence_{tenant_id}_{date_str}.zip"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # 1. STIX audit chain
        stix = _collect_stix_chain(tenant_id)
        zf.writestr(
            "stix_audit_chain.jsonl",
            "\n".join(json.dumps(b, ensure_ascii=False) for b in stix) or "[]",
        )

        # 2. Compliance posture snapshot
        posture = _collect_posture_sync(tenant_id)
        zf.writestr("compliance_posture.json", json.dumps(posture, indent=2, default=str))

        # 3. Training records
        training = _collect_training(tenant_id)
        zf.writestr("training_records.json", json.dumps(training, indent=2, default=str))

        # 4. Vendor DPA report
        vendors = _collect_vendor_dpa(tenant_id)
        zf.writestr("vendor_dpa_report.json", json.dumps(vendors, indent=2, default=str))

        # 5. ISO 27001 control report
        iso = _collect_iso27001_report()
        zf.writestr("iso27001_controls.json", json.dumps(iso, indent=2, default=str))

        # 6. Manifest
        manifest = {
            "tenant_id":    tenant_id,
            "generated_at": now.isoformat(),
            "contents": [
                "stix_audit_chain.jsonl",
                "compliance_posture.json",
                "training_records.json",
                "vendor_dpa_report.json",
                "iso27001_controls.json",
            ],
            "version": "SOC2-Bundle-v1",
        }
        zf.writestr("MANIFEST.json", json.dumps(manifest, indent=2))

    size    = buf.tell()
    buf.seek(0)
    zip_bytes = buf.read()

    # Upload to MinIO / S3
    url = await _upload_to_minio(key, zip_bytes)

    return {"url": url, "key": key, "size": size, "generated_at": now.isoformat()}


async def _upload_to_minio(key: str, data: bytes) -> str:
    """Upload bytes to MinIO and return a presigned URL (1-hour TTL)."""
    try:
        from warden.storage.s3 import S3Storage  # noqa: PLC0415
        storage = S3Storage()
        await storage.put_object(key, data, content_type="application/zip")
        url = await storage.presign_url(key, expires_in=3600)
        return url
    except Exception as exc:
        log.warning("MinIO upload failed (%s); returning local path", exc)
        # Fallback: save locally
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip", prefix="soc2_") as f:
            f.write(data)
            return f"file://{f.name}"
