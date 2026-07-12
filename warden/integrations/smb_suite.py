"""
warden/integrations/smb_suite.py  (IN-25)
──────────────────────────────────────────
SMB AI Governance Suite — single-wizard provisioning of all 7 modules.

Provisions in order:
  1. Vendor Governance (BL-22)
  2. Budget cap (BL-24)
  3. Training program "AI Safety Basics" (CM-38)
  4. Incident register (CM-35) — verify schema only
  5. Prompt Library (CM-37) — verify schema only
  6. Supplier risk assessments for known vendors (CM-36)
  7. UECIID + STIX audit chain entry for the provisioning event

Tiers: Community Business+ (smb_suite_enabled)
"""
from __future__ import annotations

import logging
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from warden.config import data_path

log = logging.getLogger("warden.integrations.smb_suite")

_SEP_DB_PATH   = data_path("warden_sep.db", "SEP_DB_PATH")
_VENDOR_DB_PATH = data_path("warden_vendor.db", "VENDOR_GOV_DB_PATH")
_COST_DB_PATH  = data_path("warden_costs.db", "COST_ALLOC_DB_PATH")


@dataclass
class SMBProvisionResult:
    tenant_id:          str
    community_id:       str
    vendor_count:       int = 0
    budget_caps_set:    int = 0
    training_programs:  int = 0
    incident_register:  bool = False
    prompt_library:     bool = False
    supplier_risk:      bool = False
    ueciid:             str = ""
    stix_chain_id:      str = ""
    errors:             list[str] = field(default_factory=list)
    provisioned_at:     str = ""

    def to_dict(self) -> dict:
        return {
            "tenant_id":         self.tenant_id,
            "community_id":      self.community_id,
            "vendor_count":      self.vendor_count,
            "budget_caps_set":   self.budget_caps_set,
            "training_programs": self.training_programs,
            "incident_register": self.incident_register,
            "prompt_library":    self.prompt_library,
            "supplier_risk":     self.supplier_risk,
            "ueciid":            self.ueciid,
            "stix_chain_id":     self.stix_chain_id,
            "errors":            self.errors,
            "provisioned_at":    self.provisioned_at,
        }


def _assign_ueciid() -> str:
    try:
        from warden.communities.sep import new_ueciid
        _, ueciid = new_ueciid()
        return ueciid
    except Exception:
        return f"SMB-{uuid.uuid4().hex[:11].upper()}"


def _append_stix(ueciid: str, tenant_id: str, community_id: str) -> str:
    import hashlib
    import json
    try:
        con = sqlite3.connect(_SEP_DB_PATH, check_same_thread=False)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("""CREATE TABLE IF NOT EXISTS sep_stix_chain (
            entry_id   TEXT PRIMARY KEY,
            community_id TEXT NOT NULL DEFAULT '',
            bundle_json  TEXT NOT NULL,
            prev_hash    TEXT NOT NULL,
            seq          INTEGER NOT NULL DEFAULT 0,
            created_at   TEXT NOT NULL
        )""")
        con.commit()
        row = con.execute(
            "SELECT bundle_json, seq FROM sep_stix_chain WHERE community_id=? ORDER BY seq DESC LIMIT 1",
            (community_id,),
        ).fetchone()
        prev_hash = hashlib.sha256(row[0].encode()).hexdigest() if row else "0" * 64
        seq       = (row[1] + 1) if row else 1
        entry_id  = str(uuid.uuid4())
        now       = datetime.now(UTC).isoformat()
        bundle    = json.dumps({
            "type": "bundle", "id": f"bundle--{entry_id}",
            "spec_version": "2.1",
            "x-chain": {"prev_hash": prev_hash, "seq": seq},
            "objects": [{"type": "note", "id": f"note--{entry_id}",
                         "created": now, "modified": now,
                         "content": f"SMB Suite provisioned: tenant={tenant_id} community={community_id} ueciid={ueciid}",
                         "object_refs": [f"identity--{entry_id}"]}],
        }, separators=(",", ":"), sort_keys=True)
        con.execute(
            "INSERT INTO sep_stix_chain (entry_id, community_id, bundle_json, prev_hash, seq, created_at) VALUES (?,?,?,?,?,?)",
            (entry_id, community_id, bundle, prev_hash, seq, now),
        )
        con.commit()
        con.close()
        return entry_id
    except Exception as exc:
        log.warning("smb_suite: stix append failed: %s", exc)
        return ""


def provision_suite(
    tenant_id:    str,
    community_id: str,
    config:       dict | None = None,
    sep_db_path:  str = _SEP_DB_PATH,
    vendor_db_path: str = _VENDOR_DB_PATH,
    cost_db_path: str = _COST_DB_PATH,
) -> SMBProvisionResult:
    """Provision all 7 SMB governance modules in one operation."""
    cfg    = config or {}
    now    = datetime.now(UTC).isoformat()
    result = SMBProvisionResult(tenant_id=tenant_id, community_id=community_id, provisioned_at=now)

    # 1. Vendor Governance
    vendors = cfg.get("vendors", [])
    for v in vendors:
        try:
            from warden.vendor_gov.registry import register_vendor
            register_vendor(
                tenant_id=tenant_id,
                display_name=v.get("display_name", v.get("name", "Unknown")),
                website=v.get("website", ""),
                provider_type=v.get("provider_type", "LLM"),
                db_path=vendor_db_path,
            )
            result.vendor_count += 1
        except Exception as exc:
            result.errors.append(f"vendor:{v.get('display_name','?')}:{exc}")

    # 2. Budget cap
    monthly_budget = cfg.get("monthly_budget_usd", 0.0)
    if monthly_budget > 0:
        try:
            from warden.financial.budget import set_budget_cap
            set_budget_cap(tenant_id, monthly_budget, department="default", db_path=cost_db_path)
            result.budget_caps_set += 1
        except Exception as exc:
            result.errors.append(f"budget:{exc}")

    # 3. Training program
    try:
        from warden.communities.training_records import create_program
        create_program(
            community_id=community_id,
            title="AI Safety Basics",
            description="Mandatory onboarding training covering AI policy, data handling, and incident reporting.",
            required_for=["all"],
            passing_score=0.8,
            valid_days=365,
            db_path=sep_db_path,
        )
        result.training_programs += 1
    except Exception as exc:
        result.errors.append(f"training:{exc}")

    # 4. Incident register — verify schema
    try:
        from warden.communities.incident_register import get_incident_stats
        get_incident_stats(tenant_id, db_path=sep_db_path)
        result.incident_register = True
    except Exception as exc:
        result.errors.append(f"incident_register:{exc}")

    # 5. Prompt library — verify schema
    try:
        from warden.communities.prompt_library import get_library_stats
        get_library_stats(community_id, db_path=sep_db_path)
        result.prompt_library = True
    except Exception as exc:
        result.errors.append(f"prompt_library:{exc}")

    # 6. Supplier risk for known vendors
    if result.vendor_count > 0:
        try:
            from warden.communities.supplier_risk import assess_supplier
            from warden.vendor_gov.registry import list_vendors
            vlist = list_vendors(tenant_id, db_path=vendor_db_path)
            for v in vlist[:10]:
                assess_supplier(community_id, v.vendor_id, tenant_id=tenant_id, db_path=sep_db_path)
            result.supplier_risk = True
        except Exception as exc:
            result.errors.append(f"supplier_risk:{exc}")

    # 7. UECIID + STIX
    result.ueciid        = _assign_ueciid()
    result.stix_chain_id = _append_stix(result.ueciid, tenant_id, community_id)

    log.info(
        "smb_suite: provisioned tenant=%s community=%s vendors=%d budget=%d training=%d ueciid=%s",
        tenant_id, community_id, result.vendor_count, result.budget_caps_set,
        result.training_programs, result.ueciid,
    )
    return result


def get_suite_health(
    tenant_id:     str,
    community_id:  str = "",
    sep_db_path:   str = _SEP_DB_PATH,
    vendor_db_path: str = _VENDOR_DB_PATH,
    cost_db_path:  str = _COST_DB_PATH,
) -> dict:
    """Health check across all 7 governance modules."""
    health: dict[str, dict] = {}

    try:
        from warden.vendor_gov.registry import get_vendor_stats
        stats = get_vendor_stats(tenant_id, db_path=vendor_db_path)
        health["vendor_governance"] = {"status": "ok", "total": stats.get("total_vendors", 0)}
    except Exception as exc:
        health["vendor_governance"] = {"status": "error", "detail": str(exc)}

    try:
        from warden.financial.budget import get_realtime_status
        bstatus = get_realtime_status(tenant_id, db_path=cost_db_path)
        health["budget_dashboard"] = {"status": "ok", "caps": bstatus.get("total_caps", 0)}
    except Exception as exc:
        health["budget_dashboard"] = {"status": "error", "detail": str(exc)}

    try:
        from warden.communities.incident_register import get_incident_stats
        istats = get_incident_stats(tenant_id, db_path=sep_db_path)
        health["incident_register"] = {"status": "ok", "total": istats.get("total", 0)}
    except Exception as exc:
        health["incident_register"] = {"status": "error", "detail": str(exc)}

    try:
        from warden.communities.prompt_library import get_library_stats
        lstats = get_library_stats(community_id or tenant_id, db_path=sep_db_path)
        health["prompt_library"] = {"status": "ok", "total": lstats.get("total_prompts", 0)}
    except Exception as exc:
        health["prompt_library"] = {"status": "error", "detail": str(exc)}

    try:
        from warden.communities.training_records import list_programs
        programs = list_programs(community_id or tenant_id, db_path=sep_db_path)
        health["training_records"] = {"status": "ok", "programs": len(programs)}
    except Exception as exc:
        health["training_records"] = {"status": "error", "detail": str(exc)}

    try:
        from warden.communities.supplier_risk import list_assessments
        assessments = list_assessments(community_id or tenant_id, db_path=sep_db_path)
        health["supplier_risk"] = {"status": "ok", "assessments": len(assessments)}
    except Exception as exc:
        health["supplier_risk"] = {"status": "error", "detail": str(exc)}

    try:
        from datetime import UTC, datetime

        from warden.financial.cost_allocation import get_monthly_summary
        period = datetime.now(UTC).strftime("%Y-%m")
        summary = get_monthly_summary(tenant_id, period, db_path=cost_db_path)
        health["cost_allocation"] = {"status": "ok", "total_usd": summary.get("total_usd", 0.0)}
    except Exception as exc:
        health["cost_allocation"] = {"status": "error", "detail": str(exc)}

    ok_count = sum(1 for v in health.values() if v.get("status") == "ok")
    return {
        "tenant_id":   tenant_id,
        "community_id": community_id,
        "modules":     health,
        "modules_ok":  ok_count,
        "modules_total": len(health),
        "overall":     "healthy" if ok_count == len(health) else "degraded",
    }
