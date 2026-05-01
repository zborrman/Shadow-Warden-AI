"""Secrets Governance API — /secrets/* (Community Business tier+)."""
from __future__ import annotations

import json
import os

from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from warden.secrets_gov.inventory import SecretsInventory
from warden.secrets_gov.lifecycle import LifecycleManager
from warden.secrets_gov.policy import SecretsPolicy, SecretsPolicyEngine
from warden.secrets_gov.vault_connector import CONNECTOR_TYPES, build_connector

router = APIRouter(tags=["secrets"])


def _get_db_path() -> str:
    return os.environ.get("SECRETS_DB_PATH", "/tmp/warden_secrets.db")


def _get_inventory() -> SecretsInventory:
    return SecretsInventory(_get_db_path())


def _get_policy_engine() -> SecretsPolicyEngine:
    return SecretsPolicyEngine(_get_db_path())


def _get_lifecycle(inv: SecretsInventory = Depends(_get_inventory)) -> LifecycleManager:
    return LifecycleManager(inv)


def _fernet() -> Fernet:
    key = os.environ.get("VAULT_MASTER_KEY", "")
    if not key:
        key = Fernet.generate_key().decode()
    return Fernet(key.encode() if isinstance(key, str) else key)


def _encrypt_config(config: dict) -> str:
    safe = {k: v for k, v in config.items()
            if k not in ("vault_type", "vault_id", "display_name")}
    return _fernet().encrypt(json.dumps(safe).encode()).decode()


def _decrypt_config(vault_row: dict) -> dict:
    enc = vault_row.get("config_enc", "")
    if not enc:
        return {}
    try:
        raw = _fernet().decrypt(enc.encode())
        return json.loads(raw)
    except Exception:
        return {}


def _get_tenant(x_tenant_id: str = "default") -> str:
    return x_tenant_id


# ── Pydantic models ───────────────────────────────────────────────────────────

class VaultRegisterRequest(BaseModel):
    vault_type: str = Field(..., description="aws_sm | azure_kv | hashicorp | gcp_sm | env")
    display_name: str
    config: dict = Field(default_factory=dict,
                         description="Vault credentials — stored encrypted")


class PolicyRequest(BaseModel):
    max_age_days: int = 90
    rotation_interval_days: int = 30
    alert_days_before_expiry: int = 14
    auto_retire_expired: bool = False
    require_expiry_date: bool = False
    forbidden_name_patterns: list[str] = Field(default_factory=list)
    require_tags: list[str] = Field(default_factory=list)


class RotateRequest(BaseModel):
    vault_id: str


# ── Vault endpoints ───────────────────────────────────────────────────────────

@router.get("/vaults")
async def list_vaults(
    tenant_id: str = Depends(_get_tenant),
    inv: SecretsInventory = Depends(_get_inventory),
):
    return inv.list_vaults(tenant_id)


@router.post("/vaults", status_code=201)
async def register_vault(
    body: VaultRegisterRequest,
    tenant_id: str = Depends(_get_tenant),
    inv: SecretsInventory = Depends(_get_inventory),
):
    if body.vault_type not in CONNECTOR_TYPES:
        raise HTTPException(400, f"Unknown vault_type. Valid: {list(CONNECTOR_TYPES)}")
    config_enc = _encrypt_config(body.config)
    vault_id = inv.register_vault(
        tenant_id=tenant_id,
        vault_type=body.vault_type,
        display_name=body.display_name,
        config_enc=config_enc,
    )
    return {"vault_id": vault_id, "vault_type": body.vault_type,
            "display_name": body.display_name}


@router.delete("/vaults/{vault_id}")
async def delete_vault(
    vault_id: str,
    tenant_id: str = Depends(_get_tenant),
    inv: SecretsInventory = Depends(_get_inventory),
):
    if not inv.delete_vault(tenant_id, vault_id):
        raise HTTPException(404, "Vault not found")
    return {"deleted": True}


@router.post("/vaults/{vault_id}/sync")
async def sync_vault(
    vault_id: str,
    tenant_id: str = Depends(_get_tenant),
    inv: SecretsInventory = Depends(_get_inventory),
):
    vault_row = inv.get_vault(tenant_id, vault_id)
    if not vault_row:
        raise HTTPException(404, "Vault not found")
    decrypted = _decrypt_config(vault_row)
    vault_config = {"vault_id": vault_id, "vault_type": vault_row["vault_type"], **decrypted}
    try:
        connector = build_connector(vault_config)
        metas = await connector.list_secrets()
    except RuntimeError as exc:
        raise HTTPException(502, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, f"Vault sync failed: {exc}") from exc
    count = inv.upsert_secrets(tenant_id, vault_id, metas)
    return {"synced_count": count, "vault_id": vault_id}


@router.get("/vaults/{vault_id}/health")
async def vault_health(
    vault_id: str,
    tenant_id: str = Depends(_get_tenant),
    inv: SecretsInventory = Depends(_get_inventory),
):
    vault_row = inv.get_vault(tenant_id, vault_id)
    if not vault_row:
        raise HTTPException(404, "Vault not found")
    decrypted = _decrypt_config(vault_row)
    vault_config = {"vault_id": vault_id, "vault_type": vault_row["vault_type"], **decrypted}
    try:
        connector = build_connector(vault_config)
        healthy = await connector.health_check()
    except Exception:
        healthy = False
    return {"vault_id": vault_id, "healthy": healthy}


# ── Inventory endpoints ───────────────────────────────────────────────────────

@router.get("/inventory")
async def list_inventory(
    tenant_id: str = Depends(_get_tenant),
    status: str | None = Query(None),
    vault_id: str | None = Query(None),
    inv: SecretsInventory = Depends(_get_inventory),
):
    secrets = inv.list_secrets(tenant_id, status=status, vault_id=vault_id)
    return [
        {
            "secret_id": s.secret_id,
            "name": s.name,
            "vault_id": s.vault_id,
            "vault_type": s.vault_type,
            "status": s.status,
            "risk_score": s.risk_score,
            "created_at": s.created_at,
            "last_rotated": s.last_rotated,
            "expires_at": s.expires_at,
            "tags": s.tags,
        }
        for s in secrets
    ]


@router.get("/inventory/expiring")
async def expiring_secrets(
    tenant_id: str = Depends(_get_tenant),
    within_days: int = Query(30),
    inv: SecretsInventory = Depends(_get_inventory),
):
    return inv.get_expiring(tenant_id, within_days=within_days)


@router.get("/stats")
async def get_stats(
    tenant_id: str = Depends(_get_tenant),
    inv: SecretsInventory = Depends(_get_inventory),
):
    return inv.get_stats(tenant_id)


# ── Lifecycle endpoints ───────────────────────────────────────────────────────

@router.post("/rotate/{secret_id}")
async def rotate_secret(
    secret_id: str,
    body: RotateRequest,
    tenant_id: str = Depends(_get_tenant),
    inv: SecretsInventory = Depends(_get_inventory),
    lc: LifecycleManager = Depends(_get_lifecycle),
):
    vault_row = inv.get_vault(tenant_id, body.vault_id)
    if not vault_row:
        raise HTTPException(404, "Vault not found")
    decrypted = _decrypt_config(vault_row)
    vault_config = {"vault_id": body.vault_id, "vault_type": vault_row["vault_type"],
                    **decrypted}
    return await lc.rotate(tenant_id, secret_id, vault_config)


@router.post("/retire/{secret_id}")
async def retire_secret(
    secret_id: str,
    tenant_id: str = Depends(_get_tenant),
    inv: SecretsInventory = Depends(_get_inventory),
):
    if not inv.update_status(tenant_id, secret_id, "retired"):
        raise HTTPException(404, "Secret not found")
    return {"retired": True, "secret_id": secret_id}


@router.get("/lifecycle/schedule")
async def rotation_schedule(
    tenant_id: str = Depends(_get_tenant),
    interval_days: int = Query(30),
    lc: LifecycleManager = Depends(_get_lifecycle),
):
    return lc.summary(tenant_id, interval_days=interval_days)


# ── Policy endpoints ──────────────────────────────────────────────────────────

@router.get("/policy")
async def get_policy(
    tenant_id: str = Depends(_get_tenant),
    pe: SecretsPolicyEngine = Depends(_get_policy_engine),
):
    p = pe.get_policy(tenant_id)
    return {
        "max_age_days": p.max_age_days,
        "rotation_interval_days": p.rotation_interval_days,
        "alert_days_before_expiry": p.alert_days_before_expiry,
        "auto_retire_expired": p.auto_retire_expired,
        "require_expiry_date": p.require_expiry_date,
        "forbidden_name_patterns": p.forbidden_name_patterns,
        "require_tags": p.require_tags,
    }


@router.put("/policy")
async def update_policy(
    body: PolicyRequest,
    tenant_id: str = Depends(_get_tenant),
    pe: SecretsPolicyEngine = Depends(_get_policy_engine),
):
    policy = SecretsPolicy(
        tenant_id=tenant_id,
        max_age_days=body.max_age_days,
        rotation_interval_days=body.rotation_interval_days,
        alert_days_before_expiry=body.alert_days_before_expiry,
        auto_retire_expired=body.auto_retire_expired,
        require_expiry_date=body.require_expiry_date,
        forbidden_name_patterns=body.forbidden_name_patterns,
        require_tags=body.require_tags,
    )
    pe.upsert_policy(policy)
    return {"updated": True}


@router.get("/policy/audit")
async def policy_audit(
    tenant_id: str = Depends(_get_tenant),
    inv: SecretsInventory = Depends(_get_inventory),
    pe: SecretsPolicyEngine = Depends(_get_policy_engine),
):
    secrets = inv.list_secrets(tenant_id)
    return pe.audit(tenant_id, secrets)


# ── Governance report ─────────────────────────────────────────────────────────

@router.get("/report")
async def governance_report(
    tenant_id: str = Depends(_get_tenant),
    inv: SecretsInventory = Depends(_get_inventory),
    pe: SecretsPolicyEngine = Depends(_get_policy_engine),
    lc: LifecycleManager = Depends(_get_lifecycle),
):
    stats = inv.get_stats(tenant_id)
    audit = pe.audit(tenant_id, inv.list_secrets(tenant_id))
    lifecycle_summary = lc.summary(tenant_id)
    expiring = inv.get_expiring(tenant_id, within_days=30)
    return {
        "tenant_id": tenant_id,
        "stats": stats,
        "compliance": {
            "score": audit["compliance_score"],
            "violations_by_severity": audit["violations_by_severity"],
        },
        "lifecycle": {
            "overdue_rotation": lifecycle_summary["overdue_rotation"],
            "due_within_7_days": lifecycle_summary["due_within_7_days"],
        },
        "expiring_within_30_days": len(expiring),
        "vaults": inv.list_vaults(tenant_id),
    }
