"""Lifecycle Manager — automated rotation scheduling, expiry alerting, retirement."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from .inventory import SecretsInventory, SecretRecord
from .vault_connector import VaultConnector, build_connector

log = logging.getLogger(__name__)


class LifecycleManager:
    def __init__(self, inventory: SecretsInventory, redis_client=None):
        self.inventory = inventory
        self._redis = redis_client

    async def check_and_flag_expiry(self, tenant_id: str,
                                     alert_days: int = 14) -> list[SecretRecord]:
        expiring = self.inventory.get_expiring(tenant_id, within_days=alert_days)
        for s in expiring:
            if s.status != "expiring_soon":
                self.inventory.update_status(tenant_id, s.secret_id, "expiring_soon")
        return expiring

    async def retire_expired(self, tenant_id: str) -> int:
        secrets = self.inventory.list_secrets(tenant_id, status="expired")
        count = 0
        for s in secrets:
            if self.inventory.update_status(tenant_id, s.secret_id, "retired"):
                count += 1
        return count

    async def rotate(self, tenant_id: str, secret_id: str,
                     vault_config: dict) -> dict:
        secrets = self.inventory.list_secrets(tenant_id)
        target = next((s for s in secrets if s.secret_id == secret_id), None)
        if not target:
            return {"success": False, "error": "secret not found"}

        try:
            connector = build_connector(vault_config)
        except Exception as exc:
            return {"success": False, "error": str(exc)}

        success = await connector.rotate_secret(target.name)
        if success:
            self.inventory.update_status(tenant_id, secret_id, "active")
            log.info("rotated secret %s for tenant %s", target.name, tenant_id)
        return {
            "success": success,
            "secret_name": target.name,
            "vault_type": vault_config.get("vault_type"),
            "message": "Rotation triggered" if success else "Vault does not support programmatic rotation",
        }

    def get_rotation_schedule(self, tenant_id: str,
                               interval_days: int = 30) -> list[dict]:
        secrets = self.inventory.list_secrets(tenant_id)
        now = datetime.now(timezone.utc)
        schedule = []
        for s in secrets:
            if s.status in ("retired", "expired"):
                continue
            if s.last_rotated:
                try:
                    last = datetime.fromisoformat(s.last_rotated.replace("Z", "+00:00"))
                    next_rotation = last + timedelta(days=interval_days)
                except ValueError:
                    next_rotation = now
            else:
                next_rotation = now

            overdue = next_rotation < now
            schedule.append({
                "secret_id": s.secret_id,
                "secret_name": s.name,
                "vault_id": s.vault_id,
                "vault_type": s.vault_type,
                "last_rotated": s.last_rotated,
                "next_rotation": next_rotation.isoformat(),
                "overdue": overdue,
                "days_until_rotation": (next_rotation - now).days,
            })

        schedule.sort(key=lambda x: x["days_until_rotation"])
        return schedule

    def summary(self, tenant_id: str, interval_days: int = 30) -> dict:
        schedule = self.get_rotation_schedule(tenant_id, interval_days)
        overdue = [s for s in schedule if s["overdue"]]
        due_soon = [s for s in schedule if not s["overdue"] and s["days_until_rotation"] <= 7]
        return {
            "total_tracked": len(schedule),
            "overdue_rotation": len(overdue),
            "due_within_7_days": len(due_soon),
            "rotation_schedule": schedule[:20],
        }
