"""Secrets Policy Engine — per-tenant governance rules and compliance auditing."""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

_DB_PATH = os.environ.get("SECRETS_DB_PATH", "/tmp/warden_secrets.db")


@contextmanager
def _conn(db_path: str = _DB_PATH):
    con = sqlite3.connect(db_path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def _init_policy_table(db_path: str = _DB_PATH) -> None:
    with _conn(db_path) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS secrets_policy (
                tenant_id               TEXT PRIMARY KEY,
                max_age_days            INTEGER NOT NULL DEFAULT 90,
                rotation_interval_days  INTEGER NOT NULL DEFAULT 30,
                alert_days_before_expiry INTEGER NOT NULL DEFAULT 14,
                auto_retire_expired     INTEGER NOT NULL DEFAULT 0,
                require_expiry_date     INTEGER NOT NULL DEFAULT 0,
                forbidden_name_patterns TEXT NOT NULL DEFAULT '[]',
                require_tags            TEXT NOT NULL DEFAULT '[]',
                updated_at              TEXT NOT NULL
            );
        """)


_init_policy_table()


@dataclass
class SecretsPolicy:
    tenant_id: str
    max_age_days: int = 90
    rotation_interval_days: int = 30
    alert_days_before_expiry: int = 14
    auto_retire_expired: bool = False
    require_expiry_date: bool = False
    forbidden_name_patterns: list[str] = field(default_factory=list)
    require_tags: list[str] = field(default_factory=list)


@dataclass
class PolicyViolation:
    secret_id: str
    secret_name: str
    rule: str
    severity: str  # critical | high | medium | low
    detail: str


class SecretsPolicyEngine:
    def __init__(self, db_path: str = _DB_PATH):
        self.db_path = db_path
        _init_policy_table(db_path)

    def upsert_policy(self, policy: SecretsPolicy) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with _conn(self.db_path) as con:
            con.execute(
                """INSERT INTO secrets_policy
                   (tenant_id,max_age_days,rotation_interval_days,
                    alert_days_before_expiry,auto_retire_expired,require_expiry_date,
                    forbidden_name_patterns,require_tags,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(tenant_id) DO UPDATE SET
                     max_age_days=excluded.max_age_days,
                     rotation_interval_days=excluded.rotation_interval_days,
                     alert_days_before_expiry=excluded.alert_days_before_expiry,
                     auto_retire_expired=excluded.auto_retire_expired,
                     require_expiry_date=excluded.require_expiry_date,
                     forbidden_name_patterns=excluded.forbidden_name_patterns,
                     require_tags=excluded.require_tags,
                     updated_at=excluded.updated_at""",
                (
                    policy.tenant_id,
                    policy.max_age_days,
                    policy.rotation_interval_days,
                    policy.alert_days_before_expiry,
                    int(policy.auto_retire_expired),
                    int(policy.require_expiry_date),
                    json.dumps(policy.forbidden_name_patterns),
                    json.dumps(policy.require_tags),
                    now,
                ),
            )

    def get_policy(self, tenant_id: str) -> SecretsPolicy:
        with _conn(self.db_path) as con:
            row = con.execute(
                "SELECT * FROM secrets_policy WHERE tenant_id=?", (tenant_id,)
            ).fetchone()
        if not row:
            return SecretsPolicy(tenant_id=tenant_id)
        d = dict(row)
        return SecretsPolicy(
            tenant_id=d["tenant_id"],
            max_age_days=d["max_age_days"],
            rotation_interval_days=d["rotation_interval_days"],
            alert_days_before_expiry=d["alert_days_before_expiry"],
            auto_retire_expired=bool(d["auto_retire_expired"]),
            require_expiry_date=bool(d["require_expiry_date"]),
            forbidden_name_patterns=json.loads(d["forbidden_name_patterns"]),
            require_tags=json.loads(d["require_tags"]),
        )

    def evaluate(self, secret, policy: SecretsPolicy) -> list[PolicyViolation]:
        violations: list[PolicyViolation] = []
        now = datetime.now(timezone.utc)

        # Age check
        if secret.created_at:
            try:
                created = datetime.fromisoformat(secret.created_at.replace("Z", "+00:00"))
                age_days = (now - created).days
                if age_days > policy.max_age_days:
                    violations.append(PolicyViolation(
                        secret_id=secret.secret_id,
                        secret_name=secret.name,
                        rule="max_age",
                        severity="high",
                        detail=f"Secret is {age_days} days old (limit: {policy.max_age_days})",
                    ))
            except ValueError:
                pass

        # Rotation check
        if secret.last_rotated:
            try:
                rotated = datetime.fromisoformat(secret.last_rotated.replace("Z", "+00:00"))
                since_rotation = (now - rotated).days
                if since_rotation > policy.rotation_interval_days:
                    violations.append(PolicyViolation(
                        secret_id=secret.secret_id,
                        secret_name=secret.name,
                        rule="rotation_interval",
                        severity="high",
                        detail=f"Not rotated in {since_rotation} days (interval: {policy.rotation_interval_days})",
                    ))
            except ValueError:
                pass
        elif policy.rotation_interval_days > 0:
            violations.append(PolicyViolation(
                secret_id=secret.secret_id,
                secret_name=secret.name,
                rule="never_rotated",
                severity="medium",
                detail="Secret has never been rotated",
            ))

        # Expiry date required
        if policy.require_expiry_date and not secret.expires_at:
            violations.append(PolicyViolation(
                secret_id=secret.secret_id,
                secret_name=secret.name,
                rule="missing_expiry",
                severity="medium",
                detail="Secret has no expiry date set",
            ))

        # Expired
        if secret.status == "expired":
            violations.append(PolicyViolation(
                secret_id=secret.secret_id,
                secret_name=secret.name,
                rule="expired",
                severity="critical",
                detail="Secret is past its expiry date",
            ))

        # Forbidden name patterns
        import re
        for pattern in policy.forbidden_name_patterns:
            if re.search(pattern, secret.name, re.IGNORECASE):
                violations.append(PolicyViolation(
                    secret_id=secret.secret_id,
                    secret_name=secret.name,
                    rule="forbidden_pattern",
                    severity="medium",
                    detail=f"Name matches forbidden pattern: {pattern}",
                ))

        # Required tags
        for tag in policy.require_tags:
            if tag not in (secret.tags or {}):
                violations.append(PolicyViolation(
                    secret_id=secret.secret_id,
                    secret_name=secret.name,
                    rule="missing_tag",
                    severity="low",
                    detail=f"Required tag missing: {tag}",
                ))

        return violations

    def audit(self, tenant_id: str, secrets: list) -> dict:
        policy = self.get_policy(tenant_id)
        all_violations: list[PolicyViolation] = []
        for s in secrets:
            all_violations.extend(self.evaluate(s, policy))

        by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in all_violations:
            by_severity[v.severity] = by_severity.get(v.severity, 0) + 1

        compliant = len([s for s in secrets if not self.evaluate(s, policy)])
        score = 100.0 if not secrets else round(compliant / len(secrets) * 100, 1)

        return {
            "tenant_id": tenant_id,
            "audited_at": datetime.now(timezone.utc).isoformat(),
            "total_secrets": len(secrets),
            "compliant_secrets": compliant,
            "compliance_score": score,
            "violations_by_severity": by_severity,
            "total_violations": len(all_violations),
            "violations": [
                {
                    "secret_id": v.secret_id,
                    "secret_name": v.secret_name,
                    "rule": v.rule,
                    "severity": v.severity,
                    "detail": v.detail,
                }
                for v in all_violations
            ],
        }
