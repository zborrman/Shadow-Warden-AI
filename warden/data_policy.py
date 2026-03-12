"""
warden/data_policy.py
──────────────────────
Data Classification Policy Engine — the "traffic light" for SMB AI data access.

Gives business owners a simple, visual way to control what their AI agents
are allowed to see — without needing to understand security concepts:

  🟢 GREEN   Public / marketing data — all AI providers allowed
  🟡 YELLOW  Internal data — local AI models only (blocks cloud LLMs)
  🔴 RED     Confidential — blocked from ALL AI (financial, legal, medical, HR)

How it works
────────────
Rules are stored per-tenant in SQLite.  Each rule defines:
  • data_class   — green / yellow / red
  • trigger_type — "pattern" (regex) or "keyword" (comma-separated list)
  • value        — the regex or keyword list

The filter pipeline calls DataPolicyEngine.classify() before semantic analysis.
  RED result    → HTTP 403, content never reaches the LLM
  YELLOW + cloud → HTTP 403 with suggestion to use a local model
  YELLOW + local → allowed (with advisory flag in the response)
  GREEN          → pass-through, no policy restriction

Built-in categories (always active, no configuration needed)
────────────────────────────────────────────────────────────
  financial       RED   — invoices, bank accounts, revenue, P&L
  legal           RED   — NDAs, settlements, attorney-client privilege
  hr              RED   — salaries, performance reviews, terminations
  medical         RED   — patient records, diagnoses, HIPAA terms
  customer_data  YELLOW — CRM exports, subscriber lists, lead databases
  internal       YELLOW — internal memos, strategy docs, unreleased roadmaps

Tenant settings
───────────────
  block_cloud_yellow  bool  — if True, YELLOW content blocks cloud AI (default: True)
  default_class       str   — fallback class for unmatched content (default: green)

Thread-safe: all writes protected by threading.Lock.
Pattern cache: compiled regex patterns are cached per-tenant and invalidated on rule change.
"""
from __future__ import annotations

import logging
import os
import re
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

log = logging.getLogger("warden.data_policy")

POLICY_DB_PATH = Path(os.getenv("POLICY_DB_PATH", "/warden/data/data_policy.db"))


# ── Classification levels ─────────────────────────────────────────────────────

class DataClass:
    GREEN  = "green"
    YELLOW = "yellow"
    RED    = "red"
    ALL    = frozenset({"green", "yellow", "red"})


# ── AI provider classification ────────────────────────────────────────────────

_CLOUD_PROVIDERS = frozenset({
    "openai", "anthropic", "google", "gemini", "mistral",
    "cohere", "huggingface", "together", "groq", "perplexity",
    "azure", "aws", "bedrock",
})

_LOCAL_PROVIDERS = frozenset({
    "ollama", "lmstudio", "llamacpp", "localai",
    "private", "local", "localhost",
})


def classify_provider(provider: str) -> str:
    """Return 'cloud' or 'local' for a given provider name."""
    p = provider.lower()
    if any(lp in p for lp in _LOCAL_PROVIDERS):
        return "local"
    return "cloud"


# ── Built-in category patterns ────────────────────────────────────────────────

_BUILTIN_CATEGORIES: dict[str, dict] = {
    "financial": {
        "level": DataClass.RED,
        "patterns": [
            r"(?i)\b(invoice(?:s|d)?|bank\s+account|wire\s+transfer|swift\s+code|iban)\b",
            r"(?i)\b(revenue|profit\s+margin|income\s+statement|balance\s+sheet|cash\s+flow)\b",
            r"(?i)\b(accounts\s+payable|accounts\s+receivable|p&l|ebitda|gross\s+margin)\b",
        ],
        "description": "Financial records — invoices, bank accounts, revenue figures, P&L",
    },
    "legal": {
        "level": DataClass.RED,
        "patterns": [
            r"(?i)\b(non.?disclosure|nda|confidentiality\s+agreement|settlement\s+agreement)\b",
            r"(?i)\b(attorney.client|privileged|litigation|intellectual\s+property|trade\s+secret)\b",
            r"(?i)\b(patent\s+pending|proprietary\s+information|cease\s+and\s+desist)\b",
        ],
        "description": "Legal documents — NDAs, settlements, attorney-client privilege",
    },
    "hr": {
        "level": DataClass.RED,
        "patterns": [
            r"(?i)\b(performance\s+review|salary\s+(?:range|band|structure)|compensation\s+plan)\b",
            r"(?i)\b(termination\s+letter|disciplinary\s+action|employee\s+record|background\s+check)\b",
            r"(?i)\b(bonus\s+structure|equity\s+grant|severance|headcount\s+plan)\b",
        ],
        "description": "HR records — salaries, performance reviews, terminations",
    },
    "medical": {
        "level": DataClass.RED,
        "patterns": [
            r"(?i)\b(patient\s+(?:record|name|id|data)|diagnosis|prescription|medical\s+history)\b",
            r"(?i)\b(hipaa|icd.10|cpt\s+code|lab\s+result|treatment\s+plan|insurance\s+claim)\b",
            r"(?i)\b(protected\s+health\s+information|phi\b|ehr|emr)\b",
        ],
        "description": "Patient / medical data — HIPAA-regulated (diagnoses, prescriptions, PHI)",
    },
    "customer_data": {
        "level": DataClass.YELLOW,
        "patterns": [
            r"(?i)\b(customer\s+list|client\s+database|crm\s+export|contact\s+list)\b",
            r"(?i)\b(subscriber\s+list|mailing\s+list|lead\s+database|prospect\s+list)\b",
        ],
        "description": "Customer lists and CRM data — internal use only, local AI preferred",
    },
    "internal": {
        "level": DataClass.YELLOW,
        "patterns": [
            r"(?i)\b(internal\s+(?:memo|document|only)|not\s+for\s+(?:distribution|external))\b",
            r"(?i)\b(company\s+strategy|roadmap\s+q[1-4]|competitive\s+analysis|unreleased)\b",
        ],
        "description": "Internal docs and strategy — cloud AI blocked by default policy",
    },
}


# ── Policy decision result ─────────────────────────────────────────────────────

@dataclass
class PolicyDecision:
    """
    Returned by DataPolicyEngine.classify().

    allowed        — False means the request must be rejected.
    data_class     — green / yellow / red
    triggered_rule — rule_id or "builtin:<category>" that caused the decision
    reason         — human-readable explanation for the end user / log
    suggestion     — actionable advice (e.g. "Use a local model instead")
    """
    allowed:        bool
    data_class:     str
    triggered_rule: str
    reason:         str
    suggestion:     str = ""

    def as_dict(self) -> dict:
        return {
            "allowed":        self.allowed,
            "data_class":     self.data_class,
            "triggered_rule": self.triggered_rule,
            "reason":         self.reason,
            "suggestion":     self.suggestion,
        }


_ALLOW_GREEN = PolicyDecision(
    allowed        = True,
    data_class     = DataClass.GREEN,
    triggered_rule = "",
    reason         = "No policy restriction applies.",
)


# ── DataPolicyEngine ──────────────────────────────────────────────────────────

class DataPolicyEngine:
    """
    Per-tenant data classification and AI access policy engine.

    Typical usage in main.py::

        _policy = DataPolicyEngine()

        decision = _policy.classify(
            text      = raw_prompt,
            provider  = "openai",
            tenant_id = tenant_id,
        )
        if not decision.allowed:
            raise HTTPException(403, detail=decision.reason)
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self._path = db_path or POLICY_DB_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock  = threading.Lock()
        self._conn  = self._open()
        self._init_schema()
        # Compiled pattern cache: tenant_id → [(rule_id, data_class, Pattern)]
        self._cache: dict[str, list[tuple[str, str, re.Pattern]]] = {}

    # ── Core classify ──────────────────────────────────────────────────────────

    def classify(
        self,
        text:      str,
        provider:  str = "openai",
        tenant_id: str = "default",
    ) -> PolicyDecision:
        """
        Classify ``text`` against the tenant's data policy.

        Evaluation order (first match wins):
          1. Tenant custom rules — RED evaluated before YELLOW before GREEN
          2. Built-in category patterns
          3. Default: GREEN (allow)
        """
        provider_type = classify_provider(provider)
        settings      = self._get_settings(tenant_id)

        # 1. Custom tenant rules
        for rule_id, data_class, pattern in self._compiled_rules(tenant_id):
            if pattern.search(text):
                return self._make_decision(
                    data_class    = data_class,
                    provider_type = provider_type,
                    triggered     = rule_id,
                    settings      = settings,
                )

        # 2. Built-in categories
        for cat_name, cat_def in _BUILTIN_CATEGORIES.items():
            for pat_str in cat_def["patterns"]:
                if re.search(pat_str, text):
                    return self._make_decision(
                        data_class    = cat_def["level"],
                        provider_type = provider_type,
                        triggered     = f"builtin:{cat_name}",
                        settings      = settings,
                        description   = cat_def["description"],
                    )

        return _ALLOW_GREEN

    # ── Settings ───────────────────────────────────────────────────────────────

    def get_settings(self, tenant_id: str) -> dict:
        return self._get_settings(tenant_id)

    def update_settings(
        self,
        tenant_id:          str,
        default_class:      str  = DataClass.GREEN,
        block_cloud_yellow: bool = True,
    ) -> None:
        """Set tenant-level policy settings."""
        if default_class not in DataClass.ALL:
            raise ValueError(f"default_class must be one of {DataClass.ALL}")

        now = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO tenant_settings
                    (tenant_id, default_class, block_cloud_yellow, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    default_class      = excluded.default_class,
                    block_cloud_yellow = excluded.block_cloud_yellow,
                    updated_at         = excluded.updated_at
                """,
                (tenant_id, default_class, int(block_cloud_yellow), now),
            )
            self._conn.commit()
        log.info(
            "DataPolicy: updated settings tenant=%s block_cloud_yellow=%s",
            tenant_id, block_cloud_yellow,
        )

    # ── Rule management ────────────────────────────────────────────────────────

    def add_rule(
        self,
        tenant_id:    str,
        data_class:   str,
        trigger_type: str,
        value:        str,
        description:  str = "",
        rule_id:      str | None = None,
    ) -> str:
        """
        Add a custom classification rule for a tenant.

        Parameters
        ----------
        data_class   : "green" | "yellow" | "red"
        trigger_type : "pattern" (regex) | "keyword" (comma-separated)
        value        : regex string, or comma-separated keyword list

        Returns the rule_id.
        Raises ValueError on invalid data_class or bad regex.
        """
        if data_class not in DataClass.ALL:
            raise ValueError(f"data_class must be one of {DataClass.ALL}")
        if trigger_type not in ("pattern", "keyword"):
            raise ValueError("trigger_type must be 'pattern' or 'keyword'")

        # Convert keyword list → regex pattern (stored as pattern type)
        if trigger_type == "keyword":
            keywords = [k.strip() for k in value.split(",") if k.strip()]
            if not keywords:
                raise ValueError("keyword list is empty")
            value        = r"(?i)\b(" + "|".join(re.escape(k) for k in keywords) + r")\b"
            trigger_type = "pattern"

        # Validate regex before writing
        re.compile(value)

        rid = rule_id or str(uuid.uuid4())[:8]
        now = datetime.now(UTC).isoformat()

        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO policy_rules
                    (rule_id, tenant_id, data_class, trigger_type, value,
                     description, active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (rid, tenant_id, data_class, trigger_type, value, description, now),
            )
            self._conn.commit()

        self._cache.pop(tenant_id, None)
        log.info(
            "DataPolicy: added rule %s tenant=%s class=%s",
            rid, tenant_id, data_class,
        )
        return rid

    def delete_rule(self, rule_id: str, tenant_id: str) -> bool:
        """Delete a rule by ID.  Returns True if it existed."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM policy_rules WHERE rule_id=? AND tenant_id=?",
                (rule_id, tenant_id),
            )
            self._conn.commit()
        self._cache.pop(tenant_id, None)
        return cur.rowcount > 0

    def get_rules(self, tenant_id: str) -> list[dict]:
        """Return all active rules for a tenant, RED-first."""
        rows = self._conn.execute(
            """
            SELECT rule_id, data_class, trigger_type, value, description,
                   active, created_at
            FROM   policy_rules
            WHERE  tenant_id=?
            ORDER BY
                CASE data_class WHEN 'red' THEN 0 WHEN 'yellow' THEN 1 ELSE 2 END,
                created_at DESC
            """,
            (tenant_id,),
        ).fetchall()
        return [
            {
                "rule_id":      r[0],
                "data_class":   r[1],
                "trigger_type": r[2],
                "value":        r[3],
                "description":  r[4],
                "active":       bool(r[5]),
                "created_at":   r[6],
            }
            for r in rows
        ]

    def get_full_policy(self, tenant_id: str) -> dict:
        """Return complete policy: settings + custom rules + built-in category info."""
        return {
            "tenant_id": tenant_id,
            "settings":  self._get_settings(tenant_id),
            "rules":     self.get_rules(tenant_id),
            "builtin_categories": {
                name: {
                    "level":       cat["level"],
                    "description": cat["description"],
                }
                for name, cat in _BUILTIN_CATEGORIES.items()
            },
        }

    # ── Decision builder ───────────────────────────────────────────────────────

    def _make_decision(
        self,
        *,
        data_class:    str,
        provider_type: str,
        triggered:     str,
        settings:      dict,
        description:   str = "",
    ) -> PolicyDecision:
        label = description or triggered

        if data_class == DataClass.RED:
            return PolicyDecision(
                allowed        = False,
                data_class     = DataClass.RED,
                triggered_rule = triggered,
                reason         = (
                    f"Confidential data detected ({label}). "
                    f"This content is classified RED and cannot be sent to any AI provider."
                ),
                suggestion     = "Remove confidential information before using AI assistance.",
            )

        if data_class == DataClass.YELLOW:
            block_cloud = settings.get("block_cloud_yellow", True)
            if provider_type == "cloud" and block_cloud:
                return PolicyDecision(
                    allowed        = False,
                    data_class     = DataClass.YELLOW,
                    triggered_rule = triggered,
                    reason         = (
                        f"Internal data detected ({label}). "
                        f"Your policy restricts this content to local AI models only."
                    ),
                    suggestion     = (
                        "Use a local model (Ollama, LM Studio) for internal documents, "
                        "or ask your administrator to adjust the policy."
                    ),
                )
            # YELLOW but cloud not blocked → allow with advisory
            return PolicyDecision(
                allowed        = True,
                data_class     = DataClass.YELLOW,
                triggered_rule = triggered,
                reason         = (
                    f"Internal data detected ({label}). "
                    f"Allowed by current policy — consider using a local model."
                ),
            )

        # GREEN
        return PolicyDecision(
            allowed        = True,
            data_class     = DataClass.GREEN,
            triggered_rule = triggered,
            reason         = "Public content — no restriction.",
        )

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _get_settings(self, tenant_id: str) -> dict:
        row = self._conn.execute(
            "SELECT default_class, block_cloud_yellow FROM tenant_settings WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
        if not row:
            return {"default_class": DataClass.GREEN, "block_cloud_yellow": True}
        return {"default_class": row[0], "block_cloud_yellow": bool(row[1])}

    def _compiled_rules(self, tenant_id: str) -> list[tuple[str, str, re.Pattern]]:
        """Return compiled regex rules for tenant from cache (build on miss)."""
        if tenant_id in self._cache:
            return self._cache[tenant_id]

        rows = self._conn.execute(
            """
            SELECT rule_id, data_class, value
            FROM   policy_rules
            WHERE  tenant_id=? AND active=1 AND trigger_type='pattern'
            ORDER BY
                CASE data_class WHEN 'red' THEN 0 WHEN 'yellow' THEN 1 ELSE 2 END
            """,
            (tenant_id,),
        ).fetchall()

        compiled: list[tuple[str, str, re.Pattern]] = []
        for rule_id, data_class, pattern_str in rows:
            try:
                compiled.append((rule_id, data_class, re.compile(pattern_str)))
            except re.error as exc:
                log.warning("DataPolicy: invalid pattern in rule %s — %s", rule_id, exc)

        self._cache[tenant_id] = compiled
        return compiled

    # ── Schema & lifecycle ─────────────────────────────────────────────────────

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS policy_rules (
                    rule_id      TEXT PRIMARY KEY,
                    tenant_id    TEXT    NOT NULL,
                    data_class   TEXT    NOT NULL,
                    trigger_type TEXT    NOT NULL,
                    value        TEXT    NOT NULL,
                    description  TEXT    NOT NULL DEFAULT '',
                    active       INTEGER NOT NULL DEFAULT 1,
                    created_at   TEXT    NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_pr_tenant
                    ON policy_rules(tenant_id);

                CREATE TABLE IF NOT EXISTS tenant_settings (
                    tenant_id           TEXT PRIMARY KEY,
                    default_class       TEXT    NOT NULL DEFAULT 'green',
                    block_cloud_yellow  INTEGER NOT NULL DEFAULT 1,
                    updated_at          TEXT    NOT NULL
                );
            """)
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()
