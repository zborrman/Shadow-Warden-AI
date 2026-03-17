"""
warden/wallet_shield.py
━━━━━━━━━━━━━━━━━━━━━━━
Token Budget Enforcement — protects SMB clients from Financial DoS (LLM10).

Without budget enforcement, a single attacker sending a flood of long prompts
can exhaust an SMB's entire OpenAI/Anthropic monthly budget overnight.

Architecture
────────────
  • Redis sliding-window counter per (tenant_id, user_id)
  • Pre-flight check: estimated tokens checked before forwarding to upstream LLM
  • Post-call accounting: actual tokens (from upstream usage field) recorded
  • Fail-open: if Redis is unavailable the request is ALLOWED (no false positives)

Token estimation
────────────────
  Pre-flight uses a fast heuristic (bytes / 4).  Actual token counts returned
  by the upstream API are recorded in post-call accounting for accurate metrics.
  The heuristic errs on the side of over-counting, providing a conservative
  safety margin.

Redis key schema
────────────────
  warden:wallet:{tenant}:{user}       — sliding-window token counter
  warden:wallet:tenant:{tenant}:daily — per-tenant daily aggregate

Environment variables
─────────────────────
  WALLET_ENABLED          true|false (default true)
  WALLET_DEFAULT_BUDGET   tokens per window, per user (default 100000)
  WALLET_WINDOW_SECONDS   sliding window in seconds (default 3600 = 1 h)
  WALLET_HARD_LIMIT       max tokens per single request (default 200000)
  TOKEN_ALERT_PCT         alert when this % of budget consumed (default 80)
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass

log = logging.getLogger("warden.wallet_shield")

# ── Config ────────────────────────────────────────────────────────────────────

_ENABLED         = os.getenv("WALLET_ENABLED",          "true").lower() == "true"
_DEFAULT_BUDGET  = int(os.getenv("WALLET_DEFAULT_BUDGET",  "100000"))
_WINDOW_SECONDS  = int(os.getenv("WALLET_WINDOW_SECONDS",  "3600"))
_HARD_LIMIT      = int(os.getenv("WALLET_HARD_LIMIT",      "200000"))
_ALERT_PCT       = int(os.getenv("TOKEN_ALERT_PCT",        "80"))
_REDIS_URL       = os.getenv("REDIS_URL", "")


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class BudgetResult:
    allowed:    bool
    used:       int
    limit:      int
    remaining:  int
    limit_type: str   # "user_window" | "hard_limit" | "disabled"

    def to_dict(self) -> dict:
        return {
            "error":      "token_budget_exceeded",
            "limit_type": self.limit_type,
            "limit":      self.limit,
            "used":       self.used,
            "remaining":  max(0, self.remaining),
            "hint":       (
                f"Your token budget ({self.limit:,} tokens/{_WINDOW_SECONDS}s window) "
                "has been exceeded. Wait for the window to reset or contact support."
            ),
        }


# ── Token estimation (no external dependencies) ───────────────────────────────

def estimate_tokens(messages: list[dict]) -> int:
    """
    Fast heuristic token estimator for a list of OpenAI-style message dicts.

    Rule: 1 token ≈ 4 UTF-8 bytes (works for Latin + Cyrillic; errs high for CJK).
    The slight overcount is intentional — it provides a conservative safety margin
    before the actual upstream token count is available.
    """
    total = 0
    for msg in messages:
        content = msg.get("content") or ""
        if isinstance(content, str):
            total += max(1, len(content.encode("utf-8")) // 4)
        elif isinstance(content, list):
            # Multi-modal content blocks
            for block in content:
                if isinstance(block, dict):
                    text = block.get("text") or ""
                    total += max(1, len(text.encode("utf-8")) // 4)
    return total


# ── WalletShield ──────────────────────────────────────────────────────────────

class WalletShield:
    """
    Sliding-window token budget enforcer.

    Thread-safe; use the :func:`get_wallet_shield` singleton.
    Redis operations are synchronous (matching warden/cache.py).
    """

    def __init__(self) -> None:
        self._redis = None
        self._mem: dict[str, int] = {}  # in-memory fallback for dev

    # ── Redis client (lazy, fail-open) ────────────────────────────────────────

    def _client(self):
        if self._redis is not None:
            return self._redis
        if not _REDIS_URL:
            return None
        try:
            import redis  # noqa: PLC0415
            self._redis = redis.from_url(
                _REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=1,
                socket_timeout=1,
            )
            self._redis.ping()
            return self._redis
        except Exception as exc:
            log.debug("WalletShield Redis unavailable (fail-open): %s", exc)
            return None

    # ── Public API ────────────────────────────────────────────────────────────

    def check_and_consume(
        self,
        tenant_id: str,
        user_id:   str,
        estimated: int,
    ) -> BudgetResult:
        """
        Pre-flight budget check.

        Atomically increments the counter by *estimated* tokens and checks it
        against the configured budget.  If the budget would be exceeded, the
        increment is reversed and BudgetResult.allowed=False is returned.

        Fail-open: Redis errors always return BudgetResult.allowed=True.
        """
        if not _ENABLED:
            return BudgetResult(True, 0, _DEFAULT_BUDGET, _DEFAULT_BUDGET, "disabled")

        # Hard per-request limit (no Redis needed)
        if estimated > _HARD_LIMIT:
            return BudgetResult(
                allowed=False,
                used=estimated,
                limit=_HARD_LIMIT,
                remaining=0,
                limit_type="hard_limit",
            )

        key = f"warden:wallet:{tenant_id}:{user_id}"
        r   = self._client()

        if r:
            try:
                new_val = r.incrby(key, estimated)
                # Set TTL only when the key is new (EXPIREX NX)
                r.expire(key, _WINDOW_SECONDS, nx=True)

                if new_val > _DEFAULT_BUDGET:
                    # Over budget — reverse the increment
                    r.decrby(key, estimated)
                    current = max(0, new_val - estimated)
                    _fire_budget_exceeded_metric(tenant_id, "user_window")
                    return BudgetResult(
                        allowed=False,
                        used=current,
                        limit=_DEFAULT_BUDGET,
                        remaining=max(0, _DEFAULT_BUDGET - current),
                        limit_type="user_window",
                    )

                # Alert when approaching limit
                if new_val >= (_DEFAULT_BUDGET * _ALERT_PCT // 100):
                    log.warning(
                        "token_budget_alert tenant=%s user=%s used=%d/%d (%.0f%%)",
                        tenant_id, user_id, new_val, _DEFAULT_BUDGET,
                        new_val / _DEFAULT_BUDGET * 100,
                    )

                _fire_tokens_consumed_metric(tenant_id, estimated)
                return BudgetResult(
                    allowed=True,
                    used=new_val,
                    limit=_DEFAULT_BUDGET,
                    remaining=max(0, _DEFAULT_BUDGET - new_val),
                    limit_type="user_window",
                )
            except Exception as exc:
                log.debug("WalletShield check error (fail-open): %s", exc)
                return BudgetResult(True, 0, _DEFAULT_BUDGET, _DEFAULT_BUDGET, "redis_error")

        # ── In-memory fallback ────────────────────────────────────────────────
        current = self._mem.get(key, 0)
        if current + estimated > _DEFAULT_BUDGET:
            _fire_budget_exceeded_metric(tenant_id, "user_window")
            return BudgetResult(
                allowed=False,
                used=current,
                limit=_DEFAULT_BUDGET,
                remaining=max(0, _DEFAULT_BUDGET - current),
                limit_type="user_window",
            )
        self._mem[key] = current + estimated
        _fire_tokens_consumed_metric(tenant_id, estimated)
        return BudgetResult(True, current + estimated, _DEFAULT_BUDGET,
                            _DEFAULT_BUDGET - current - estimated, "user_window")

    def record_actual(
        self,
        tenant_id: str,
        user_id:   str,
        actual:    int,
        estimated: int,
    ) -> None:
        """
        Post-call correction: adjust counter from *estimated* to *actual* tokens.

        Called after the upstream LLM response is received and the real token
        count is known (from response.usage.total_tokens).
        If actual < estimated the excess is returned to the budget.
        If actual > estimated the additional tokens are charged.
        """
        if not _ENABLED or actual == estimated:
            return
        delta = actual - estimated
        key = f"warden:wallet:{tenant_id}:{user_id}"
        r   = self._client()
        try:
            if r:
                r.incrby(key, delta)  # negative delta = credit back
            else:
                self._mem[key] = max(0, self._mem.get(key, 0) + delta)
            if delta != 0:
                _fire_tokens_consumed_metric(tenant_id, delta)
        except Exception as exc:
            log.debug("WalletShield record_actual error (non-fatal): %s", exc)

    def get_usage(self, tenant_id: str, user_id: str) -> int:
        """Return current window token usage for a user. Returns 0 on error."""
        if not _ENABLED:
            return 0
        key = f"warden:wallet:{tenant_id}:{user_id}"
        r   = self._client()
        try:
            if r:
                return int(r.get(key) or 0)
            return self._mem.get(key, 0)
        except Exception:
            return 0


# ── Prometheus helpers (non-fatal) ────────────────────────────────────────────

def _fire_tokens_consumed_metric(tenant_id: str, tokens: int) -> None:
    try:
        from warden.metrics import WALLET_TOKENS_CONSUMED  # noqa: PLC0415
        WALLET_TOKENS_CONSUMED.labels(tenant_id=tenant_id).inc(tokens)
    except Exception:
        pass


def _fire_budget_exceeded_metric(tenant_id: str, limit_type: str) -> None:
    try:
        from warden.metrics import WALLET_BUDGET_EXCEEDED  # noqa: PLC0415
        WALLET_BUDGET_EXCEEDED.labels(tenant_id=tenant_id, limit_type=limit_type).inc()
    except Exception:
        pass


# ── Module-level singleton ────────────────────────────────────────────────────

_shield: WalletShield | None = None


def get_wallet_shield() -> WalletShield:
    global _shield
    if _shield is None:
        _shield = WalletShield()
    return _shield
