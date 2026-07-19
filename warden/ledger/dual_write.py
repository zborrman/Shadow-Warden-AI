"""
warden/ledger/dual_write.py — dual-run bridge for the ledger migration (FT-2).

The reversible cutover: live balance writers keep their existing counters as the
source of truth and ALSO mirror each movement into the double-entry ledger. The
ledger is validated against the counters (`reconcile`) before anything reads from
it. Two hard rules make this safe to switch on in production:

  * **Gated** — mirroring only runs when `settings.ledger_dual_write` is true
    (default off), so merging this changes nothing until an operator opts in.
  * **Fails open** — a ledger write that raises is swallowed (counted via
    `record_failopen`); it must never break the authoritative live money path.
    The opposite posture from the ledger's own writes, which fail-closed — here
    the ledger is a shadow, not the record.

`reconcile` is deliberately generic (the caller supplies the counter value) so
this module never imports the higher-level billing modules — the `ledger` layer
stays a leaf.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from warden.config import settings
from warden.ledger import journal
from warden.ledger.money import Money
from warden.observability import Reason, record_failopen

log = logging.getLogger("warden.ledger.dual_write")

# Best-effort counter of swallowed mirror failures (observability without a hard dep).
_mirror_failures = 0


def enabled() -> bool:
    """True when live writers should mirror into the ledger (operator opt-in)."""
    return bool(settings.ledger_dual_write)


def mirror(label: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
    """Best-effort mirror of a ledger operation. No-op unless dual-write is enabled.

    Any exception (including `LedgerError`) is swallowed and counted via
    `record_failopen` — the caller's live path already succeeded and must not be
    undone by a shadow-ledger hiccup.
    """
    if not enabled():
        return
    global _mirror_failures
    try:
        fn(*args, **kwargs)
    except Exception as exc:
        _mirror_failures += 1
        record_failopen("ledger_dual_write", Reason.BACKEND_ERROR, exc)
        log.warning("ledger dual-write mirror failed (%s): %s", label, exc)


def mirror_failure_count() -> int:
    """Swallowed-mirror-failure count this process (health/recon signal)."""
    return _mirror_failures


def reconcile(account: str, counter_micros: int, *, db_path: str | None = None) -> dict:
    """Compare the ledger balance of *account* to an authoritative counter.

    `counter_micros` is supplied by the caller (e.g. a recon job converting a
    credit count to µUSD) so this leaf module imports no billing code. Returns a
    drift report; ``ok`` is True when they agree exactly.
    """
    ledger_micros = journal.balance(account, db_path=db_path).micros
    drift = ledger_micros - int(counter_micros)
    return {
        "account": account,
        "ledger_micros": ledger_micros,
        "counter_micros": int(counter_micros),
        "drift_micros": drift,
        "ok": drift == 0,
        "ledger_usd": Money.from_micros(ledger_micros).to_usd(),
    }
