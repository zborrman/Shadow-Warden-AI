"""
warden/workers/clearing_outbox_relay.py
──────────────────────────────────────────
ARQ worker: drain the ClearingEngine transactional outbox (FT-4 slice 3).

`clearing.py::clear_async()` already attempts an immediate Postgres relay on
every clearing, but a transient Postgres outage leaves the outbox row
'pending' rather than losing it. This job periodically drains whatever is
still pending — the "relay" half of the at-least-once outbox pattern.
"""
from __future__ import annotations

import logging

from warden.marketplace import clearing

log = logging.getLogger("warden.workers.clearing_outbox_relay")


async def relay_clearing_outbox(ctx: dict) -> dict:
    """ARQ cron entry point — drains up to 50 pending outbox rows per run.

    Passes `clearing._DB_PATH` explicitly rather than relying on
    `relay_pending()`'s bound default (defaults are evaluated once at
    def-time, so a test's `monkeypatch.setattr(clearing, "_DB_PATH", ...)`
    would otherwise have no effect on this call — same gotcha as
    `x402_settlement.settle_x402_deductions`).
    """
    summary = await clearing.relay_pending(db_path=clearing._DB_PATH, limit=50)
    if summary["still_pending"]:
        log.warning(
            "clearing_outbox_relay: %d rows still pending after this run "
            "(attempted=%d, relayed=%d)",
            summary["still_pending"], summary["attempted"], summary["relayed"],
        )
    else:
        log.debug("clearing_outbox_relay: %s", summary)
    return summary


async def purge_clearing_outbox(ctx: dict) -> dict:
    """ARQ cron entry point — retention/cleanup for confirmed-relayed rows.

    Same explicit-`_DB_PATH`-argument pattern as `relay_clearing_outbox`
    (module-level default parameters bind at def-time, not call-time).
    Only deletes rows already marked 'relayed'; anything still 'pending' is
    left untouched regardless of age.
    """
    summary = clearing.purge_relayed_outbox(db_path=clearing._DB_PATH, older_than_days=30.0)
    if summary["purged"]:
        log.info("purge_clearing_outbox: purged %d relayed rows", summary["purged"])
    else:
        log.debug("purge_clearing_outbox: %s", summary)
    return summary
