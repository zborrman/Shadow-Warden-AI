"""
warden/ledger/journal.py — append-only double-entry journal (FT-1).

The single source of truth for money movement. Every change of value is a
`Transaction`: a set of `Posting`s whose signed micro-USD amounts **sum to zero**
(double-entry). Rows are immutable — there is no UPDATE or DELETE path — and each
transaction is chained by SHA-256 to its predecessor so tampering with history is
detectable (`verify_chain`).

Invariants (property-tested):
  I1  every transaction's postings sum to Money.zero()  — no value created/destroyed
  I5  idempotency_key is UNIQUE; a replay returns the original, posts nothing new
  I7  balances are DERIVED (`SUM(amount_micros)`), never a mutable counter

Storage: one SQLite DB via the `open_db` seam + DDL registry (`ledger` key),
path `data_path("warden_ledger.db", "LEDGER_DB_PATH")`. No float ever touches it —
amounts are integer micro-USD carried by `Money`.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime

from warden.config import data_path
from warden.db.connect import open_db
from warden.db.ddl_registry import register
from warden.ledger import accounts
from warden.ledger.money import Money

_DB_PATH = data_path("warden_ledger.db", "LEDGER_DB_PATH")
_lock = threading.RLock()
_GENESIS_HASH = "0" * 64

_LEDGER_DDL = """
    CREATE TABLE IF NOT EXISTS ledger_transactions (
        tx_id           TEXT    PRIMARY KEY,
        idempotency_key TEXT    NOT NULL UNIQUE,
        kind            TEXT    NOT NULL,
        seq             INTEGER NOT NULL,
        prev_hash       TEXT    NOT NULL,
        entry_hash      TEXT    NOT NULL,
        created_at      TEXT    NOT NULL
    );
    CREATE TABLE IF NOT EXISTS ledger_postings (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        tx_id         TEXT    NOT NULL,
        account       TEXT    NOT NULL,
        amount_micros INTEGER NOT NULL,
        created_at    TEXT    NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_ledger_postings_account ON ledger_postings(account);
    CREATE INDEX IF NOT EXISTS idx_ledger_postings_tx      ON ledger_postings(tx_id);
    CREATE INDEX IF NOT EXISTS idx_ledger_tx_seq           ON ledger_transactions(seq);
"""

register("ledger", "warden.ledger.journal", _LEDGER_DDL)


class LedgerError(RuntimeError):
    """Raised when a transaction violates a ledger invariant."""


@dataclass(frozen=True)
class Posting:
    account: str
    amount: Money  # signed; the sum across a transaction must be Money.zero()

    def __post_init__(self) -> None:
        accounts.validate(self.account)
        if not isinstance(self.amount, Money):
            raise LedgerError(f"posting amount must be Money, got {type(self.amount).__name__}")


@dataclass(frozen=True)
class Transaction:
    tx_id: str
    idempotency_key: str
    kind: str
    seq: int
    prev_hash: str
    entry_hash: str
    created_at: str
    postings: list[Posting] = field(default_factory=list)
    replayed: bool = False  # True when returned from an idempotent replay (nothing posted)


@contextmanager
def _conn(db_path: str | None = None) -> Generator[sqlite3.Connection, None, None]:
    path = db_path or _DB_PATH
    with open_db("ledger", path, module_default_path=_DB_PATH) as con:
        yield con


def _canonical_hash(
    tx_id: str, idem: str, kind: str, seq: int, prev_hash: str, created_at: str,
    postings: list[Posting],
) -> str:
    payload = {
        "tx_id": tx_id,
        "idempotency_key": idem,
        "kind": kind,
        "seq": seq,
        "prev_hash": prev_hash,
        "created_at": created_at,
        # postings sorted so the hash is order-independent
        "postings": sorted((p.account, p.amount.micros) for p in postings),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def _row_to_tx(con: sqlite3.Connection, row: sqlite3.Row) -> Transaction:
    prows = con.execute(
        "SELECT account, amount_micros FROM ledger_postings WHERE tx_id=? ORDER BY id",
        (row["tx_id"],),
    ).fetchall()
    postings = [Posting(account=r["account"], amount=Money.from_micros(int(r["amount_micros"]))) for r in prows]
    return Transaction(
        tx_id=row["tx_id"], idempotency_key=row["idempotency_key"], kind=row["kind"],
        seq=int(row["seq"]), prev_hash=row["prev_hash"], entry_hash=row["entry_hash"],
        created_at=row["created_at"], postings=postings,
    )


def post(
    idempotency_key: str,
    kind: str,
    postings: list[Posting],
    *,
    db_path: str | None = None,
) -> Transaction:
    """Append a balanced transaction. Idempotent on *idempotency_key*.

    Raises `LedgerError` if the postings do not sum to zero, are fewer than two,
    or name a malformed account. A replay of an already-recorded
    idempotency_key returns the original transaction (``replayed=True``) and
    writes nothing.
    """
    if not idempotency_key or not idempotency_key.strip():
        raise LedgerError("idempotency_key is required")
    if len(postings) < 2:
        raise LedgerError("a transaction needs at least two postings (double-entry)")

    total = Money.zero()
    for p in postings:
        accounts.validate(p.account)
        total += p.amount
    if not total.is_zero():
        raise LedgerError(f"postings do not balance: sum={total.micros} µUSD (must be 0)")

    with _lock, _conn(db_path) as con:
        existing = con.execute(
            "SELECT * FROM ledger_transactions WHERE idempotency_key=?",
            (idempotency_key,),
        ).fetchone()
        if existing is not None:
            tx = _row_to_tx(con, existing)
            return Transaction(**{**tx.__dict__, "replayed": True})

        head = con.execute(
            "SELECT seq, entry_hash FROM ledger_transactions ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        seq = (int(head["seq"]) + 1) if head else 1
        prev_hash = head["entry_hash"] if head else _GENESIS_HASH

        tx_id = f"ltx-{uuid.uuid4().hex}"
        created_at = datetime.now(UTC).isoformat()
        entry_hash = _canonical_hash(tx_id, idempotency_key, kind, seq, prev_hash, created_at, postings)

        con.execute(
            "INSERT INTO ledger_transactions"
            "(tx_id, idempotency_key, kind, seq, prev_hash, entry_hash, created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (tx_id, idempotency_key, kind, seq, prev_hash, entry_hash, created_at),
        )
        con.executemany(
            "INSERT INTO ledger_postings(tx_id, account, amount_micros, created_at) VALUES(?,?,?,?)",
            [(tx_id, p.account, p.amount.micros, created_at) for p in postings],
        )

    return Transaction(
        tx_id=tx_id, idempotency_key=idempotency_key, kind=kind, seq=seq,
        prev_hash=prev_hash, entry_hash=entry_hash, created_at=created_at,
        postings=list(postings),
    )


def balance(account: str, *, db_path: str | None = None) -> Money:
    """Derived balance of *account* = signed sum of its postings. Never a counter."""
    accounts.validate(account)
    with _conn(db_path) as con:
        row = con.execute(
            "SELECT COALESCE(SUM(amount_micros), 0) AS bal FROM ledger_postings WHERE account=?",
            (account,),
        ).fetchone()
    return Money.from_micros(int(row["bal"]))


def get_transaction(tx_id: str, *, db_path: str | None = None) -> Transaction | None:
    with _conn(db_path) as con:
        row = con.execute("SELECT * FROM ledger_transactions WHERE tx_id=?", (tx_id,)).fetchone()
        if row is None:
            return None
        return _row_to_tx(con, row)


def postings_for_account(
    account: str, *, since_iso: str | None = None, db_path: str | None = None
) -> list[dict]:
    """Every posting on *account*, oldest first, each carrying its own tx kind
    and timestamp — the read primitive AML-style monitors scan (FT-5).

    ``since_iso`` filters to postings with ``created_at >= since_iso``
    (ISO-8601 string compare, consistent with how timestamps are stored).
    """
    accounts.validate(account)
    with _conn(db_path) as con:
        if since_iso:
            rows = con.execute(
                """SELECT p.tx_id, p.amount_micros, p.created_at, t.kind
                   FROM ledger_postings p JOIN ledger_transactions t ON t.tx_id = p.tx_id
                   WHERE p.account=? AND p.created_at >= ?
                   ORDER BY p.id""",
                (account, since_iso),
            ).fetchall()
        else:
            rows = con.execute(
                """SELECT p.tx_id, p.amount_micros, p.created_at, t.kind
                   FROM ledger_postings p JOIN ledger_transactions t ON t.tx_id = p.tx_id
                   WHERE p.account=?
                   ORDER BY p.id""",
                (account,),
            ).fetchall()
    return [
        {
            "tx_id": r["tx_id"],
            "amount": Money.from_micros(int(r["amount_micros"])),
            "created_at": r["created_at"],
            "kind": r["kind"],
        }
        for r in rows
    ]


def distinct_accounts(*, namespace: str | None = None, db_path: str | None = None) -> list[str]:
    """Every distinct account id that has ever posted, optionally filtered to
    one namespace prefix (e.g. ``"tenant"``) — the enumeration primitive for
    account-scoped batch scans (FT-5 AML monitor).
    """
    with _conn(db_path) as con:
        rows = con.execute("SELECT DISTINCT account FROM ledger_postings").fetchall()
    all_accounts = [r["account"] for r in rows]
    if namespace is None:
        return all_accounts
    prefix = f"{namespace}:"
    return [a for a in all_accounts if a.startswith(prefix)]


def verify_chain(*, db_path: str | None = None) -> tuple[bool, int | None]:
    """Re-hash the chain in seq order. Returns (ok, broken_seq).

    ``broken_seq`` is the seq of the first transaction whose stored hash or
    prev-link does not reconcile, or None when the whole chain verifies.
    """
    with _conn(db_path) as con:
        rows = con.execute("SELECT * FROM ledger_transactions ORDER BY seq").fetchall()
        prev = _GENESIS_HASH
        for row in rows:
            tx = _row_to_tx(con, row)
            recomputed = _canonical_hash(
                tx.tx_id, tx.idempotency_key, tx.kind, tx.seq, tx.prev_hash, tx.created_at, tx.postings
            )
            if row["prev_hash"] != prev or row["entry_hash"] != recomputed:
                return False, tx.seq
            prev = row["entry_hash"]
    return True, None
