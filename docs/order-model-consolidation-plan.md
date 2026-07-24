# Order-Model Consolidation Plan (FT-6, last sub-part)

Status: **design only — no migration has been executed.** This document exists so the
actual data migration (a future, separately-reviewed slice) has a concrete target to
implement against, instead of starting blind. Written after a full-codebase survey of
all three order/receipt table clusters (see "Current state" below); the two smaller
FT-6 sub-parts (`authorize_payment()` chokepoint, x402 balance-core dedup) already
shipped and are tracked in `docs/unified-modernization-roadmap.md`.

## Why this is a doc, not code

The three tables below are not "the same shape stored three times" — the plan text
("adopt the marketplace order model") undersells how different they actually are.
`m2m_orders` and `commerce_orders` are schema-less JSON blobs (a single `data_json`
column); `marketplace_purchases` is fully fielded with no blob column at all. There is
no existing column mapping, no agreed target schema, and these are money-bearing
production tables read by six-plus consumers (analytics, Sybil detection, trust graph,
Prometheus metrics, a Streamlit admin page). Migrating them live without a written,
reviewable plan is not a place to move fast — see the `docs/fintech-grade-commerce-plan.md`
"What NOT to do" list: *"Don't migrate historical float rows in place; open [new
schema] with opening balances and freeze old tables read-only."* Same principle applies
here: dual-write first, cut over reads only after a bake period, freeze rather than
drop.

## Current state (as surveyed)

| Cluster | Table(s) | Shape | db_key / file | Writers | Readers |
|---|---|---|---|---|---|
| `warden/m2m_store/inventory.py` | `m2m_orders` | blob: `id, data_json, created_at` (real fields live inside the `Order` Pydantic model — `agent_id`, `offer_id`, `product_id`, `mandate_id`, `qty`, `total`, `status`, `payment_token`, `reservation_id`, `shipped_at`, `tenant_id`, `stix_chain_id`) | `m2m_store` / `warden_m2m_store.db` | `InventoryManager.save_order()`, `.ship()` | `.get_order()`, `.list_orders()`, `store_agent.py::_purchase_history()` |
| `warden/business_community/agentic_commerce/` | `commerce_orders`, `commerce_receipts` | blob: `id, tenant_id, mandate_id, data_json, created_at` (order) / `id, order_id, data_json, created_at` (receipt) | `commerce` / `warden_commerce.db` | `service.py::_save_order()`, `ap2.py::execute_payment()` (receipt) | `service.py::get_order_history()`, `ap2.py::get_receipt()` |
| `warden/marketplace/listing.py` | `marketplace_purchases` | fielded: `purchase_id, listing_id, asset_id, buyer_agent, seller_agent, price_paid, status, escrow_id, negotiation_id, purchased_at, completed_at, idempotency_key` | `marketplace` / `warden_marketplace.db` (Turso-routed) | `create_purchase()`, `finalize_purchase()` | `analytics.py`, `reputation.py`, `sybil_guard.py`, `trust_graph.py`, `metrics.py`, `pages/23_Marketplace_Admin.py` |

`commerce_orders` itself was also *literally* double-declared (identical columns, two
different index names) in both `ap2.py` and `service.py` — that specific duplication
was fixed in this same PR by having `service.py` import `ap2.py`'s
`COMMERCE_ORDERS_DDL` constant instead of re-declaring it. That fix is pure DDL-text
dedup with zero data risk and is unrelated to the cross-domain migration below (it's
already done, not proposed).

## Target schema (proposal)

Extend `marketplace_purchases` — the roadmap already names it as the destination —
rather than inventing a fourth table name. New nullable columns, added via the same
idempotent `_migrate_*` pattern `listing.py` already uses for `kya_status` /
`idempotency_key`:

```sql
ALTER TABLE marketplace_purchases ADD COLUMN domain TEXT NOT NULL DEFAULT 'marketplace';
ALTER TABLE marketplace_purchases ADD COLUMN tenant_id TEXT;
ALTER TABLE marketplace_purchases ADD COLUMN mandate_id TEXT;
ALTER TABLE marketplace_purchases ADD COLUMN payment_token TEXT;
ALTER TABLE marketplace_purchases ADD COLUMN reservation_id TEXT;
ALTER TABLE marketplace_purchases ADD COLUMN stix_chain_id TEXT;
ALTER TABLE marketplace_purchases ADD COLUMN shipped_at TEXT;
ALTER TABLE marketplace_purchases ADD COLUMN receipt_json TEXT;   -- commerce_receipts is 1:1 with its order; merge in directly
ALTER TABLE marketplace_purchases ADD COLUMN metadata_json TEXT;  -- overflow: offer/product detail, MCP intent, items list — anything not promoted to a real column
CREATE INDEX IF NOT EXISTS idx_mp_domain ON marketplace_purchases(domain);
CREATE INDEX IF NOT EXISTS idx_mp_tenant ON marketplace_purchases(tenant_id);
```

`domain` discriminates which source system a row came from (`'marketplace'` |
`'m2m_store'` | `'agentic_commerce'`); existing marketplace rows default to
`'marketplace'` with all the new columns `NULL`, so this is additive and backward
compatible for every current reader (`analytics.py`, `sybil_guard.py`, `trust_graph.py`
never reference these new columns and keep working unmodified).

### Column mapping

| Target column | `m2m_orders` (via `Order`) | `commerce_orders`/`commerce_receipts` (via `PurchaseOrder`) | `marketplace_purchases` (native) |
|---|---|---|---|
| `purchase_id` | `Order.id` | `PurchaseOrder.id` | `purchase_id` (native) |
| `buyer_agent` | `Order.agent_id` | *(tenant-level, no per-agent buyer field — use `tenant_id` as identity)* | `buyer_agent` (native) |
| `tenant_id` | `Order.tenant_id` | `PurchaseOrder.tenant_id` | *(new — nullable)* |
| `asset_id` | `Order.product_id`/`offer_id` | *(derive from `store_url` or leave null — needs confirmation)* | `asset_id` (native) |
| `mandate_id` | `Order.mandate_id` | `PurchaseOrder.mandate_id` | *(new — nullable)* |
| `price_paid` | `Order.total` | `PurchaseOrder.total` | `price_paid` (native) |
| `status` | `Order.status` | `PurchaseOrder.status` | `status` (native) |
| `payment_token` | `Order.payment_token` | — | *(new — nullable)* |
| `reservation_id` | `Order.reservation_id` | — | *(new — nullable)* |
| `stix_chain_id` | `Order.stix_chain_id` | `PurchaseOrder.stix_chain_id` | *(new — nullable)* |
| `shipped_at` | `Order.shipped_at` | — | *(new — nullable)* |
| `receipt_json` | — | `commerce_receipts.data_json` (joined on `order_id`) | *(new — nullable)* |
| `metadata_json` | any `Order` field not listed above | any `PurchaseOrder`/`MCPIntent` field not listed above | unused for native rows |

**Resolved**: `commerce_orders` has no `asset_id` equivalent — `PurchaseOrder.store_url`
is a merchant URL, not an asset identifier, and `items: list[OrderItem]` is a
multi-item cart, not a single asset. Decision: relax `asset_id` to nullable rather than
synthesize a meaningless value or use an empty-string sentinel. `marketplace_purchases.
asset_id` is `NOT NULL` today, and SQLite has no `ALTER COLUMN` — relaxing it requires a
full table rebuild (create-copy-drop-rename), a materially different risk class than
adding a nullable column. That rebuild is scoped to **Phase B** (below), timed to when
agentic_commerce dual-write actually needs to insert a NULL `asset_id` — not done
pre-emptively in Phase A, so Phase A keeps its "zero behavior change, every reader
unaffected" property intact.

## Migration sequencing

1. **✅ Phase A — schema only, DONE.** `_migrate_order_consolidation_columns()` in
   `listing.py` (same pattern as the existing four `_migrate_*` functions) added nine
   nullable columns (`domain` defaults to `'marketplace'`) plus `idx_mp_domain`/
   `idx_mp_tenant` indexes. Purely additive `ALTER TABLE ADD COLUMN` — no behavior
   change, every current reader unaffected, 5 dedicated tests + full marketplace/
   analytics/Sybil/trust-graph regression suite green.
2. **✅ Phase B — dual-write + asset_id rebuild, DONE.** `_migrate_relax_asset_id_nullable()`
   rebuilds `marketplace_purchases` (create-copy-drop-rename, all indexes recreated) the
   first time it sees `asset_id` still `NOT NULL`; every subsequent call short-circuits on
   a `PRAGMA table_info` check. No explicit `BEGIN`/`COMMIT` — `open_db()`'s connection
   already has a transaction open by the time it's yielded (from `ensure_schema`'s own
   bookkeeping), so atomicity comes from `open_db()`'s own commit-once/close-on-exception
   instead (an explicit `BEGIN IMMEDIATE` raised `OperationalError: cannot start a
   transaction within a transaction` in testing — fixed before this landed). New
   `warden/marketplace/listing.py::upsert_mirrored_order()` is the single write path both
   dual-writers call; `m2m_store.InventoryManager.save_order()` and
   `agentic_commerce.service.AgenticCommerceService._save_order()` (plus `ap2.py`'s receipt
   write) call it after their own blob-table write already succeeded. Reads are still from
   the original blob tables — Phase C's job, not this one.

   Two real bugs caught during implementation, not just at review: (1) the upsert's
   `ON CONFLICT` clause originally included `price_paid=excluded.price_paid` — a later
   status/receipt-only call (e.g. `ap2.py`'s receipt mirror, which never passes
   `price_paid`) would have zeroed out the real price on every update; fixed by dropping
   `price_paid` from the `UPDATE SET` entirely (set once at creation, never touched
   again) and wrapping `shipped_at`/`receipt_json`/`metadata_json` in `COALESCE` so an
   omitted field preserves its previous value instead of overwriting with `NULL`.
   (2) `upsert_mirrored_order`'s `db_path` parameter can't use this file's usual
   `= _DB_PATH` bound-default pattern, because it's called from OTHER modules that rely
   entirely on the default and need test-time monkeypatching of `listing._DB_PATH` to
   work — a def-time-bound default can't see that. Resolved dynamically inside the
   function body instead (`db_path or _DB_PATH`).
3. **Phase C — cutover reads.** Once Phase B's dual-write has been running cleanly,
   switch `list_orders()`/`get_order()`/`order_history()`/`get_receipt()` to query
   `marketplace_purchases WHERE domain = ...` instead of the original blob tables.
   Requires updating each domain's own tests to assert against the new table.
4. **Phase D — freeze, don't drop.** Once nothing reads from `m2m_orders`,
   `commerce_orders`, or `commerce_receipts`, mark them read-only (revoke the
   `save_order`/`_save_order` write paths, or simply stop calling them) for a safety
   window before a final cleanup PR drops them. Never drop in the same PR that cuts
   over reads.

## Status

- Phase A shipped (nine additive nullable columns + two indexes on
  `marketplace_purchases`; `commerce_orders` DDL dedup landed in the prior slice).
- Phase B shipped (`asset_id` rebuild + `m2m_store`/`agentic_commerce` dual-write via
  `upsert_mirrored_order()`). `m2m_orders`/`commerce_orders`/`commerce_receipts` remain
  the source of truth — every read still goes through them. Two mirror rows exist per
  order from now on: the original blob row (authoritative) and a fielded
  `marketplace_purchases` row (best-effort, fail-soft, for Phase C to eventually read
  from once trusted).
- Phase C (cutover reads) is next and has not started — needs a bake period on Phase B's
  dual-write first (compare row counts / spot-check field values between the blob and
  fielded copies) before any reader is switched over.
- Does not estimate a timeline beyond what `fintech-grade-commerce-plan.md` already
  states (FT-6 "Consolidation (2 weeks)" covers all three FT-6 sub-parts, of which this
  is the largest).
