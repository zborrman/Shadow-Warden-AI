# Shadow Agentic Container (SAC) — Architecture

SAC is the "smart isolated runtime" layer for agent execution in Shadow Warden.
The original concept (an eBPF-sensored Kata/QEMU micro-VM with speculative
Copy-on-Write execution and Hermes JIT secrets on AWS bare-metal) is translated
here into constructs that run on the **actual stack** — Python/FastAPI, Docker on
a single VPS, no kernel eBPF and no bare-metal hypervisor. The security *intent*
of each SAC pillar is preserved; the delivery mechanism is application-level.

## Pillar 1 — Inner Warden execution guard (`warden/sac/`)

Every agent tool call is screened before it runs. This is the Python-native
analogue of the spec's eBPF syscall sensor: instead of intercepting
`sys_enter_connect` in the guest kernel, the guard inspects the tool input at the
dispatch boundary.

Two deliberately different postures:

| Check | Posture | Behaviour |
|-------|---------|-----------|
| Outbound URL screening (SSRF / exfil) | **fail-CLOSED** | Every `http(s)` URL in the tool input is validated with `warden.net_guard.is_public_url`. A URL resolving to a private / loopback / link-local / cloud-metadata address (or that fails to parse/resolve) marks the call `COMPROMISED` and `blocked`; the tool is not dispatched. |
| Secret-path / traversal denylist | WARNING (non-blocking) | String args are scanned for `.ssh`, `id_rsa`, `.env`, `.git/config`, `/etc/shadow`, `../` … These raise a flag and downgrade the verdict but do not block. |
| GSAM telemetry emission | **fail-OPEN** | The verdict is shipped to GSAM as a metadata-only `Observation` (`event=tool_call`). Any error building or emitting it is swallowed — telemetry never breaks dispatch. |

**Wiring.** The guard is invoked at the single dispatch chokepoint:
- `warden/agent/tools.py::traced_dispatch` — all SOVA tools (and staff tools
  delegated to SOVA). URL-taking tools (`visual_assert_page`, `visual_diff`,
  `scan_shadow_ai`, `filter_request`) are screened `url_sensitive`.
- `warden/staff/dispatcher.py::staff_dispatch` — staff-native tools, after the
  existing boundary + velocity checks.

**Why not screen inside `BrowserSandbox`.** `BrowserSandbox` launches Chromium
with `--no-sandbox` and previously received agent-supplied URLs with no check —
the SSRF gap this pillar closes. The guard is placed at the *agent dispatch
boundary* rather than inside `BrowserSandbox.navigate` on purpose: the sandbox is
also driven by trusted internal callers (visual patrol of `localhost:8001` and
`PATROL_URLS`), and a blanket private-IP block there would break legitimate
internal patrol. Untrusted (agent-supplied) URLs are screened where they enter;
internally-constructed URLs are trusted.

**GSAM as first producer.** Before this pillar, nothing in production emitted GSAM
observations — the stream (`warden/gsam/collector.py`) was built but idle. The
guard is the first tap. Emitted fields are exactly the GDPR-allowlisted metadata
already reserved in `warden/gsam/schema.py` (`network_calls_count`,
`resolved_domains` (hostnames only), `unauthorized_commands_flag`,
`scan_verdict`, `latency_ms`, `payload_kind` = tool-name label). Tool input text
is never emitted.

## Pillar 2 — Hermes JIT credential lease (`warden/gsam/jit_lease.py`)

Time-boxed, single-use credential leasing so raw secrets stay out of an agent's
context and chat history. An agent requests a **lease** (carrying no secret);
only on a one-time **redeem** is a scope-bound ephemeral capability returned,
server-side.

- Storage: Turso-or-SQLite `gsam_leases` (schema in `app_factory._GSAM_DDL`),
  optional Redis fail-open metadata cache. Mirrors
  `warden/protocols/acp/token_vault.py`.
- Binding: HMAC-SHA256 over `lease_id|agent_id|tenant_id|scope|expires_at`.
- **Fail-CLOSED key:** the signing key comes from
  `warden.secret_keys.resolve_key("GSAM_LEASE_SECRET", purpose="gsam_lease")`,
  which raises `InsecureKeyError` in production when no key/master is configured.
  The API maps that to **HTTP 503** — leasing is a credential path, never
  fail-open.
- **Single-use:** redeem claims the lease atomically
  (`UPDATE … WHERE lease_id=? AND used_at=''`); a second redeem is rejected.
- Redeem also rejects expired / agent-mismatch / revoked / tampered-signature
  leases. The redeemed `credential` is an HMAC-derived bearer capability bound to
  this exact lease + scope (not a stored raw secret); a real secret backend
  (Vault / AWS SM) can be swapped behind `_derive_capability` later.

REST API (`warden/gsam/api.py`, mounted at `/gsam`):

| Method & path | Purpose |
|---------------|---------|
| `POST /gsam/lease` | Issue a lease (metadata only — never a secret). |
| `POST /gsam/lease/{id}/redeem` | Redeem once → `{scope, credential}`. |
| `DELETE /gsam/lease/{id}` | Revoke an active lease. |
| `GET /gsam/lease/{id}` | Lease metadata (never a credential). |

## Pillar 3 — GSAM downstream (rollup, drift, quarantine, read API)

Shipped as Phase 1 of the modernization plan (see `docs/modernization-plan-v8.md`).

- `warden/gsam/drift.py` — pure math: total-variation distance, EWMA drift
  `D_t = λ·TV + (1−λ)·D_{t−1}`, poisoning-gated baseline update (frozen while
  `drift ≥ threshold`), anti-inflation clamp (trust gains require ≥2 distinct
  counterparts).
- `warden/gsam/rollup.py` — registered as a `collector.register_sink()` at
  `main.py` startup; folds every flushed observation batch into
  `gsam_agent_stats` (hourly upsert) and updates `gsam_drift_baselines`.
- `warden/gsam/quarantine.py` — drift breach ⇒ Redis flag
  `gsam:quarantine:{agent_id}` (in-proc TTL fallback); enforced as an
  **additive** gate in `staff_dispatch`, after the boundary check.
- Read API `GET /gsam/heatmap | agents/{id}/stats | compliance/score` and the
  `gsam_agent_stats` semantic-layer model — both read the rollup, never
  ClickHouse.

## Configuration

| Setting | Default | Meaning |
|---------|---------|---------|
| `GSAM_ENABLED` | `true` | Master switch; disables leasing/rollup when false. |
| `GSAM_LEASE_TTL_S` | `900` | Default lease lifetime (seconds). |
| `GSAM_LEASE_SECRET` | `""` | Explicit HMAC key override; empty ⇒ derived from `VAULT_MASTER_KEY`, else fail-CLOSED. |
| `GSAM_DB_PATH` | `/tmp/warden_gsam.db` | SQLite fallback (Turso db name `gsam`). |
| `GSAM_DRIFT_LAMBDA` | `0.2` | EWMA smoothing factor λ for the drift index. |
| `GSAM_DRIFT_QUARANTINE_THRESHOLD` | `0.85` | Drift score that triggers quarantine. |
| `NET_GUARD_ALLOW_PRIVATE` | `false` | Dev/CI only — disables the SSRF private-range check. |

## Non-goals (documented, not built)

These parts of the original spec require infrastructure that does not exist on
this stack and are intentionally **not** implemented:

- **Kernel eBPF sensor / Rust sidecar** — needs a Linux guest kernel and
  privileged CO-RE bytecode loading; replaced by the application-level guard.
- **Kata Containers / QEMU micro-VMs, COW speculative execution** — needs
  bare-metal virtualization and RAM-backed OverlayFS; speculatively executing
  predicted shell commands is also a security hazard we will not add.
- **RISC-Zero ZK-audit of syscall traces** — no ZKVM in the stack; the
  tamper-evident audit need is already met by the STIX SHA-256 chain
  (`warden/communities/stix_audit.py`) and the billing audit chain.
- **AMM resource market (Token-LP) / Speculative Transaction Clearing** —
  marketplace R&D; the existing `warden/marketplace/clearing.py` ClearingEngine
  is the current clearing path.

## Follow-on slices (sequenced)

Full 7-phase deep-engineering + math modernization roadmap (assessment,
sequencing, invariants, verification pattern) lives in
`docs/modernization-plan-v8.md`. Phase 1 (GSAM downstream, above) is done;
Phase 2 (two-phase preflight billing) is next.
