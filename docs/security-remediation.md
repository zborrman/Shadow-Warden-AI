# Security Remediation Plan — Shadow Warden AI v4.7

**Date:** 2026-04-25  
**Scope:** 11 reported vulnerabilities re-assessed against actual codebase state  
**Author:** Security review (automated + manual code inspection)

---

## Severity Re-Assessment After Code Review

Several reported severities changed after reading the actual code.

| # | Title | Reported | Actual | Reason |
|---|-------|----------|--------|--------|
| 1 | Fernet Key Persistence | CRITICAL | HIGH | Masking vault key is intentionally ephemeral (session-scoped PII tokens). Real risk is VAULT_MASTER_KEY for communities/sovereign with no startup validation. |
| 2 | Regex Injection via Evolution | CRITICAL | HIGH | `regex_pattern` rules are persisted but activation path for regex hot-loading into a live engine is not present in evolve.py — only `semantic_example` calls `add_examples()`. Risk is real but narrower. |
| 3 | Shadow Ban Pool Size | CRITICAL | HIGH | Confirmed: 6 responses, deterministic (`hash(entity_key) % 6`). Fingerprinting with 6 probes from different IPs is trivial. |
| 4 | Timing Side-Channel | CRITICAL | MEDIUM | Real architectural concern but exploitability requires network-layer precision not available through Caddy proxy. |
| 5 | Cache Poisoning | CRITICAL | LOW | Full SHA-256 confirmed (`hashlib.sha256`). No truncation. SHA-256 collision is infeasible. Actual risk is Redis compromise, not hash collision. |
| 6 | Causal Arbiter CPT Poisoning | CRITICAL | HIGH | Real. `calibrate_from_logs()` reads production NDJSON with no adversarial validation gate. |
| 7 | Community Keys in SQLite | CRITICAL | HIGH | Real. Private key material (`_mldsa_priv_enc`, `_mlkem_priv_enc`) Fernet-encrypted at field level but SQLite DB itself is plaintext. |
| 8 | HTTP/3 0-RTT Replay | CRITICAL | MEDIUM | Caddy 2.8+ has 0-RTT enabled by default. Needs explicit disable for mutating endpoints. |
| 9 | SEP Velocity DOS | HIGH | MEDIUM | Redis sorted sets grow unbounded per community. Mitigated by Redis maxmemory policy if set. |
| 10 | Scapy Privilege Escalation | HIGH | LOW | `SHADOW_AI_USE_SCAPY=false` by default. Real concern only when explicitly enabled. |
| 11 | Dev Defaults to Fail-Open | HIGH | HIGH | `WARDEN_API_KEY=""` + `WARDEN_API_KEYS_PATH=""` → all requests pass. `STRICT_MODE` env exists but not enforced at startup. |

---

## Remediation Plan

### P0 — Fix Before Next Production Deploy

---

#### Fix #11 — Startup Fail-Closed Enforcement

**File:** `warden/main.py` — `lifespan()` function  
**Risk:** Production deploy with blank WARDEN_API_KEY passes all requests unauthenticated.

```python
# In lifespan(), after settings load:
if not settings.warden_api_key and not settings.warden_api_keys_path:
    if os.getenv("ALLOW_UNAUTHENTICATED") != "true":
        raise RuntimeError(
            "FATAL: Neither WARDEN_API_KEY nor WARDEN_API_KEYS_PATH is set. "
            "Set ALLOW_UNAUTHENTICATED=true to explicitly allow open access (dev only)."
        )
    log.warning("AUTH DISABLED — dev mode. Never use in production.")
```

Add `ALLOW_UNAUTHENTICATED=true` to `.env.example` with a prominent comment.  
Add `ALLOW_UNAUTHENTICATED` to `warden/config.py` settings.

---

#### Fix #1 — VAULT_MASTER_KEY Startup Validation

**Files:** `warden/main.py` (lifespan), `warden/communities/keypair.py`, `warden/communities/data_pod.py`  
**Risk:** If VAULT_MASTER_KEY is not set or rotated between restarts, community keypairs and pod secret keys silently fail to decrypt with no error — corrupted data is returned or 500s are raised with no useful diagnostic.

```python
# warden/main.py lifespan() — add after settings validation
_vault_key = os.getenv("VAULT_MASTER_KEY") or os.getenv("COMMUNITY_VAULT_KEY")
if _vault_key:
    try:
        Fernet(_vault_key.encode() if isinstance(_vault_key, str) else _vault_key)
    except Exception as exc:
        raise RuntimeError(f"FATAL: VAULT_MASTER_KEY is not a valid Fernet key: {exc}") from exc
else:
    log.warning(
        "VAULT_MASTER_KEY not set — community keypairs and data pod secret keys "
        "will use an insecure dev fallback. Set in production."
    )
```

Additionally: document key rotation procedure in `docs/key-rotation.md`:
- Export current encrypted blobs before rotation
- Re-encrypt all community keypair rows with new key
- Verify decryption before retiring old key
- Recovery procedure: restore VAULT_MASTER_KEY from backup, not regenerate

---

### P1 — Fix Within 7 Days

---

#### Fix #3 — Shadow Ban Pool Expansion + True Randomization

**File:** `warden/shadow_ban.py`  
**Risk:** 6 deterministic responses allow fingerprinting the shadow ban in ~6 probes.

**Changes:**
1. Expand `_GASLIGHT_POOL` to 30+ entries covering varied domains (finance, medical, legal, devops, HR, infosec).
2. Replace deterministic hash selection with `secrets.choice()`.
3. Add per-entity timing jitter (50–250 ms uniform random delay, non-blocking: `asyncio.sleep`).

```python
import secrets

_GASLIGHT_POOL = [
    # ... 30+ entries ...
]

def _pick_response(entity_key: str, strategy: str = "standard") -> str:
    pool = _GASLIGHT_POOL if strategy == "gaslight" else _POOL
    return secrets.choice(pool)  # true random, not deterministic
```

For jitter, add to the shadow ban response path in `main.py`:
```python
import asyncio, random
if shadow_banned:
    await asyncio.sleep(random.uniform(0.05, 0.25))
```

---

#### Fix #6 — Causal Arbiter CPT Adversarial Validation Gate

**File:** `warden/causal_arbiter.py` — `calibrate_from_logs()`  
**Risk:** Coordinated low-volume attacks that just barely trigger HIGH/BLOCK can shift CPT distributions over time.

**Changes:**
1. Add statistical outlier detection before accepting new CPT values:

```python
def _is_cpt_update_safe(old_val: float, new_val: float, label: str) -> bool:
    """Block CPT updates that deviate more than 25% from the prior."""
    if old_val == 0:
        return True
    drift = abs(new_val - old_val) / old_val
    if drift > 0.25:
        log.warning(
            "calibrate_from_logs: CPT[%s] drift %.1f%% exceeds threshold — "
            "update rejected. Manual review required.", label, drift * 100
        )
        return False
    return True
```

2. Require minimum sample count before any update (currently 100 — raise to 500).
3. Add Prometheus metric `warden_cpt_drift_rejected_total` counter.
4. Add alert in `grafana/provisioning/alerting/warden_alerts.yml` for CPT drift rejections.

---

#### Fix #7 — SQLite DB-Level Encryption for Community Key Material

**File:** `warden/communities/keypair.py`, `warden/communities/sep.py`  
**Risk:** SQLite databases at `SEP_DB_PATH` store Fernet-encrypted private key fields, but the DB file itself is plaintext — an attacker with filesystem read access can extract all rows.

**Option A (recommended):** Use [SQLCipher](https://www.zetetic.net/sqlcipher/) via `pysqlcipher3`. Key derived from `VAULT_MASTER_KEY` via PBKDF2.

**Option B (simpler, no new dep):** Store community private keys in a separate encrypted file (one Fernet blob per keypair) rather than in SQLite rows. SQLite stores only the `kid` reference; private material is in `{COMMUNITY_KEY_ARCHIVE_PATH}/{kid}.enc`.

Option B implementation outline:
```python
def _write_private_key(kid: str, priv_bytes: bytes, fernet: Fernet) -> None:
    path = Path(os.getenv("COMMUNITY_KEY_ARCHIVE_PATH", "/tmp/warden_keys"))
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    key_file = path / f"{kid}.enc"
    key_file.write_bytes(fernet.encrypt(priv_bytes))
    key_file.chmod(0o600)

def _read_private_key(kid: str, fernet: Fernet) -> bytes:
    path = Path(os.getenv("COMMUNITY_KEY_ARCHIVE_PATH", "/tmp/warden_keys"))
    return fernet.decrypt((path / f"{kid}.enc").read_bytes())
```

Add `COMMUNITY_KEY_ARCHIVE_PATH` to env docs. Change default from `/tmp/...` to `/warden/data/keys` (persisted Docker volume).

---

### P2 — Fix Within 30 Days

---

#### Fix #2 — Regex Complexity Gate for Evolution Engine

**File:** `warden/brain/evolve.py`  
**Risk:** AI-generated regex patterns persisted to `dynamic_rules.json` are not ReDoS-checked before being loaded.

Note: Current code does NOT hot-load `regex_pattern` type rules into a live regex engine (only `semantic_example` calls `add_examples()`). The risk exists when/if regex rules are loaded at startup from `dynamic_rules.json`.

**Changes:**
1. Add `_validate_regex_safety()` gate called before persisting any `regex_pattern` rule:

```python
import re, concurrent.futures, time

_REDOS_CANARY = "a" * 10_000  # worst-case backtracking string

def _validate_regex_safety(pattern: str, timeout_s: float = 0.3) -> tuple[bool, str]:
    """Compile + test against a degenerate string. Reject if it times out or fails."""
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        return False, f"invalid regex: {exc}"
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(compiled.search, _REDOS_CANARY)
        try:
            future.result(timeout=timeout_s)
        except concurrent.futures.TimeoutError:
            return False, "ReDoS timeout on degenerate input"
    
    # Complexity heuristic: reject patterns with nested quantifiers
    DANGER = re.compile(r'(\(.*[+*{].*\)[+*{]|\[.*\][+*{][+*{])')
    if DANGER.search(pattern):
        return False, "nested quantifier structure detected"
    
    return True, "ok"
```

2. Call before `_persist(rule)` in `learn()`.
3. Add `google-re2` as optional dependency; if available, compile all dynamic patterns with RE2 instead of `re`.

---

#### Fix #8 — Caddy HTTP/3 0-RTT Disable for Mutating Endpoints

**File:** `docker/Caddyfile`  
**Risk:** 0-RTT resumption allows replay attacks on `POST /filter`, `POST /sep/*`, `POST /agent/*`.

Caddy does not yet expose per-route 0-RTT control (as of v2.8). Mitigate at the application layer:

```python
# warden/main.py — add middleware
@app.middleware("http")
async def reject_early_data(request: Request, call_next):
    if request.headers.get("Early-Data") == "1" and request.method != "GET":
        return JSONResponse({"detail": "0-RTT replay rejected"}, status_code=425)
    return await call_next(request)
```

HTTP 425 ("Too Early") is the RFC 8470 correct status for this.  
Document in `docs/security-model.md` under network controls.

---

#### Fix #4 — Timing Normalization for Early-Rejection Paths

**File:** `warden/main.py` — filter endpoint  
**Risk:** Short-circuit exits (auth fail → 0ms; topology block → 2ms; full pipeline → 40ms) create a timing oracle.

**Minimal mitigation** (no pipeline refactor):

```python
import time, asyncio

@app.post("/filter")
async def filter_request(req: FilterRequest, ...):
    _start = time.perf_counter()
    result = await _run_pipeline(req)
    elapsed = time.perf_counter() - _start
    # Pad to minimum 15ms to collapse timing oracle for early rejections
    pad = max(0.0, 0.015 - elapsed)
    if pad > 0:
        await asyncio.sleep(pad)
    return result
```

For high-security deployments: add `TIMING_PAD_MS` env var (default 15) configurable per tier.

---

#### Fix #9 — SEP Velocity Redis Memory Cap

**File:** `warden/communities/transfer_guard.py`  
**Risk:** Unbounded sorted sets per community can cause Redis OOM under a flood attack.

```python
# After ZADD in velocity tracking:
pipe.zadd(vel_key, {str(now): now})
pipe.zremrangebyscore(vel_key, 0, now - 3600)
pipe.expire(vel_key, 7200)
# Add explicit size cap (keep latest 10,000 entries max)
pipe.zremrangebyrank(vel_key, 0, -(10_001))  # trim oldest if > 10,000
```

Add Redis `maxmemory-policy allkeys-lru` to deployment docs as a global backstop.

---

### P3 — Operational / Documentation

---

#### Fix #10 — Alert on Scapy Fallback

**File:** `warden/shadow_ai/discovery.py`  
**Risk:** Silent fallback on `PermissionError` could mask container escape attempts.

```python
except PermissionError:
    log.warning(
        "SHADOW_AI: Scapy ARP probe failed (no CAP_NET_RAW) — "
        "falling back to full host list. If this is unexpected, investigate "
        "whether the container has been granted elevated privileges."
    )
    from warden.alerting import send_alert
    send_alert("[shadow-ai] Scapy CAP_NET_RAW fallback triggered — verify container privileges")
```

Never set `CAP_NET_RAW` in production `docker-compose.yml`. Document in `CONTRIBUTING.md` Docker standards.

---

#### Fix #5 — Cache Entry Metadata (Low Priority)

**File:** `warden/cache.py`  
**Risk:** SHA-256 is cryptographically sound. No action needed on the hash function. 

Add content-length to cache key as defense-in-depth:
```python
def _cache_key(content: str) -> str:
    return _PREFIX + hashlib.sha256(f"{len(content)}:{content}".encode()).hexdigest()
```

---

## Implementation Order

| Week | Items | Owner |
|------|-------|-------|
| Week 1 | P0: #11 fail-closed, #1 VAULT_MASTER_KEY validation | Backend |
| Week 2 | P1: #3 shadow ban expansion, #6 CPT drift gate | Backend |
| Week 3 | P1: #7 community key isolation | Backend + DevOps |
| Week 4 | P2: #2 regex gate, #8 Early-Data middleware | Backend |
| Week 5 | P2: #4 timing pad, #9 Redis cap | Backend |
| Week 6 | P3: #10 Scapy alert, #5 cache key, docs | Backend + Docs |

---

## Tests Required Per Fix

| Fix | New Test |
|-----|----------|
| #11 | `test_startup_fails_without_auth_key` — assert RuntimeError without ALLOW_UNAUTHENTICATED |
| #1  | `test_vault_key_validation` — assert RuntimeError on invalid Fernet key |
| #3  | `test_shadow_ban_response_uniqueness` — sample 100 calls, assert >10 unique responses |
| #3  | `test_shadow_ban_timing_jitter` — assert avg response time > 50ms under shadow ban |
| #6  | `test_cpt_drift_rejection` — feed 150% shift, assert metric counter increments |
| #7  | `test_private_key_not_in_sqlite` — assert no private key bytes in DB rows |
| #2  | `test_regex_redos_rejected` — feed `(a+)+$` pattern, assert validation returns False |
| #8  | `test_early_data_rejected` — send `Early-Data: 1` header on POST, assert 425 |
| #4  | `test_filter_minimum_latency` — assert early-block responses take ≥ 15ms |

---

## Out of Scope / Won't Fix

- **#5 SHA-256 collision** — computationally infeasible. SHA-256 is correct. Closed.
- **#10 Scapy in production** — already disabled by default. Documentation fix only.
- Full pipeline parallelism for timing (#4) — the 15ms pad is sufficient mitigation without a full pipeline refactor.
