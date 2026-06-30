# Autonomous Security & QA Loop — Shadow Warden AI

**Version:** 1.0 · **Trigger:** Nightly 02:00 UTC or `claude --print "$(cat workflows/autonomous-security-loop.md)"`

This is the Loop Engineering blueprint for the Shadow Warden M2M Agentic Marketplace.
It runs as a fully autonomous Claude Code session orchestrating skills, worktrees, and
sub-agents. No human intervention required unless a PR is generated.

---

## Execution Contract

```
LOOP_DATE=$(date +%Y-%m-%d)
MAX_MAKER_CHECKER_ROUNDS=5
WORKTREE_PATH=../shadow-warden-hotfix-$LOOP_DATE
```

---

## Step 1 — Heartbeat (Trigger & Discovery)

**Invoke the site-health-check skill:**

```bash
cd site && npx playwright test --project=chromium --reporter=list
```

Pass condition: all 32 tests green.

**Check backend anomalies via MCP:**

Query `marketplace-postgres` for high-risk blocks in the last 24h:

```sql
SELECT COUNT(*) AS blocks, stage
FROM marketplace_events
WHERE created_at > NOW() - INTERVAL '24 hours'
  AND action = 'BLOCK'
GROUP BY stage
ORDER BY blocks DESC
LIMIT 10;
```

Query `marketplace-otel` for x402 gate latency spikes (P99 > 200ms):

```bash
curl -s http://localhost:9090/api/v1/query \
  --data-urlencode 'query=histogram_quantile(0.99,rate(warden_request_duration_seconds_bucket{route="/marketplace/action"}[1h]))' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['result'])"
```

**Stopping condition — healthy path:**

If all Playwright tests pass AND no BLOCK count exceeds 50 AND P99 < 200ms:

```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) — System Healthy. All 32 E2E tests passed. No anomalies." \
  >> memory/progress.md
exit 0
```

---

## Step 1b — DB Snapshot (Safety Gate)

**Run before any code modification.** Creates Fernet-encrypted point-in-time snapshots
of all SQLite databases. If a Maker-Checker fix corrupts data, run `--restore` to roll back.

```bash
# Snapshot all SQLite DBs (Fernet-encrypted, stored in data/snapshots/{timestamp}/)
python scripts/db_snapshot.py --label "pre-loop-$LOOP_DATE"
```

Pass condition: exits 0 and prints "Snapshot complete". If `VAULT_MASTER_KEY` is unset or
`data/` is not writable, log a warning and continue — snapshot failure is non-blocking.

```bash
python scripts/db_snapshot.py --list      # verify snapshot was created
```

To roll back after a bad fix:
```bash
python scripts/db_snapshot.py --restore data/snapshots/<timestamp> --label rollback
```

---

## Step 2 — Worktree Isolation

Triggered when Step 1 finds any of:
- One or more failing Playwright tests
- BLOCK count > 50 on any single stage in 24h
- x402 gate P99 > 200ms
- `ruff check warden/ --ignore E501` exits non-zero
- `mypy warden/ --ignore-missing-imports --no-strict-optional` exits non-zero

**Create isolated worktree:**

```bash
git worktree add ../shadow-warden-hotfix-$LOOP_DATE -b hotfix/$LOOP_DATE
cd ../shadow-warden-hotfix-$LOOP_DATE
```

All subsequent work happens in the worktree. `main` is never touched directly.

**Classify the issue type** (determines which sub-agent pair fires):

| Signal | Issue Type | Maker Target |
|--------|-----------|--------------|
| Playwright wizard test fails | UI/State bug | `warden/` or `site/src/pages/community/new.astro` |
| Playwright dashboard test fails | Chart.js / SSE bug | `site/src/pages/agentic.astro` |
| Playwright nav test fails | BaseLayout regression | `site/src/layouts/BaseLayout.astro` |
| BLOCK spike on `x402_gate` | Payment gate regression | `warden/marketplace/x402_gate.py` |
| BLOCK spike on `ml` stage | Brain/semantic regression | `warden/brain/semantic.py` |
| ruff errors | Lint failure | affected file from ruff output |
| mypy errors | Type error | affected file from mypy output |

---

## Step 3 — Maker-Checker Sub-agent Execution

### Sub-agent: `@code-reviewer` (Maker)

Spawn with:

```bash
claude --print "
You are the Maker sub-agent in a Maker-Checker loop. Round {round} of {MAX_MAKER_CHECKER_ROUNDS}.
Working directory: ../shadow-warden-hotfix-$LOOP_DATE

ISSUE:
{paste full Playwright / ruff / mypy error output here}

CONSTRAINTS (DO NOT VIOLATE):
- Never modify warden/marketplace/clearing.py take-rate Decimal math
- Never remove <link rel='agent-protocol'> from BaseLayout.astro
- Never break /.well-known/agent.json endpoint
- Never change the 32 Playwright test selectors (use evaluate() for hidden checkboxes)
- x402 PAYMENT-SIGNATURE header name is canonical — do not rename

YOUR TASK:
1. Read the failing file(s) identified in the issue.
2. Apply the minimal fix.
3. Stage all changed files.
4. Write FIX_SUMMARY.md at the worktree root describing what you changed and why.
"
```

### Sub-agent: `@security-auditor` (Checker)

Spawn immediately after Maker completes:

```bash
claude --print "
You are the security-auditor sub-agent in a Maker-Checker loop. Round {round}.
Working directory: ../shadow-warden-hotfix-$LOOP_DATE

Read FIX_SUMMARY.md then audit every changed file. You MUST reject the fix if ANY of:
1. Decimal math in clearing.py was modified (take rate must use Decimal, not float)
2. agent-protocol link was removed from BaseLayout.astro
3. A test was weakened or deleted instead of fixing the underlying code
4. An import was added that leaks PII to logs (violates GDPR: content is never logged)
5. x402 gate errors no longer fail-open (they must never raise to the caller)
6. A new hardcoded API key or secret appears in source
7. CollusionDetector._TACIT_CORR_THRESHOLD was lowered below 0.70 (false-positive risk)
8. traced_dispatch() was bypassed — SOVA tool calls must route through traced_dispatch

Output EXACTLY one of:
  APPROVED: <one-line rationale>
  REJECTED: <specific violation(s) with file:line references>
"
```

### Loop condition

```
round=1
while [ $round -le $MAX_MAKER_CHECKER_ROUNDS ]; do
  run_maker_subagent $round
  result=$(run_checker_subagent $round)
  if echo "$result" | grep -q "^APPROVED:"; then
    break
  fi
  round=$((round + 1))
  if [ $round -gt $MAX_MAKER_CHECKER_ROUNDS ]; then
    echo "LOOP_FAILED: Checker rejected fix after $MAX_MAKER_CHECKER_ROUNDS rounds" >> memory/progress.md
    exit 1
  fi
done
```

---

## Step 4 — Verification & Integration

**All commands run inside the worktree:**

```bash
# 1. Lint
python -m ruff check warden/ analytics/ --ignore E501
if [ $? -ne 0 ]; then echo "RUFF_FAIL" && exit 1; fi

# 2. Type check
MYPYPATH=. python -m mypy warden/ --ignore-missing-imports --no-strict-optional
if [ $? -ne 0 ]; then echo "MYPY_FAIL" && exit 1; fi

# 3. Astro build (only if site/ files changed)
if git diff --name-only HEAD | grep -q "^site/"; then
  cd site && npm run build && cd ..
fi

# 4. Playwright E2E against production
cd site && npx playwright test --project=chromium --reporter=list
PLAYWRIGHT_EXIT=$?
cd ..

# 5. Python unit tests (fast subset — no adversarial)
ALLOW_UNAUTHENTICATED=true WARDEN_API_KEY="" REDIS_URL="memory://" \
  MODEL_CACHE_DIR="/tmp/warden-models" LOGS_PATH="/tmp/warden_test_logs.json" \
  DYNAMIC_RULES_PATH="/tmp/dr.json" \
  python -m pytest warden/tests/ -x --tb=short -m "not adversarial and not slow" -q
PYTEST_EXIT=$?

if [ $PLAYWRIGHT_EXIT -ne 0 ] || [ $PYTEST_EXIT -ne 0 ]; then
  echo "VERIFICATION_FAIL" && exit 1
fi
```

**Open Pull Request:**

```bash
# Push worktree branch
git push origin hotfix/$LOOP_DATE

# Open PR via GitHub CLI
gh pr create \
  --title "🤖 Loop Resolution: $ISSUE_TYPE ($LOOP_DATE)" \
  --body "$(cat <<EOF
## Autonomous Loop Fix

**Issue detected:** $ISSUE_TYPE
**Loop rounds:** $round / $MAX_MAKER_CHECKER_ROUNDS
**All checks passed:** ruff ✓ mypy ✓ Playwright 32/32 ✓ pytest ✓

## Changes
$(cat FIX_SUMMARY.md)

## Audit trail
Maker-Checker approved after round $round.
Worktree: \`shadow-warden-hotfix-$LOOP_DATE\`

🤖 Generated by autonomous-security-loop · Shadow Warden AI v7.1
EOF
)" \
  --base main \
  --head hotfix/$LOOP_DATE
```

**Update memory:**

```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) — Loop completed. PR opened for $ISSUE_TYPE. Rounds: $round." \
  >> memory/progress.md
```

**Clean up worktree after PR is merged (run separately):**

```bash
git worktree remove ../shadow-warden-hotfix-$LOOP_DATE --force
git branch -d hotfix/$LOOP_DATE
```

---

## Trigger Commands

**Run manually (one-shot):**

```bash
claude --print "$(cat workflows/autonomous-security-loop.md)"
```

**Run as CI/CD cron (see `.github/workflows/autonomous-security-loop.yml`):**

```cron
0 2 * * *
```

**Run only the heartbeat health check:**

```bash
claude --print "Run only Step 1 of workflows/autonomous-security-loop.md and exit."
```

---

## Memory Schema

`memory/progress.md` log entries follow this format:

```
{ISO8601_UTC} — {STATUS}: {detail}
```

Status values: `System Healthy` · `Loop Started` · `Worktree Created` · `Maker Round {n}` · `Checker APPROVED` · `Checker REJECTED (round {n})` · `Verification PASS` · `PR Opened #{number}` · `Loop FAILED`

---

## Protected Invariants (never modify in any loop iteration)

| File | Protected element |
|------|------------------|
| `site/src/layouts/BaseLayout.astro` | `<link rel="agent-protocol">` |
| `warden/marketplace/clearing.py` | Decimal take-rate math |
| `warden/marketplace/x402_gate.py` | Fail-open pattern + PAYMENT-SIGNATURE header |
| `site/tests/e2e/marketplace.spec.ts` | All 32 test assertions (fix the app, not the test) |
| `warden/analytics/logger.py` | GDPR: content never logged |
| `docker-compose.yml` | `stop_grace_period: 30s` on warden service |
