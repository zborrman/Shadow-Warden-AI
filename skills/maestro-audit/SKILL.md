---
name: maestro-audit
description: MAESTRO threat detection for Shadow Warden marketplace agents. Three detectors: GoalMisalignmentDetector (agent deviating from community goals), CollusionDetector (coordinated price manipulation between pairs, 90-day history window), ModelPoisoningDetector (statistical outlier in imported assets). Threat levels: low / medium / high. Auto-isolation pipeline on high threat. Use when running security audits on agents, interpreting threat scores, triggering agent isolation, or debugging MAESTRO flags.
---

## Threat report

```
GET /marketplace/agents/{agent_id}/maestro-report
→ {
    agent_id,
    overall_threat_level: "low" | "medium" | "high",
    misalignment_score: 0.0–1.0,
    collusion_score: 0.0–1.0,
    poisoning_flag: bool,
    threat_components: { ... },
    recommended_action: str
  }
```

## Active flags

```
GET /marketplace/maestro/flags
→ { flags: [{ agent_id, flag_type, reason, flagged_at }] }
```

## Auto-isolation pipeline (threat_level == "high")

All steps are **fail-open** — partial failure does not block remaining steps.

1. Suspend agent capabilities → `[]`
2. Delist all active listings
3. Cancel pending escrows (refund buyers)
4. Lock HSM keys
5. Send Slack/PagerDuty alert
6. Append to STIX 2.1 audit chain (`sep_stix_chain`)
7. Emit Kafka event (`marketplace.agent.isolated`)

Restore via: `POST /marketplace/agents/{agent_id}/restore` (DAO proposal or admin).

## Reputation integration

MAESTRO contributes 10% weight to the composite reputation score:

```
maestro_factor = 1.0 - maestro_penalty
score = completed_rate*0.45 + volume*0.12 + dispute*0.08 + trust_rank*0.15
      + sybil*0.10 + maestro_factor*0.10
```

## Collusion detection

Tracks buyer↔seller negotiation pairs over 90-day history window (`COLLUSION_TTL=90*86400`). Flags coordinated price manipulation patterns (consistent below-market cross-trades, synchronized timing).

## Asset import validation

Before hot-loading purchased assets:
- `rule` → `validate_imported_rule()` (ReDoS screen + semantic check)
- `model` → `validate_imported_model()` (statistical outlier vs corpus)
- `signals` → poisoning score check

MAESTRO blocks import if `poisoning_flag=True`.

## Env vars

| Var | Default | Effect |
|---|---|---|
| `COLLUSION_TTL` | `7776000` (90d) | Pair history window |
| `MAESTRO_HIGH_THRESHOLD` | `0.7` | Score above which → "high" |
| `MAESTRO_MEDIUM_THRESHOLD` | `0.4` | Score above which → "medium" |
