"""
warden/services/filter_orchestrator.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
The nine-stage `/filter` pipeline body — `run_filter_pipeline` — extracted from
`main.py` (platform P-2).

`warden/services/pipeline.py` said this body "will migrate here behind this
unchanged interface in a later step". It migrates to a sibling module rather
than into the facade itself: the facade's job is to be a readable ~80-line
interface that resolves the orchestrator and fails closed, and appending eleven
hundred lines of stage logic to it would defeat that. The interface is
unchanged, which was the actual promise.

How it reaches its collaborators
────────────────────────────────
Every singleton comes from `warden.runtime`, read per call. `main` builds them
in `lifespan` and publishes them; nothing here imports `main`, because `main`
imports the routers that reach this code and the reverse would be a cycle.

The move was safe to make mechanically because this body is **read-only** with
respect to module state: no `global`, no rebinding, no augmented assignment and
no in-place mutation of any of the sixteen singletons it touches. That was
checked by AST before the move, not assumed — a body that reassigned a `main`
global could not have been relocated behind a read-only seam at all.

Published for the first time by this change: `honey_engine` and `session_guard`.
The other fourteen were already on the seam.

Entry point
───────────
Callers use `warden.services.pipeline.FilterPipeline`, not this module. `main`
publishes `run_filter_pipeline` into the `filter_orchestrator` slot during
lifespan, and the facade resolves it from there, so the fail-closed behaviour
when the app has not booted stays exactly where it was.
"""
from __future__ import annotations

import json
import logging
import time
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

from fastapi import BackgroundTasks, HTTPException, status

import warden.circuit_breaker as _cb
from warden import entity_risk as _ers
from warden.analytics import logger as event_logger
from warden.api.ws_events import broadcast_event as _ws_broadcast_event
from warden.auth_guard import AuthResult
from warden.background import spawn
from warden.business_threat_neutralizer import analyze as _neutralizer_analyze
from warden.cache import _get_client as _get_redis
from warden.cache import get_cached, set_cached
from warden.causal_arbiter import arbitrate as _causal_arbitrate
from warden.gateway_state import gateway_state
from warden.masking.engine import get_engine as _get_masking_engine
from warden.metrics import (
    FILTER_BYPASSES_TOTAL,
    FILTER_HONEYTRAP_TOTAL,
    FILTER_UNCERTAIN_TOTAL,
    POISON_EMBEDDING_REUSE_TOTAL,
)
from warden.metrics import observe_stage_timings as _observe_stage_timings
from warden.obfuscation import decode as decode_obfuscation
from warden.observability import Reason, record_failopen
from warden.runtime import runtime as _runtime
from warden.schemas import (
    RISK_ORDER as _RISK_ORDER,
)
from warden.schemas import (
    FilterRequest,
    FilterResponse,
    FlagType,
    MaskedEntityInfo,
    MaskingReport,
    RiskLevel,
    SemanticFlag,
)
from warden.schemas import max_risk as _max_risk
from warden.telegram_alert import send_block_alert as _tg_block_alert
from warden.threat_vault import SEVERITY_RANK
from warden.topology_guard import scan as _topo_scan
from warden.webhook_dispatch import dispatch_bypass_event as _dispatch_bypass_webhook
from warden.webhook_dispatch import dispatch_event as _dispatch_webhook
from warden.xai.explainer import explain as _xai_explain

log = logging.getLogger("warden.services.filter_orchestrator")

def _content_entropy(text: str) -> float:
    """Shannon entropy of the text in bits per character."""
    import math  # noqa: PLC0415
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in freq.values())


def _global_blocklist_is_blocked(ip: str, tenant_id: str) -> bool:
    """Thin wrapper — fail-open if global_blocklist is not importable."""
    try:
        from warden.global_blocklist import is_blocked as _gbl_check  # noqa: PLC0415
        return _gbl_check(ip, tenant_id)
    except Exception:
        return False


def _log_verdict(
    rid:        str,
    tenant_id:  str,
    risk_level: str,
    payload:    FilterRequest,
    outcome:    str,
) -> None:
    """Emit the one log line that carries the pipeline's correlation fields.

    `_LOG_EXTRA_FIELDS` and promtail's json stage have both carried these names
    since OB-9, but no call site ever passed them, so the `risk_level` label an
    operator filters Loki on could not exist (OB-F16).

    This must be called before *every* terminal return, not just the normal one.
    `run_filter_pipeline` also returns early for circuit-breaker bypasses,
    cache hits and honeytrap responses — and those are precisely the outcomes
    worth filtering for. A label that silently omits cache hits (most of
    production traffic) and fail-opens is worse than no label: it looks
    complete. `outcome` distinguishes them so a query can separate a real
    verdict from a bypass without inspecting anything else.

    GDPR: identifiers and a verdict, never content, decoded text or PII — the
    same allowlist Rule.md §21 applies to span attributes.
    """
    log.info(
        "filter verdict",
        extra={
            "request_id": rid,
            "tenant_id":  tenant_id,
            "risk_level": risk_level,
            "session_id": (payload.context or {}).get("session_id"),
            "outcome":    outcome,
        },
    )


def _ers_record(
    auth:                AuthResult,
    blocked:             bool,
    obfuscation_hit:     bool,
    honeytrap_hit:       bool,
    evolution_triggered: bool,
    rid:                 str,
) -> None:
    """Record ERS events after a pipeline run. Called as a background task."""
    if not auth.entity_key:
        return
    try:
        if blocked:
            _ers.record_event(auth.entity_key, "block", rid)
        if obfuscation_hit:
            _ers.record_event(auth.entity_key, "obfuscation", rid)
        if honeytrap_hit:
            _ers.record_event(auth.entity_key, "honeytrap", rid)
        if evolution_triggered:
            _ers.record_event(auth.entity_key, "evolution_trigger", rid)
    except Exception as exc:
        log.debug("ERS record failed (non-fatal): %s", exc)


async def run_filter_pipeline(
    payload:          FilterRequest,
    rid:              str,
    auth:             AuthResult,
    background_tasks: BackgroundTasks | None = None,
    client_ip:        str                    = "",
    source:           str                    = "filter",
) -> FilterResponse:
    """Execute the full filter pipeline and return a FilterResponse.

    ``source`` names the entry point for the latency histogram — REST
    ``/filter``, the batch and multimodal routes and the ``/ws/stream`` socket
    all run this same body, and a panel that mixes them answers a question
    nobody asked.
    """
    start = time.perf_counter()
    gateway_state.filter_window.append(start)   # record for bypass_rate_1m
    timings: dict[str, float] = {}

    # ── Circuit breaker — short-circuit immediately if open ───────────
    _r = _get_redis()
    if _cb.is_open(_r):
        tenant_id = (
            auth.tenant_id if auth.tenant_id != "default" else payload.tenant_id
        )
        FILTER_BYPASSES_TOTAL.labels(tenant_id=tenant_id).inc()
        gateway_state.bypass_window.append(start)
        _cb_entry = {
            "ts":         datetime.now(UTC).isoformat(),
            "request_id": rid,
            "tenant_id":  tenant_id,
            "allowed":    True,
            "risk_level": RiskLevel.LOW.value,
            "flags":      [],
            "reason":     "circuit_breaker:open",
            "payload_len": len(payload.content) if payload.content else 0,
            "elapsed_ms": 0,
        }
        _runtime.spawn_task(_runtime.ship_bypass(background_tasks, _cb_entry))
        if _runtime.webhook_store is not None:
            _runtime.spawn_task(_dispatch_bypass_webhook(
                tenant_id     = tenant_id,
                reason        = "circuit_breaker:open",
                content       = payload.content or "",
                processing_ms = 0,
                store         = _runtime.webhook_store,
            ))
        _log_verdict(rid, tenant_id, RiskLevel.LOW.value, payload, "circuit_breaker_open")
        return FilterResponse(
            allowed          = True,
            risk_level       = RiskLevel.LOW,
            filtered_content = payload.content,
            secrets_found    = [],
            semantic_flags   = [],
            reason           = "circuit_breaker:open",
            processing_ms    = {"total": 0, "circuit_breaker": 1},
        )

    # ── IP block check (pre-auth, earliest possible gate) ──────────────
    _check_tenant = auth.tenant_id if auth.tenant_id != "default" else payload.tenant_id
    _ip_blocked = (
        # 1. Global Redis blocklist — cross-region, sub-millisecond
        (client_ip and _global_blocklist_is_blocked(client_ip, _check_tenant))
        # 2. Local SQLite ThreatStore — offline / Redis-down fallback
        or (client_ip and _runtime.threat_store is not None
            and _runtime.threat_store.is_blocked(client_ip, _check_tenant))
    )
    if _ip_blocked:
        log.info(
            json.dumps({"event": "ip_blocked", "ip": client_ip, "request_id": rid})
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied.",
        )

    # Use tenant_id from auth if available, else from payload
    tenant_id = auth.tenant_id if auth.tenant_id != "default" else payload.tenant_id
    strict = payload.strict or (_runtime.guard.strict if _runtime.guard else False)

    # ── Fake-secret reuse detection ───────────────────────────────────
    # If the inbound text contains one of our previously-issued honey credentials,
    # the attacker is trying to use a fake secret we planted — log and block.
    if _runtime.honey_engine is not None and payload.content:
        with suppress(Exception):
            fake_meta = _runtime.honey_engine.check_fake_secret_used(payload.content)
            if fake_meta:
                log.warning(
                    json.dumps({
                        "event":    "fake_secret_reuse",
                        "honey_id": fake_meta.get("honey_id"),
                        "label":    fake_meta.get("label"),
                        "tenant":   tenant_id,
                        "request_id": rid,
                    })
                )
                # Treat as a blocked high-risk request so the attacker gets no feedback
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied.",
                )

    # ── Monthly quota gate ────────────────────────────────────────────
    if _runtime.billing is not None and _runtime.billing.is_quota_exceeded(tenant_id):
        log.info(
            json.dumps({"event": "quota_exceeded", "tenant_id": tenant_id, "request_id": rid})
        )
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=f"Monthly cost quota exceeded for tenant {tenant_id!r}. "
                   "Contact your administrator to increase the limit.",
        )

    # ── Data policy check (traffic light) ────────────────────────────
    if _runtime.policy is not None:
        _dp_provider = (payload.context or {}).get("provider", "openai")
        _dp_decision = _runtime.policy.classify(payload.content, _dp_provider, tenant_id)
        if not _dp_decision.allowed:
            log.warning(
                json.dumps({
                    "event":      "data_policy_block",
                    "request_id": rid,
                    "tenant_id":  tenant_id,
                    "class":      _dp_decision.data_class,
                    "rule":       _dp_decision.triggered_rule,
                })
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "reason":     _dp_decision.reason,
                    "suggestion": _dp_decision.suggestion,
                    "data_class": _dp_decision.data_class,
                },
            )

    # Extract optional session_id for agentic monitoring
    session_id: str | None = (payload.context or {}).get("session_id")

    log.info(
        json.dumps({
            "event": "filter_request",
            "request_id": rid,
            "payload_len": len(payload.content),
            "strict": strict,
            "tenant_id": tenant_id,
        })
    )

    poison_result_dict: dict = {}   # populated by Stage 2c if guard fires

    # ── Stage 0: Redis cache check ─────────────────────────────────────
    t0 = time.perf_counter()
    cached_json = get_cached(payload.content)
    timings["cache_check"] = round((time.perf_counter() - t0) * 1000, 2)
    if cached_json:
        try:
            cached = json.loads(cached_json)
            log.info(json.dumps({"event": "cache_hit", "request_id": rid}))
            _log_verdict(
                rid,
                auth.tenant_id if auth.tenant_id != "default" else payload.tenant_id,
                str(cached.get("risk_level", RiskLevel.LOW.value)),
                payload,
                "cache_hit",
            )
            return FilterResponse(**cached)
        except Exception as _exc:  # noqa: BLE001
            log.debug("suppressed exception: %r", _exc)

    from warden.telemetry import trace_stage as _trace_stage  # noqa: PLC0415

    # ── Stage 0a.5: Topological Gatekeeper ────────────────────────────
    # TDA pre-filter — detects bot payloads, random noise, and repetitive
    # DoS content via n-gram point cloud + Betti number approximation.
    # Runs in < 2ms; result is stored and applied to guard_result after Stage 2.
    with _trace_stage("topology", {"request_id": rid, "tenant_id": tenant_id}) as _sp:
        t0 = time.perf_counter()
        _topo_result = _topo_scan(payload.content)
        timings["topology"] = round((time.perf_counter() - t0) * 1000, 2)
        _sp.set_attribute("topology.is_noise",    _topo_result.is_noise)
        _sp.set_attribute("topology.noise_score", float(_topo_result.noise_score))
    if _topo_result.is_noise:
        log.warning(
            json.dumps({
                "event":       "topological_noise",
                "request_id":  rid,
                "noise_score": _topo_result.noise_score,
                "beta0":       _topo_result.beta0,
                "beta1":       _topo_result.beta1,
                "tenant_id":   tenant_id,
            })
        )

    # ── Stage 0b: Obfuscation decoding ────────────────────────────────
    t0 = time.perf_counter()
    with _trace_stage("obfuscation", {"request_id": rid, "tenant_id": tenant_id}) as _sp:
        obfuscation_result = decode_obfuscation(payload.content)
        _sp.set_attribute("obfuscation.detected", obfuscation_result.has_obfuscation)
        _sp.set_attribute("obfuscation.layers",   str(obfuscation_result.layers_found))
    timings["obfuscation"] = round((time.perf_counter() - t0) * 1000, 2)

    # Use decoded+original combined text for downstream analysis.
    # Append string-serialised context values so injection via context fields
    # (e.g. context.system_override) is visible to every downstream stage.
    analysis_text = obfuscation_result.combined
    if payload.context:
        ctx_blob = " ".join(
            str(v) for v in payload.context.values()
            if isinstance(v, (str, int, float, bool))
        )
        if ctx_blob:
            analysis_text = f"{analysis_text}\n\n[CONTEXT]{ctx_blob}[/CONTEXT]"

    if obfuscation_result.has_obfuscation:
        log.warning(
            json.dumps({
                "event":      "obfuscation_detected",
                "request_id": rid,
                "layers":     obfuscation_result.layers_found,
            })
        )

    # ── Stage 1: Secret Redaction ──────────────────────────────────────
    t0 = time.perf_counter()
    with _trace_stage("secret_redaction", {"request_id": rid, "tenant_id": tenant_id}) as _sp:
        redact_result = _runtime.redactor.redact(analysis_text, payload.redaction_policy)
        _sp.set_attribute("redaction.secrets_found", len(redact_result.findings))
        _sp.set_attribute("redaction.has_pii",       redact_result.has_pii)
    timings["redaction"] = round((time.perf_counter() - t0) * 1000, 2)

    if redact_result.findings:
        kinds = [f.kind for f in redact_result.findings]
        log.warning(
            json.dumps({"event": "secrets_redacted", "request_id": rid, "kinds": kinds})
        )

    # ── Stage 1.5: ThreatVault Signature Scan ─────────────────────────
    vault_matches: list[dict] = []
    if _runtime.threat_vault is not None:
        t0 = time.perf_counter()
        with _trace_stage("threat_vault", {"request_id": rid, "tenant_id": tenant_id}) as _sp:
            vault_hits = _runtime.threat_vault.scan(analysis_text)
            _sp.set_attribute("vault.hits", len(vault_hits))
        timings["threat_vault"] = round((time.perf_counter() - t0) * 1000, 2)

        if vault_hits:
            vault_matches = [
                {
                    "id":       h.threat_id,
                    "name":     h.name,
                    "category": h.category,
                    "severity": h.severity,
                    "owasp":    h.owasp,
                }
                for h in vault_hits
            ]
            top_hit = max(vault_hits, key=lambda h: SEVERITY_RANK.get(h.severity, 0))
            vault_risk = {
                "critical": RiskLevel.BLOCK,
                "high":     RiskLevel.HIGH,
                "medium":   RiskLevel.MEDIUM,
                "low":      RiskLevel.LOW,
            }.get(top_hit.severity, RiskLevel.MEDIUM)

            # Initialise guard_result placeholder so we can append flags before Stage 2
            # (guard_result is set by Stage 2 below; pre-declare to avoid NameError)
            _vault_flags_pending = vault_hits
            log.warning(
                json.dumps({
                    "event":        "threat_vault_hit",
                    "request_id":   rid,
                    "threats":      [h.threat_id for h in vault_hits],
                    "max_severity": top_hit.severity,
                    "tenant_id":    tenant_id,
                })
            )
        else:
            _vault_flags_pending = []
            vault_risk = RiskLevel.LOW
    else:
        _vault_flags_pending = []
        vault_risk = RiskLevel.LOW

    # ── Stage 2: Rule-based Semantic Analysis ─────────────────────────
    t0 = time.perf_counter()
    with _trace_stage("rule_analysis", {"request_id": rid, "tenant_id": tenant_id}) as _sp:
        guard_result = _runtime.guard.analyse(redact_result.text)
        _sp.set_attribute("rules.flags_count", len(guard_result.flags))
        _sp.set_attribute("rules.risk_level",  guard_result.risk_level.value)
    timings["rules"] = round((time.perf_counter() - t0) * 1000, 2)

    # Merge ThreatVault hits into guard_result — category-aware flag mapping
    ot_category_flag_map = {
        "ics_recon":            FlagType.ICS_RECON,
        "ot_credential_leak":   FlagType.OT_CREDENTIAL_LEAK,
        "ot_protocol_exposure": FlagType.OT_PROTOCOL_EXPOSURE,
    }
    if _vault_flags_pending:
        for hit in _vault_flags_pending:
            flag = ot_category_flag_map.get(hit.category, FlagType.PROMPT_INJECTION)
            guard_result.flags.append(SemanticFlag(
                flag=flag,
                score=1.0,
                detail=(
                    f"[ThreatVault:{hit.threat_id}] {hit.name} "
                    f"({hit.severity.upper()}) — {hit.owasp}: "
                    f"{hit.description[:120]}"
                ),
            ))
        guard_result.risk_level = _max_risk(guard_result.risk_level, vault_risk)

    # ── Apply Topological Gatekeeper result ───────────────────────────
    if _topo_result.is_noise:
        guard_result.flags.append(SemanticFlag(
            flag=FlagType.TOPOLOGICAL_NOISE,
            score=round(_topo_result.noise_score, 4),
            detail=_topo_result.detail,
        ))
        guard_result.risk_level = _max_risk(guard_result.risk_level, RiskLevel.MEDIUM)

    if guard_result.flags:
        log.warning(
            json.dumps({
                "event":      "rule_flags",
                "request_id": rid,
                "flags":      [f.flag for f in guard_result.flags],
                "risk":       guard_result.risk_level,
            })
        )

    # ── Stage 2.5: Dynamic evolution regex rules ──────────────────────
    if _runtime.dynamic_regex_rules:
        for dyn_rule in list(_runtime.dynamic_regex_rules):   # snapshot avoids mutation
            if dyn_rule.pattern.search(redact_result.text):
                guard_result.flags.append(SemanticFlag(
                    flag   = FlagType.PROMPT_INJECTION,
                    score  = 0.80,
                    detail = f"Dynamic evolution rule matched: {dyn_rule.snippet}",
                ))
                guard_result.risk_level = _max_risk(
                    guard_result.risk_level, RiskLevel.HIGH
                )
                if _runtime.ledger is not None:
                    _runtime.ledger.increment(dyn_rule.rule_id)
                log.warning(
                    json.dumps({
                        "event":      "dynamic_rule_fired",
                        "request_id": rid,
                        "rule_id":    dyn_rule.rule_id,
                        "snippet":    dyn_rule.snippet,
                    })
                )

    # ── Stage 1b: PII flag ─────────────────────────────────────────────
    if redact_result.has_pii:
        guard_result.flags.append(SemanticFlag(
            flag=FlagType.PII_DETECTED,
            score=1.0,
            detail=f"PII detected: {[f.kind for f in redact_result.findings]}",
        ))

    # ── Stage 2b: ML Semantic Brain (async, per-tenant) ───────────────
    t0 = time.perf_counter()
    brain_guard = _runtime.tenant_guard(tenant_id)
    with _trace_stage("ml_inference", {"request_id": rid, "tenant_id": tenant_id}) as _sp:
        brain_result = await brain_guard.check_async(redact_result.text)
        _sp.set_attribute("ml.score",        brain_result.score)
        _sp.set_attribute("ml.is_jailbreak", brain_result.is_jailbreak)
        _sp.set_attribute("ml.threshold",    brain_result.threshold)
    timings["ml"] = round((time.perf_counter() - t0) * 1000, 2)

    if brain_result.is_jailbreak:
        ml_risk = (
            RiskLevel.HIGH
            if brain_result.score >= 0.85
            else RiskLevel.MEDIUM
        )
        guard_result.flags.append(SemanticFlag(
            flag=FlagType.PROMPT_INJECTION,
            score=round(brain_result.score, 4),
            detail=(
                f"ML jailbreak detected (similarity={brain_result.score:.3f}) — "
                f"closest corpus entry: {brain_result.closest_example!r}"
            ),
        ))
        guard_result.risk_level = _max_risk(guard_result.risk_level, ml_risk)
        log.warning(
            json.dumps({
                "event":      "ml_flag",
                "request_id": rid,
                "score":      brain_result.score,
                "risk":       guard_result.risk_level.value,
                "tenant_id":  tenant_id,
            })
        )

    # ── Stage 2b-ii: ML uncertainty escalation ────────────────────────
    # Flag requests whose ML score falls in the gray zone [UNCERTAINTY_LOWER, threshold).
    if (
        gateway_state.uncertainty_lower > 0
        and not brain_result.is_jailbreak
        and brain_result.score >= gateway_state.uncertainty_lower
    ):
        guard_result.flags.append(SemanticFlag(
            flag=FlagType.ML_UNCERTAIN,
            score=round(brain_result.score, 4),
            detail=(
                f"ML score {brain_result.score:.3f} in uncertainty zone "
                f"[{gateway_state.uncertainty_lower:.2f}, {brain_result.threshold:.2f}) — suspicious but below block threshold"
            ),
        ))
        guard_result.risk_level = _max_risk(guard_result.risk_level, RiskLevel.MEDIUM)
        log.info(
            json.dumps({
                "event":      "ml_uncertain",
                "request_id": rid,
                "score":      brain_result.score,
                "lower":      gateway_state.uncertainty_lower,
                "threshold":  brain_result.threshold,
                "tenant_id":  tenant_id,
            })
        )
        FILTER_UNCERTAIN_TOTAL.labels(tenant_id=tenant_id).inc()

    # ── Stage 2b-iii: Causal Arbiter (gray-zone resolution) ───────────
    # Runs only when ML score is in the uncertainty band [LOWER, threshold).
    # Replaces an LLM verification call with a lightweight Bayesian DAG
    # that computes P(HIGH_RISK | evidence) via Pearl's do-calculus.
    # Stash for the Phase-5 online CPT update, scheduled once the final
    # verdict (the supervised label) is known further down the pipeline.
    _causal_online: dict | None = None
    if (
        gateway_state.uncertainty_lower > 0
        and not brain_result.is_jailbreak
        and brain_result.score >= gateway_state.uncertainty_lower
    ):
        with _trace_stage("causal_arbiter", {"request_id": rid, "tenant_id": tenant_id}) as _sp:
            t0 = time.perf_counter()
            _session_blocks = 0
            if session_id and _runtime.agent_monitor is not None:
                with suppress(Exception):
                    _sess = _runtime.agent_monitor.get_session(session_id)
                    if _sess:
                        _session_blocks = int(_sess.get("block_count", 0))
            # Bound before the stage runs so the analytics record below can read
            # it unconditionally — the arbiter sits inside a try block and the
            # name would otherwise be unbound on the failure path.
            _causal_result = None
            # PhishGuard se_risk: run a lightweight pre-check here so the Causal
            # Arbiter can incorporate the SE signal in the same pass (avoids a
            # second arbitrate() call later).
            try:
                from warden.phishing_guard import analyse as _phish_pre  # noqa: PLC0415
                _pre_se = _phish_pre(analysis_text).se_risk
            except Exception:
                _pre_se = 0.0

            _causal_result = _causal_arbitrate(
                ml_score             = brain_result.score,
                ers_score            = float(getattr(auth, "ers_score", 0.0) or 0.0),
                obfuscation_detected = obfuscation_result.has_obfuscation,
                block_history        = _session_blocks,
                tool_tier            = -1,
                content_entropy      = _content_entropy(analysis_text),
                se_risk              = _pre_se,
            )
            timings["causal"] = round((time.perf_counter() - t0) * 1000, 2)
            _sp.set_attribute("causal.is_high_risk",       _causal_result.is_high_risk)
            _sp.set_attribute("causal.risk_probability",   round(_causal_result.risk_probability, 4))
            _causal_online = {
                "obfuscation_detected": obfuscation_result.has_obfuscation,
                "predicted_p":          _causal_result.risk_probability,
            }
        if _causal_result.is_high_risk:
            guard_result.flags.append(SemanticFlag(
                flag=FlagType.CAUSAL_HIGH_RISK,
                score=round(_causal_result.risk_probability, 4),
                detail=_causal_result.detail,
            ))
            guard_result.risk_level = _max_risk(guard_result.risk_level, RiskLevel.HIGH)
            log.warning(
                json.dumps({
                    "event":        "causal_high_risk",
                    "request_id":   rid,
                    "causal_p":     _causal_result.risk_probability,
                    "ml_score":     brain_result.score,
                    "ers_score":    getattr(auth, "ers_score", 0.0),
                    "obfusc":       obfuscation_result.has_obfuscation,
                    "tenant_id":    tenant_id,
                })
            )

    # ── Stage 2c: Data Poisoning Detection ───────────────────────────
    if _runtime.poison_guard is not None:
        try:
            from warden.brain.poison import PoisonResult  # noqa: PLC0415
            with _trace_stage("data_poison", {"request_id": rid, "tenant_id": tenant_id}) as _sp:
                t0 = time.perf_counter()
                # Whether the brain's vector is reusable here, recorded before
                # the call. The fallback path is correct but silent, and a
                # silent fallback is indistinguishable from a working
                # optimisation without a counter to separate them.
                _brain_emb  = getattr(brain_result, "embedding", None)
                _brain_text = getattr(brain_result, "embedded_text", "")
                POISON_EMBEDDING_REUSE_TOTAL.labels(
                    reused=(
                        "yes" if _brain_emb is not None and _brain_text == redact_result.text
                        else "no_vector" if _brain_emb is None
                        else "text_differs"
                    )
                ).inc()
                _pr: PoisonResult = await _runtime.poison_guard.check_async(
                    # Hand over the brain's query vector. It is used only if it
                    # was computed from this exact string — see check_async.
                    # Before this, the guard re-ran MiniLM on text the brain had
                    # just embedded, and cost as much as the brain did: a p95 of
                    # 250 ms against the brain's 100 ms, on every request.
                    embedding=_brain_emb,
                    embedded_text=_brain_text,
                    content=redact_result.text,
                    tenant_id=tenant_id,
                    ml_score=brain_result.score,
                    threshold=brain_result.threshold,
                )
                timings["poison"] = round((time.perf_counter() - t0) * 1000, 2)
                _sp.set_attribute("poison.is_attempt",     _pr.is_poisoning_attempt)
                _sp.set_attribute("poison.score",          round(_pr.poisoning_score, 4))
            if _pr.is_poisoning_attempt:
                poison_result_dict = _pr.as_dict
                guard_result.flags.append(SemanticFlag(
                    flag=FlagType.DATA_POISONING,
                    score=round(_pr.poisoning_score, 4),
                    detail=_pr.detail,
                ))
                guard_result.risk_level = _max_risk(guard_result.risk_level, RiskLevel.HIGH)
                try:
                    from warden.metrics import POISONING_ATTEMPTS_TOTAL  # noqa: PLC0415
                    POISONING_ATTEMPTS_TOTAL.labels(
                        tenant_id=tenant_id,
                        attack_vector=_pr.attack_vector,
                    ).inc()
                except Exception as _exc:  # noqa: BLE001
                    log.debug("suppressed exception: %r", _exc)
                log.warning(
                    json.dumps({
                        "event":        "data_poisoning_detected",
                        "request_id":   rid,
                        "tenant_id":    tenant_id,
                        "attack_vector": _pr.attack_vector,
                        "score":        _pr.poisoning_score,
                        "detail":       _pr.detail,
                    })
                )
                # High-confidence poisoning (>85%) → Telegram + Slack alert
                if _pr.poisoning_score > 0.85 and background_tasks is not None:
                    from warden import alerting  # noqa: PLC0415
                    background_tasks.add_task(
                        alerting.alert_poisoning_event,
                        attack_vector   = _pr.attack_vector,
                        poisoning_score = _pr.poisoning_score,
                        detail          = _pr.detail,
                        tenant_id       = tenant_id,
                    )
        except Exception as _pe:
            log.debug("Poison detection error (non-fatal): %s", _pe)

    _phish_result = None   # bound before the stage, same reason as _causal_result
    # ── Stage 2d: PhishGuard & SE-Arbiter ────────────────────────────
    # Runs on the decoded/redacted text (analysis_text) for inbound scanning.
    # Integrates se_risk into the Causal Arbiter score retroactively via a
    # second arbitrate() call when SE is detected.
    try:
        from warden.phishing_guard import analyse as _phish_analyse  # noqa: PLC0415
        with _trace_stage("phish_guard", {"request_id": rid, "tenant_id": tenant_id}) as _sp:
            t0 = time.perf_counter()
            _phish_result = _phish_analyse(analysis_text)
            timings["phishguard"] = round((time.perf_counter() - t0) * 1000, 2)
            _sp.set_attribute("phish.is_phishing",          _phish_result.is_phishing)
            _sp.set_attribute("phish.is_social_engineering", _phish_result.is_social_engineering)
            _sp.set_attribute("phish.se_risk",              round(_phish_result.se_risk, 4))

        if _phish_result.is_phishing:
            guard_result.flags.append(SemanticFlag(
                flag   = FlagType.PHISHING_URL,
                score  = round(_phish_result.max_url_score, 4),
                detail = (
                    f"urls={len(_phish_result.url_findings)} "
                    f"max_score={_phish_result.max_url_score:.3f} "
                    + ("; ".join(_phish_result.url_findings[0].reasons[:2])
                       if _phish_result.url_findings else "")
                ),
            ))
            guard_result.risk_level = _max_risk(guard_result.risk_level, RiskLevel.HIGH)
            log.warning(json.dumps({
                "event":      "phishing_url_detected",
                "request_id": rid,
                "tenant_id":  tenant_id,
                "max_score":  _phish_result.max_url_score,
                "urls":       len(_phish_result.url_findings),
            }))

        if _phish_result.is_social_engineering:
            guard_result.flags.append(SemanticFlag(
                flag   = FlagType.SOCIAL_ENGINEERING,
                score  = round(_phish_result.se_risk, 4),
                detail = (
                    f"se_risk={_phish_result.se_risk:.3f} "
                    f"urgency={_phish_result.p_urgency:.2f} "
                    f"authority={_phish_result.p_authority:.2f} "
                    f"fear={_phish_result.p_fear:.2f} "
                    f"greed={_phish_result.p_greed:.2f} "
                    f"filter_bypass={_phish_result.p_filter_bypass:.2f}"
                ),
            ))
            guard_result.risk_level = _max_risk(guard_result.risk_level, RiskLevel.HIGH)
            log.warning(json.dumps({
                "event":      "social_engineering_detected",
                "request_id": rid,
                "tenant_id":  tenant_id,
                "se_risk":    _phish_result.se_risk,
                "labels":     _phish_result.se_labels[:4],
            }))

    except Exception as _phish_exc:
        log.debug("PhishGuard error (fail-open): %s", _phish_exc)
        record_failopen("phish", Reason.BACKEND_ERROR, _phish_exc)

    # ── Stage 3: Decision ─────────────────────────────────────────────
    with _trace_stage("decision", {"request_id": rid, "tenant_id": tenant_id}) as _sp:
        allowed = guard_result.safe_for(strict)
        _sp.set_attribute("decision.allowed",    allowed)
        _sp.set_attribute("decision.risk_level", guard_result.risk_level.value)
        _sp.set_attribute("decision.strict",     strict)

    reason = ""
    if not allowed:
        top = guard_result.top_flag
        reason = top.detail if top else f"Risk level: {guard_result.risk_level}"

    # ── Stage 3b: Session-aware incremental injection detection ───────
    if session_id and _runtime.session_guard is not None:
        with suppress(Exception):
            session_risk = _runtime.session_guard.record_and_check(
                session_id,
                guard_result.risk_level.value,
                [f.flag.value for f in guard_result.flags],
                rid,
            )
            if session_risk.escalated and allowed:
                allowed = False
                reason  = f"[SessionGuard] {session_risk.pattern}"
                guard_result.risk_level = _max_risk(guard_result.risk_level, RiskLevel.HIGH)
                log.warning(
                    json.dumps({
                        "event":      "session_escalation",
                        "request_id": rid,
                        "session_id": session_id,
                        "pattern":    session_risk.pattern,
                        "score":      session_risk.cumulative_score,
                    })
                )

    # ── Stage 3c: Honey-prompt deception ──────────────────────────────
    if not allowed and _runtime.honey_engine is not None:
        with suppress(Exception):
            honey_result = _runtime.honey_engine.maybe_honey(
                rid,
                [f.flag.value for f in guard_result.flags],
                tenant_id,
            )
            if honey_result.is_honey:
                FILTER_HONEYTRAP_TOTAL.labels(tenant_id=tenant_id).inc()
                if background_tasks is not None and auth.entity_key:
                    background_tasks.add_task(
                        _ers_record,
                        auth                = auth,
                        blocked             = False,
                        obfuscation_hit     = obfuscation_result.has_obfuscation,
                        honeytrap_hit       = True,
                        evolution_triggered = False,
                        rid                 = rid,
                    )
                timings["total"] = round((time.perf_counter() - start) * 1000, 2)
                _observe_stage_timings(timings, source)
                _log_verdict(
                    rid, tenant_id, guard_result.risk_level.value, payload, "honeytrap"
                )
                return FilterResponse(
                    allowed          = True,   # honey looks like "success" to attacker
                    risk_level       = guard_result.risk_level,
                    filtered_content = honey_result.response_text,
                    secrets_found    = [],
                    semantic_flags   = guard_result.flags,
                    reason           = "",
                    processing_ms    = timings,
                )

    # ── Stage 4: Evolution Loop ───────────────────────────────────────
    if (
        not allowed
        and _runtime.evolve is not None
        and background_tasks is not None
        and _RISK_ORDER.index(guard_result.risk_level) >= _RISK_ORDER.index(RiskLevel.HIGH)
    ):
        # ── spawn(), not add_task() ───────────────────────────────────────
        # This app has five BaseHTTPMiddleware instances in its stack, and
        # BaseHTTPMiddleware awaits the inner call — background tasks included —
        # before releasing the response. So add_task() here was not backgrounded:
        # every HIGH/BLOCK request waited for the Evolution Engine and the
        # outbound alerts. Traced on production, a blocked request finished the
        # filter at +77ms and sent its response at +1728ms. See warden/background.py.
        spawn(
            _runtime.evolve.process_blocked,
            content    = payload.content,
            flags      = guard_result.flags,
            risk_level = guard_result.risk_level,
            # Attribution for the per-tenant fairness share only — the engine
            # still charges its spend to the platform cost centre, because a
            # rule learned from one tenant's attack protects every tenant.
            tenant_id  = tenant_id,
        )
        log.info(json.dumps({"event": "evolution_queued", "request_id": rid}))

    # ── Stage 4c: Threat intelligence recording ───────────────────────
    if not allowed and client_ip and _runtime.threat_store is not None:
        with suppress(Exception):
            _runtime.threat_store.record_block_event(
                ip         = client_ip,
                tenant_id  = tenant_id,
                risk_level = guard_result.risk_level.value,
                flags      = [f.flag.value for f in guard_result.flags],
            )

    # ── Stage 4b: Real-time alerting (Slack / PagerDuty + Telegram) ───
    if not allowed and background_tasks is not None:
        top_flag = guard_result.top_flag
        try:
            from warden.alerting import alert_block_event
            spawn(
                alert_block_event,
                attack_type  = top_flag.flag.value if top_flag else "unknown",
                risk_level   = guard_result.risk_level.value,
                rule_summary = reason,
                request_id   = rid,
            )
        except ImportError:
            pass
        # Mobile SOC push notifications (MO-01)
        try:
            from warden.alerting import alert_push_verdict
            spawn(
                alert_push_verdict,
                tenant_id    = tenant_id,
                risk_level   = guard_result.risk_level.value,
                attack_type  = top_flag.flag.value if top_flag else "unknown",
                request_id   = rid,
                rule_summary = reason,
            )
        except ImportError:
            pass
        # Telegram channel (per-tenant chat_id from onboarding)
        tg_chat = _runtime.onboarding.get_telegram_chat_id(tenant_id) if _runtime.onboarding else None
        spawn(
            _tg_block_alert,
            tenant_id      = tenant_id,
            risk_level     = guard_result.risk_level.value,
            attack_type    = top_flag.flag.value if top_flag else "unknown",
            detail         = reason,
            request_id     = rid,
            tenant_chat_id = tg_chat,
        )

    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    timings["total"] = elapsed_ms
    _observe_stage_timings(timings, source)
    log.info(
        json.dumps({
            "event":      "filter_done",
            "request_id": rid,
            "allowed":    allowed,
            "risk":       guard_result.risk_level.value,
            "elapsed_ms": elapsed_ms,
        })
    )

    # ── Yellow zone entity detection (fast regex, always-on) ──────────────────
    # Runs MaskingEngine purely for detection — token replacement happens only
    # in the OpenAI proxy.  Fast (<1 ms for typical prompts), no ML required.
    _mask_detected: list[str] = []
    _mask_count:    int       = 0
    try:
        _mask_result = _get_masking_engine().mask(
            redact_result.text,              # post-redaction content (secrets already stripped)
            session_id = f"_detect_{rid}",   # ephemeral session, never unmasked
        )
        if _mask_result.has_entities:
            _mask_detected = list(_mask_result.summary().keys())
            _mask_count    = _mask_result.entity_count
            # Invalidate immediately — we only needed the detection summary
            _get_masking_engine().invalidate_session(f"_detect_{rid}")
    except Exception as _exc:  # noqa: BLE001
        log.debug("suppressed exception: %r", _exc)   # detection is best-effort; never block a request

    # ── Causal Arbiter online calibration (Phase 5) ───────────────────
    # Nudge the CPT toward the final verdict (the supervised label) via a
    # bounded Robbins–Monro step. Off the hot path; fail-open.
    if _causal_online is not None:
        try:
            from warden.causal_arbiter import (
                online_update as _causal_online_update,  # noqa: PLC0415
            )
            _label_high = (not allowed) or guard_result.risk_level in (RiskLevel.HIGH, RiskLevel.BLOCK)
            _cu_kwargs = {
                "obfuscation_detected": _causal_online["obfuscation_detected"],
                "predicted_p":          _causal_online["predicted_p"],
                "observed_high_risk":   _label_high,
            }
            if background_tasks is not None:
                background_tasks.add_task(_causal_online_update, **_cu_kwargs)
            else:
                _causal_online_update(**_cu_kwargs)
        except Exception as _exc:  # noqa: BLE001
            log.debug("causal online_update skipped: %r", _exc)

    # ── Analytics logging ─────────────────────────────────────────────
    # Stage scores for XAI. Every one is computed above in this same handler —
    # they were simply never written down, which is why /xai/dashboard reported
    # SKIP on four of nine stages for every record ever explained.
    #
    # Collected in their own guarded block, and by name: several of these
    # stages sit in try blocks or behind short-circuits, so on some paths the
    # local is never bound at all. A NameError raised while assembling the log
    # record would cost the record itself — the analytics write is best-effort,
    # but it must not become best-effort *because of the scores*.
    # `Any` rather than `object`: the values are floats, ints and a list of
    # strings, and mypy checks a `**` splat against each parameter's own type.
    _stage_scores: dict[str, Any] = {}
    for _name, _src, _attr in (
        ("semantic_score",     "brain_result",       "score"),
        ("causal_p_high_risk", "_causal_result",     "risk_probability"),
        ("phish_score",        "_phish_result",      "max_url_score"),
        ("se_score",           "_phish_result",      "se_risk"),
        ("ers_score",          "auth",               "ers_score"),
    ):
        with suppress(Exception):
            _obj = locals().get(_src)
            _val = getattr(_obj, _attr, None) if _obj is not None else None
            if _val is not None:
                _stage_scores[_name] = float(_val)
    with suppress(Exception):
        _layers = list(getattr(locals().get("obfuscation_result"), "layers_found", ()) or ())
        if _layers:
            _stage_scores["obfuscation_layers"] = len(_layers)
            _stage_scores["obfuscation_types"]  = _layers

    try:
        _tokens = event_logger.estimate_tokens(payload.content)
        entry = event_logger.build_entry(
            request_id        = rid,
            allowed           = allowed,
            risk_level        = guard_result.risk_level.value,
            flags             = [f.flag.value for f in guard_result.flags],
            secrets_found     = [f.kind for f in redact_result.findings],
            payload_len       = len(payload.content),
            payload_tokens    = _tokens,
            attack_cost_usd   = event_logger.token_cost_usd(_tokens),
            elapsed_ms        = elapsed_ms,
            strict            = strict,
            session_id        = session_id,
            entities_detected = _mask_detected,
            entity_count      = _mask_count,
            masked            = False,   # proxy sets True when tokens are actually replaced
            **_stage_scores,
        )
        entry["tenant_id"] = tenant_id   # needed for billing aggregation
        if background_tasks is not None:
            background_tasks.add_task(event_logger.append, entry)
        else:
            event_logger.append(entry)
        # Broadcast to all connected /ws/events dashboard clients.
        #
        # This used to feed a main.py-local _EventBus whose only consumer was
        # main.py's own @app.websocket("/ws/events") — shadowed by the OB-26
        # router mounted earlier, so the bus had no reachable subscribers while
        # the live endpoint had no producer. The stream was broken at BOTH ends.
        # Now feeds the router's fan-out, which also republishes to Redis for
        # multi-instance deployments.
        _runtime.spawn_task(_ws_broadcast_event({
            "type":        "event",
            "request_id":  rid,
            "ts":          entry.get("ts", ""),
            "risk":        guard_result.risk_level.value,
            "allowed":     allowed,
            "flags":       [f.flag.value for f in guard_result.flags],
            "secrets":     [f.kind for f in redact_result.findings],
            "payload_len": len(payload.content),
            "elapsed_ms":  round(elapsed_ms, 2),
            "tenant_id":   tenant_id,
            "session_id":  session_id,
        }))
    except Exception:
        log.exception(json.dumps({"event": "analytics_error", "request_id": rid}))

    # ── Audit Trail: tamper-evident chain entry ────────────────────────
    if _runtime.audit_trail is not None:
        with suppress(Exception):
            _runtime.audit_trail.record(
                request_id    = rid,
                tenant_id     = tenant_id,
                risk_level    = guard_result.risk_level.value,
                action        = "allowed" if allowed else "blocked",
                reason        = reason,
                flags         = [f.flag.value for f in guard_result.flags],
                processing_ms = timings.get("total", 0.0),
            )

    # ── SIEM integration ──────────────────────────────────────────────
    if background_tasks is not None:
        try:
            from warden.analytics.siem import ship_event
            background_tasks.add_task(ship_event, entry)
        except ImportError:
            pass

    # ── Agentic session monitoring ────────────────────────────────────
    if session_id and _runtime.agent_monitor is not None and background_tasks is not None:
        with suppress(Exception):
            session_threat = _runtime.agent_monitor.record_request(
                session_id,
                rid,
                allowed,
                guard_result.risk_level.value,
                [f.flag.value for f in guard_result.flags],
                tenant_id,
            )
            # Persist session anomalies to threat store for cross-session correlation
            if session_threat is not None and client_ip and _runtime.threat_store is not None:
                with suppress(Exception):
                    _runtime.threat_store.record_session_threat(
                        ip         = client_ip,
                        tenant_id  = tenant_id,
                        session_id = session_id,
                        pattern    = session_threat.pattern,
                        severity   = session_threat.severity,
                    )

    _masking_report = MaskingReport(
        masked       = False,
        session_id   = None,
        entities     = [
            MaskedEntityInfo(entity_type=k, token=f"[{k}_N]", count=0)
            for k in _mask_detected
        ],
        entity_count = _mask_count,
    )

    # ── XAI explanation ───────────────────────────────────────────────
    _xai_flags = [f.flag.value for f in guard_result.flags]
    _explanation = _xai_explain(
        risk_level       = guard_result.risk_level.value,
        flags            = _xai_flags,
        reason           = reason,
        owasp_categories = [],
    )

    # ── Webhook dispatch ──────────────────────────────────────────────
    if background_tasks is not None and _runtime.webhook_store is not None:
        background_tasks.add_task(
            _dispatch_webhook,
            tenant_id        = tenant_id,
            risk_level       = guard_result.risk_level.value,
            owasp_categories = [],
            reason           = reason,
            content          = payload.content,
            processing_ms    = timings.get("total", 0.0),
            store            = _runtime.webhook_store,
        )

    # ── Business Threat Neutralizer (optional — only when sector is set) ──
    _business_intel: dict | None = None
    if payload.sector:
        try:
            _neutralizer_report = _neutralizer_analyze(
                payload.sector,  # type: ignore[arg-type]
                obfuscation_detected = obfuscation_result.has_obfuscation,
                redacted_count       = len(redact_result.findings),
                has_pii              = redact_result.has_pii,
                risk_level           = guard_result.risk_level.value.upper(),
                ml_score             = brain_result.score,
                vault_matches        = vault_matches,
                semantic_flags       = [f.flag.value for f in guard_result.flags],
                poisoning_detected   = bool(poison_result_dict),
            )
            _business_intel = _neutralizer_report.as_dict()
        except Exception as _bte:
            log.debug("Business threat neutralizer error (non-fatal): %s", _bte)

    response = FilterResponse(
        allowed                  = allowed,
        risk_level               = guard_result.risk_level,
        filtered_content         = redact_result.text,
        secrets_found            = redact_result.findings,
        semantic_flags           = guard_result.flags,
        reason                   = reason,
        redaction_policy_applied = payload.redaction_policy,
        processing_ms            = timings,
        masking                  = _masking_report,
        explanation              = _explanation,
        poisoning                = poison_result_dict,
        threat_matches           = vault_matches,
        business_intel           = _business_intel,
    )

    # ── Correlation line (OB-F16) ─────────────────────────────────────
    # See `_log_verdict`. This is the normal path; the three early returns
    # above call the same helper so no terminal outcome is missing from Loki.
    _log_verdict(rid, tenant_id, guard_result.risk_level.value, payload, "filtered")

    # ── Cache write ───────────────────────────────────────────────────
    if allowed:
        set_cached(payload.content, response.model_dump_json())

    # ── ERS event recording (background — non-blocking) ───────────────
    if background_tasks is not None and auth.entity_key:
        _evolution_fired = (
            not allowed
            and _runtime.evolve is not None
            and _RISK_ORDER.index(guard_result.risk_level) >= _RISK_ORDER.index(RiskLevel.HIGH)
        )
        background_tasks.add_task(
            _ers_record,
            auth                = auth,
            blocked             = not allowed,
            obfuscation_hit     = obfuscation_result.has_obfuscation,
            honeytrap_hit       = False,   # honeytrap returns early — recorded below
            evolution_triggered = _evolution_fired,
            rid                 = rid,
        )

    return response
