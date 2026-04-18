"""
warden/xai/chain.py
─────────────────────
CausalChain — structured pipeline graph for XAI 2.0.

A CausalChain represents one filter decision as a directed acyclic graph:
  nodes  — one per pipeline stage, each with verdict + numeric score
  edges  — ordered flow between stages
  primary_cause — the first stage that produced a blocking signal

The graph is designed for:
  • Frontend visualization (D3 / React Flow — serializes to JSON)
  • HTML/PDF report generation (renderer.py)
  • SOVA's explain_decision tool (#30)

Pipeline stages in execution order:
  topology       TopologicalGatekeeper  (Betti numbers)
  obfuscation    ObfuscationDecoder     (encoded layers count)
  secrets        SecretRedactor         (matched PII/secret patterns)
  semantic_rules SemanticGuard          (rule engine, compound risk)
  brain          HyperbolicBrain        (MiniLM cosine + hyperbolic)
  causal         CausalArbiter          (Bayesian DAG, do-calculus)
  phish          PhishGuard             (URL phishing + SE-Arbiter)
  ers            ERS + Shadow Ban       (sliding window score)
  decision       Final Decision         (aggregated verdict)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# ── Stage metadata ────────────────────────────────────────────────────────────

STAGE_META: dict[str, dict[str, str]] = {
    "topology":       {"name": "Topological Gatekeeper", "icon": "🔷", "color": "#6366f1"},
    "obfuscation":    {"name": "Obfuscation Decoder",    "icon": "🔓", "color": "#8b5cf6"},
    "secrets":        {"name": "Secret Redactor",        "icon": "🔑", "color": "#ec4899"},
    "semantic_rules": {"name": "Semantic Rule Engine",   "icon": "📋", "color": "#f59e0b"},
    "brain":          {"name": "HyperbolicBrain (ML)",   "icon": "🧠", "color": "#ef4444"},
    "causal":         {"name": "Causal Arbiter",         "icon": "🎯", "color": "#f97316"},
    "phish":          {"name": "PhishGuard + SE-Arbiter","icon": "🎣", "color": "#14b8a6"},
    "ers":            {"name": "ERS + Shadow Ban",       "icon": "🛡",  "color": "#06b6d4"},
    "decision":       {"name": "Final Decision",         "icon": "⚖",  "color": "#64748b"},
}

STAGE_ORDER: list[str] = [
    "topology", "obfuscation", "secrets", "semantic_rules",
    "brain", "causal", "phish", "ers", "decision",
]

_VERDICT_WEIGHT: dict[str, int] = {"BLOCK": 3, "FLAG": 2, "PASS": 1, "SKIP": 0}


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class ChainNode:
    stage_id:   str
    stage_name: str
    icon:       str
    color:      str
    verdict:    str              # PASS | FLAG | BLOCK | SKIP
    score:      float | None     # stage primary numeric score (0–1 or raw)
    score_label: str             # human label for the score
    detail:     dict[str, Any]   # all stage-specific data
    latency_ms: float | None     # stage processing time if available
    weight:     float            # 0.0–1.0 causal contribution to final decision


@dataclass
class Counterfactual:
    stage_id:    str
    explanation: str             # "Remove base64 encoding from the payload"
    severity:    str             # HIGH | MEDIUM | LOW


@dataclass
class CausalChain:
    request_id:    str
    tenant_id:     str
    final_verdict: str           # ALLOWED | BLOCKED
    risk_level:    str           # LOW | MEDIUM | HIGH | CRITICAL
    nodes:         list[ChainNode]
    edges:         list[tuple[str, str]]   # (from_stage_id, to_stage_id)
    primary_cause: str           # stage_id of the main blocking signal
    primary_cause_name: str
    rationale:     str           # plain-English explanation
    counterfactuals: list[Counterfactual]
    flags:         list[str]
    processing_ms: float | None
    timestamp:     str


# ── Builder ───────────────────────────────────────────────────────────────────

def build_chain(record: dict, tenant_id: str = "default") -> CausalChain:
    """
    Construct a CausalChain from a raw analytics log record.

    The record is the dict returned by `read_by_request_id()`.
    Fields that are absent are treated as SKIP (stage not reached or not logged).
    """
    nodes: list[ChainNode] = []

    # ── Topology ──────────────────────────────────────────────────────────────
    beta0 = record.get("beta0")
    beta1 = record.get("beta1")
    topo_noise = record.get("topology_noise")
    topo_score = _norm(beta1, 0, 5) if beta1 is not None else None
    topo_verdict = _verdict_from_score(topo_score, 0.4, 0.7) if topo_score is not None else "SKIP"
    nodes.append(ChainNode(
        stage_id   = "topology",
        stage_name = STAGE_META["topology"]["name"],
        icon       = STAGE_META["topology"]["icon"],
        color      = STAGE_META["topology"]["color"],
        verdict    = topo_verdict,
        score      = topo_score,
        score_label= f"β₁={beta1}" if beta1 is not None else "—",
        detail     = {"beta0": beta0, "beta1": beta1, "noise_score": topo_noise},
        latency_ms = None,
        weight     = _weight(topo_verdict),
    ))

    # ── Obfuscation ───────────────────────────────────────────────────────────
    obf_layers = record.get("obfuscation_layers", 0)
    obf_verdict = "BLOCK" if obf_layers >= 3 else ("FLAG" if obf_layers >= 1 else "PASS")
    nodes.append(ChainNode(
        stage_id   = "obfuscation",
        stage_name = STAGE_META["obfuscation"]["name"],
        icon       = STAGE_META["obfuscation"]["icon"],
        color      = STAGE_META["obfuscation"]["color"],
        verdict    = "SKIP" if obf_layers is None else obf_verdict,
        score      = float(obf_layers) if obf_layers else None,
        score_label= f"{obf_layers} layer(s)" if obf_layers else "—",
        detail     = {"layers": obf_layers, "types": record.get("obfuscation_types", [])},
        latency_ms = None,
        weight     = _weight(obf_verdict),
    ))

    # ── Secret Redactor ───────────────────────────────────────────────────────
    secrets = record.get("secrets_found", [])
    sec_verdict = "FLAG" if secrets else "PASS"
    nodes.append(ChainNode(
        stage_id   = "secrets",
        stage_name = STAGE_META["secrets"]["name"],
        icon       = STAGE_META["secrets"]["icon"],
        color      = STAGE_META["secrets"]["color"],
        verdict    = sec_verdict,
        score      = float(len(secrets)) if secrets else 0.0,
        score_label= f"{len(secrets)} pattern(s)" if secrets else "clean",
        detail     = {"patterns": secrets, "entity_types": record.get("entities_detected", [])},
        latency_ms = None,
        weight     = _weight(sec_verdict),
    ))

    # ── Semantic Rule Engine ──────────────────────────────────────────────────
    flags     = record.get("flags", [])
    sem_score = record.get("semantic_score")
    sem_verdict = _verdict_from_score(sem_score, 0.5, 0.72) if sem_score is not None else (
        "FLAG" if flags else "PASS"
    )
    nodes.append(ChainNode(
        stage_id   = "semantic_rules",
        stage_name = STAGE_META["semantic_rules"]["name"],
        icon       = STAGE_META["semantic_rules"]["icon"],
        color      = STAGE_META["semantic_rules"]["color"],
        verdict    = sem_verdict,
        score      = sem_score,
        score_label= f"{sem_score:.3f}" if sem_score is not None else "rule-match",
        detail     = {"flags": flags, "rule_score": sem_score},
        latency_ms = None,
        weight     = _weight(sem_verdict),
    ))

    # ── HyperbolicBrain ───────────────────────────────────────────────────────
    hyp_dist  = record.get("hyperbolic_distance")
    brain_score = record.get("brain_score") or sem_score   # brain_score may alias semantic_score
    brain_verdict = _verdict_from_score(brain_score, 0.5, 0.72) if brain_score is not None else "SKIP"
    nodes.append(ChainNode(
        stage_id   = "brain",
        stage_name = STAGE_META["brain"]["name"],
        icon       = STAGE_META["brain"]["icon"],
        color      = STAGE_META["brain"]["color"],
        verdict    = brain_verdict,
        score      = brain_score,
        score_label= f"{brain_score:.3f}" if brain_score is not None else "—",
        detail     = {
            "cosine_score":      brain_score,
            "hyperbolic_dist":   hyp_dist,
            "closest_example":   record.get("closest_example"),
        },
        latency_ms = None,
        weight     = _weight(brain_verdict),
    ))

    # ── Causal Arbiter ────────────────────────────────────────────────────────
    p_high = record.get("causal_p_high_risk")
    causal_verdict = _verdict_from_score(p_high, 0.3, 0.7) if p_high is not None else "SKIP"
    nodes.append(ChainNode(
        stage_id   = "causal",
        stage_name = STAGE_META["causal"]["name"],
        icon       = STAGE_META["causal"]["icon"],
        color      = STAGE_META["causal"]["color"],
        verdict    = causal_verdict,
        score      = p_high,
        score_label= f"P={p_high:.3f}" if p_high is not None else "—",
        detail     = {
            "p_high_risk":    p_high,
            "do_operator":    record.get("causal_do_operator"),
            "backdoor_nodes": record.get("causal_backdoor_nodes", []),
        },
        latency_ms = None,
        weight     = _weight(causal_verdict),
    ))

    # ── PhishGuard ────────────────────────────────────────────────────────────
    phish_score = record.get("phish_score")
    se_score    = record.get("se_score")
    phish_max   = max(
        (phish_score or 0.0),
        (se_score or 0.0),
    )
    phish_verdict = _verdict_from_score(phish_max, 0.4, 0.7) if phish_max > 0 else "PASS"
    nodes.append(ChainNode(
        stage_id   = "phish",
        stage_name = STAGE_META["phish"]["name"],
        icon       = STAGE_META["phish"]["icon"],
        color      = STAGE_META["phish"]["color"],
        verdict    = phish_verdict,
        score      = phish_max if phish_max > 0 else None,
        score_label= f"{phish_max:.3f}" if phish_max > 0 else "clean",
        detail     = {"phish_score": phish_score, "se_score": se_score},
        latency_ms = None,
        weight     = _weight(phish_verdict),
    ))

    # ── ERS + Shadow Ban ──────────────────────────────────────────────────────
    ers_score   = record.get("ers_score")
    ban_strat   = record.get("shadow_ban_strategy")
    ers_verdict = _verdict_from_score(ers_score, 0.5, 0.75) if ers_score is not None else "SKIP"
    nodes.append(ChainNode(
        stage_id   = "ers",
        stage_name = STAGE_META["ers"]["name"],
        icon       = STAGE_META["ers"]["icon"],
        color      = STAGE_META["ers"]["color"],
        verdict    = ers_verdict,
        score      = ers_score,
        score_label= f"{ers_score:.3f}" if ers_score is not None else "—",
        detail     = {"ers_score": ers_score, "ban_strategy": ban_strat},
        latency_ms = None,
        weight     = _weight(ers_verdict),
    ))

    # ── Final Decision ────────────────────────────────────────────────────────
    action        = record.get("action", "blocked" if not record.get("allowed") else "allowed")
    final_verdict = "BLOCKED" if action in ("blocked", "block") else "ALLOWED"
    risk_level    = record.get("risk_level", "UNKNOWN").upper()
    dec_verdict   = "BLOCK" if final_verdict == "BLOCKED" else "PASS"
    nodes.append(ChainNode(
        stage_id   = "decision",
        stage_name = STAGE_META["decision"]["name"],
        icon       = STAGE_META["decision"]["icon"],
        color      = STAGE_META["decision"]["color"],
        verdict    = dec_verdict,
        score      = None,
        score_label= final_verdict,
        detail     = {
            "final_verdict": final_verdict,
            "risk_level":    risk_level,
            "processing_ms": record.get("processing_ms") or record.get("elapsed_ms"),
        },
        latency_ms = record.get("processing_ms") or record.get("elapsed_ms"),
        weight     = 1.0,
    ))

    # ── Edges ─────────────────────────────────────────────────────────────────
    edges = [(STAGE_ORDER[i], STAGE_ORDER[i + 1]) for i in range(len(STAGE_ORDER) - 1)]

    # ── Primary cause ─────────────────────────────────────────────────────────
    primary = _find_primary_cause(nodes, record)

    # ── Counterfactuals ───────────────────────────────────────────────────────
    counterfactuals = _build_counterfactuals(nodes, record)

    # ── Rationale ─────────────────────────────────────────────────────────────
    rationale = record.get("xai_rationale") or _generate_rationale(
        nodes, primary, flags, final_verdict, risk_level,
        record.get("processing_ms") or record.get("elapsed_ms"),
    )

    return CausalChain(
        request_id       = record.get("request_id", "unknown"),
        tenant_id        = tenant_id,
        final_verdict    = final_verdict,
        risk_level       = risk_level,
        nodes            = nodes,
        edges            = edges,
        primary_cause    = primary,
        primary_cause_name = STAGE_META.get(primary, {}).get("name", primary),
        rationale        = rationale,
        counterfactuals  = counterfactuals,
        flags            = flags,
        processing_ms    = record.get("processing_ms") or record.get("elapsed_ms"),
        timestamp        = record.get("ts", ""),
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _norm(val: float | None, lo: float, hi: float) -> float | None:
    """Normalize *val* to [0, 1] within [lo, hi] range."""
    if val is None:
        return None
    return min(1.0, max(0.0, (val - lo) / (hi - lo + 1e-9)))


def _verdict_from_score(score: float | None, flag_thresh: float, block_thresh: float) -> str:
    if score is None:
        return "SKIP"
    if score >= block_thresh:
        return "BLOCK"
    if score >= flag_thresh:
        return "FLAG"
    return "PASS"


def _weight(verdict: str) -> float:
    weights = {"BLOCK": 1.0, "FLAG": 0.6, "PASS": 0.1, "SKIP": 0.0}
    return weights.get(verdict, 0.0)


def _find_primary_cause(nodes: list[ChainNode], record: dict) -> str:
    """Return the stage_id most responsible for the final decision."""
    # Prefer the first BLOCK node in pipeline order
    for node in nodes[:-1]:   # exclude "decision" node itself
        if node.verdict == "BLOCK":
            return node.stage_id
    # Fallback: highest-weight FLAG
    flagged = [n for n in nodes[:-1] if n.verdict == "FLAG"]
    if flagged:
        return max(flagged, key=lambda n: n.weight).stage_id
    # Fallback: first non-SKIP
    for node in nodes[:-1]:
        if node.verdict != "SKIP":
            return node.stage_id
    return "decision"


def _build_counterfactuals(nodes: list[ChainNode], record: dict) -> list[Counterfactual]:
    """Generate actionable counterfactuals for each non-PASS, non-SKIP stage."""
    _explanations: dict[str, str] = {
        "topology":       "Reduce payload structural complexity — shorter, simpler content has lower Betti numbers.",
        "obfuscation":    "Remove encoding layers (base64, hex, ROT13) from the payload before submission.",
        "secrets":        "Strip API keys, passwords, and PII from the content — use placeholder tokens instead.",
        "semantic_rules": "Avoid prompt injection patterns and system-override language.",
        "brain":          "Rephrase the request — the content is semantically similar to known attack examples.",
        "causal":         "The causal model assigns high P(HARM|evidence) — multiple risk signals reinforce each other.",
        "phish":          "Remove phishing URLs or social-engineering manipulation language.",
        "ers":            "Rate limit exceeded or shadow-ban threshold reached — reduce request frequency.",
    }
    result: list[Counterfactual] = []
    for node in nodes[:-1]:   # skip "decision"
        if node.verdict in ("BLOCK", "FLAG"):
            severity = "HIGH" if node.verdict == "BLOCK" else "MEDIUM"
            result.append(Counterfactual(
                stage_id    = node.stage_id,
                explanation = _explanations.get(node.stage_id, f"Address signal in stage: {node.stage_name}."),
                severity    = severity,
            ))
    return result


def _generate_rationale(
    nodes:         list[ChainNode],
    primary_cause: str,
    flags:         list[str],
    final_verdict: str,
    risk_level:    str,
    processing_ms: Any,
) -> str:
    cause_name = STAGE_META.get(primary_cause, {}).get("name", primary_cause)
    blocked_stages = [n.stage_name for n in nodes if n.verdict == "BLOCK"]
    flagged_stages = [n.stage_name for n in nodes if n.verdict == "FLAG"]

    parts = [f"Request {final_verdict.lower()} — risk level: {risk_level}."]
    if blocked_stages:
        parts.append(f"Blocking signal from: {', '.join(blocked_stages)}.")
    elif flagged_stages:
        parts.append(f"Flagged by: {', '.join(flagged_stages)}.")
    if flags:
        parts.append(f"Trigger flags: {', '.join(flags[:5])}{'…' if len(flags) > 5 else ''}.")
    parts.append(f"Primary cause: {cause_name}.")
    if processing_ms is not None:
        parts.append(f"Pipeline completed in {processing_ms:.1f}ms.")
    return " ".join(parts)


# ── Serialization ─────────────────────────────────────────────────────────────

def chain_to_dict(chain: CausalChain) -> dict:
    """Serialize a CausalChain to a JSON-compatible dict."""
    return {
        "request_id":         chain.request_id,
        "tenant_id":          chain.tenant_id,
        "final_verdict":      chain.final_verdict,
        "risk_level":         chain.risk_level,
        "primary_cause":      chain.primary_cause,
        "primary_cause_name": chain.primary_cause_name,
        "rationale":          chain.rationale,
        "flags":              chain.flags,
        "processing_ms":      chain.processing_ms,
        "timestamp":          chain.timestamp,
        "nodes": [
            {
                "stage_id":    n.stage_id,
                "stage_name":  n.stage_name,
                "icon":        n.icon,
                "color":       n.color,
                "verdict":     n.verdict,
                "score":       n.score,
                "score_label": n.score_label,
                "detail":      n.detail,
                "latency_ms":  n.latency_ms,
                "weight":      n.weight,
            }
            for n in chain.nodes
        ],
        "edges": [{"from": e[0], "to": e[1]} for e in chain.edges],
        "counterfactuals": [
            {
                "stage_id":    c.stage_id,
                "explanation": c.explanation,
                "severity":    c.severity,
            }
            for c in chain.counterfactuals
        ],
    }
