"""
warden/security/loop_monitor.py  (DET-02)
──────────────────────────────────────────
Agentic Loop Monitor — detects anomalous multi-step agent chains using
session-level topology graphs and β₂ Betti number computation.

A Betti number β₂ > 0 indicates a "void" in the simplicial complex built
from the agent call graph — i.e., a cyclic pattern or excessive back-edge
density that suggests an indirect prompt injection chain or infinite loop.

Session graph is stored in Redis as an adjacency list; falls back to
in-process dict when Redis is unavailable.
"""
from __future__ import annotations

import json
import logging
import os
from collections import defaultdict
from typing import Any

log = logging.getLogger("warden.security.loop_monitor")

_REDIS_PREFIX  = "loop_monitor:session:"
_MAX_NODES     = 500
_B2_THRESHOLD  = int(os.getenv("LOOP_MONITOR_B2_THRESHOLD", "2"))

_in_proc: dict[str, dict] = {}


# ── Redis helpers ──────────────────────────────────────────────────────────────

def _redis():
    try:
        import redis as redis_lib
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if url.startswith("memory://"):
            return None
        r = redis_lib.Redis.from_url(url, decode_responses=True)
        r.ping()
        return r
    except Exception:
        return None


def _load_graph(session_id: str) -> dict:
    r = _redis()
    if r:
        raw = r.get(f"{_REDIS_PREFIX}{session_id}")
        return json.loads(raw) if raw else {"nodes": [], "edges": []}
    return _in_proc.get(session_id, {"nodes": [], "edges": []})


def _save_graph(session_id: str, graph: dict) -> None:
    r = _redis()
    if r:
        r.setex(f"{_REDIS_PREFIX}{session_id}", 3600, json.dumps(graph))
    else:
        _in_proc[session_id] = graph


# ── Betti number computation (pure Python) ────────────────────────────────────

def _betti_numbers(nodes: list[str], edges: list[tuple[str, str]]) -> tuple[int, int, int]:
    """Compute β₀, β₁, β₂ via Euler characteristic on the clique complex.

    β₀ = connected components
    β₁ = independent cycles (loops)
    β₂ = enclosed voids (anomalous topology)

    Uses simplified formula for graphs (1-skeleton only):
      χ = V - E + F  (F = triangular faces)
      β₀ - β₁ + β₂ = χ
    """
    if not nodes:
        return 0, 0, 0

    n     = len(nodes)
    idx   = {node: i for i, node in enumerate(nodes)}
    adj   = defaultdict(set)
    for u, v in edges:
        if u in idx and v in idx:
            adj[idx[u]].add(idx[v])
            adj[idx[v]].add(idx[u])

    # β₀ — connected components via BFS
    visited = [False] * n
    b0 = 0
    for start in range(n):
        if not visited[start]:
            b0 += 1
            queue = [start]
            while queue:
                cur = queue.pop()
                if visited[cur]:
                    continue
                visited[cur] = True
                queue.extend(adj[cur] - {cur})

    e_count = sum(len(v) for v in adj.values()) // 2

    # Count triangular faces
    f_count = 0
    node_list = list(range(n))
    for u in node_list:
        for v in adj[u]:
            if v > u:
                common = adj[u] & adj[v]
                f_count += sum(1 for w in common if w > v)

    # Euler characteristic: χ = V - E + F
    chi = n - e_count + f_count
    # β₂ = χ - β₀ + β₁  →  β₁ = E - V + β₀  (standard formula)
    b1 = e_count - n + b0
    b2 = max(0, chi - b0 + b1)
    return b0, b1, b2


# ── Public API ─────────────────────────────────────────────────────────────────

def record_agent_call(session_id: str, caller: str, callee: str) -> None:
    """Record an agent→tool or agent→agent call edge in the session graph."""
    graph = _load_graph(session_id)
    if len(graph["nodes"]) >= _MAX_NODES:
        return
    for node in (caller, callee):
        if node not in graph["nodes"]:
            graph["nodes"].append(node)
    edge = [caller, callee]
    if edge not in graph["edges"]:
        graph["edges"].append(edge)
    _save_graph(session_id, graph)


def analyse_session(session_id: str) -> dict[str, Any]:
    """Analyse a session graph and return topology metrics + anomaly verdict.

    Returns
    -------
    {
        "session_id": str,
        "nodes": int,
        "edges": int,
        "b0": int,           # connected components
        "b1": int,           # independent cycles
        "b2": int,           # voids (anomalous)
        "anomaly": bool,     # True when b2 >= B2_THRESHOLD
        "risk": "LOW"|"MEDIUM"|"HIGH",
        "graph": {...},      # raw graph data
    }
    """
    graph  = _load_graph(session_id)
    nodes  = graph.get("nodes", [])
    edges  = [(e[0], e[1]) for e in graph.get("edges", []) if len(e) == 2]
    b0, b1, b2 = _betti_numbers(nodes, edges)
    anomaly = b2 >= _B2_THRESHOLD

    risk = "LOW"
    if b2 >= _B2_THRESHOLD * 2:
        risk = "HIGH"
    elif anomaly:
        risk = "MEDIUM"

    if anomaly:
        log.warning(
            "loop_monitor: anomalous agent topology — session=%s b0=%d b1=%d b2=%d",
            session_id, b0, b1, b2,
        )

    return {
        "session_id": session_id,
        "nodes":      len(nodes),
        "edges":      len(edges),
        "b0": b0, "b1": b1, "b2": b2,
        "anomaly": anomaly,
        "risk":    risk,
        "graph":   graph,
    }


def clear_session(session_id: str) -> None:
    r = _redis()
    if r:
        r.delete(f"{_REDIS_PREFIX}{session_id}")
    _in_proc.pop(session_id, None)
