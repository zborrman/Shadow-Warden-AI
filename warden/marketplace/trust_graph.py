"""
warden/marketplace/trust_graph.py
──────────────────────────────────
TrustGraph — directed trust graph built from marketplace trade history.
Uses weighted PageRank (TrustRank) to score agents.

Graph structure:
  Nodes  = agent_id strings
  Edges  = buyer → seller (buyer trusts seller after a trade)
  Weight = trade quality: completed=1.0 · disputed=0.3 · other=0.5

Falls back to pure-Python PageRank when networkx is unavailable.
"""
from __future__ import annotations

from typing import Any

import logging
import os
import sqlite3
import threading
from collections import defaultdict, deque

log = logging.getLogger("warden.marketplace.trust_graph")

_DB_PATH          = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
_DAMPING          = 0.85
_MAX_ITER         = 100
_RECALC_EVERY     = 10   # full PageRank recompute after N incremental updates

try:
    import networkx as nx
    _NX = True
except ImportError:
    _NX = False
    log.debug("networkx not installed — TrustGraph uses pure-Python fallback")


def _trade_weight(status: str) -> float:
    return 1.0 if status == "completed" else (0.3 if status == "disputed" else 0.5)


class TrustGraph:
    """Directed agent trust graph + TrustRank scorer."""

    def __init__(self) -> None:
        self._rank: dict[str, float] = {}
        self._updates = 0
        self._updates_lock = threading.Lock()
        self._g: Any  # nx.DiGraph when networkx available, else plain dict
        if _NX:
            self._g = nx.DiGraph()
        else:
            self._g = {}   # {src: {dst: {"weight": float, "trades": int}}}

    # ── Build ─────────────────────────────────────────────────────────────────

    def build_graph(self, db_path: str = _DB_PATH) -> None:
        """(Re)build from full marketplace_purchases history."""
        agg = self._load_trades(db_path)
        if _NX:
            self._g = nx.DiGraph()
            for (buyer, seller), (w_sum, n) in agg.items():
                self._g.add_edge(buyer, seller, weight=w_sum / n, trades=n)
        else:
            self._g = {}
            for (buyer, seller), (w_sum, n) in agg.items():
                self._g.setdefault(buyer, {})[seller] = {"weight": w_sum / n, "trades": n}
        self._recompute()

    def _load_trades(self, db_path: str) -> dict:
        agg: dict[tuple, list] = defaultdict(lambda: [0.0, 0])
        try:
            con = sqlite3.connect(db_path)
            rows = con.execute(
                "SELECT buyer_agent, seller_agent, status FROM marketplace_purchases"
            ).fetchall()
            con.close()
            for buyer, seller, status in rows:
                if buyer and seller and buyer != seller:
                    key = (buyer, seller)
                    agg[key][0] += _trade_weight(status)
                    agg[key][1] += 1
        except Exception as exc:
            log.debug("TrustGraph load error: %s", exc)
        return agg

    # ── PageRank ──────────────────────────────────────────────────────────────

    def _recompute(self) -> None:
        if _NX:
            if len(self._g.nodes) == 0:
                self._rank = {}
                return
            try:
                self._rank = nx.pagerank(self._g, alpha=_DAMPING, weight="weight", max_iter=_MAX_ITER)
            except Exception:
                n = len(self._g.nodes)
                self._rank = {v: 1.0 / max(n, 1) for v in self._g.nodes}
        else:
            self._rank = self._pure_pagerank()

    def _pure_pagerank(self) -> dict[str, float]:
        nodes: set[str] = set(self._g)
        for src in self._g:
            nodes.update(self._g[src])
        n = len(nodes)
        if n == 0:
            return {}
        rank = dict.fromkeys(nodes, 1.0 / n)
        for _ in range(_MAX_ITER):
            new: dict[str, float] = {}
            for v in nodes:
                s = 0.0
                for src, dsts in self._g.items():
                    if v in dsts:
                        total_w = sum(d["weight"] for d in dsts.values())
                        if total_w > 0:
                            s += rank.get(src, 0.0) * dsts[v]["weight"] / total_w
                new[v] = (1.0 - _DAMPING) / n + _DAMPING * s
            rank = new
        return rank

    def compute_pagerank(self) -> dict[str, float]:
        """Recompute and return a fresh TrustRank map."""
        self._recompute()
        return dict(self._rank)

    # ── Queries ───────────────────────────────────────────────────────────────

    def get_trust_score(self, agent_id: str) -> float:
        """Normalised TrustRank [0.0–1.0]; 0.5 for unknown agents."""
        if not self._rank:
            return 0.5
        raw = self._rank.get(agent_id, 0.0)
        max_r = max(self._rank.values()) or 1.0
        return min(1.0, raw / max_r)

    def get_transitive_trust(self, agent_a: str, agent_b: str) -> float:
        """Min TrustRank on shortest path A→B; falls back to blended average."""
        if agent_a == agent_b:
            return self.get_trust_score(agent_a)
        try:
            path = (
                nx.shortest_path(self._g, agent_a, agent_b)
                if _NX
                else self._bfs(agent_a, agent_b)
            )
            if not path:
                raise ValueError
            return min(self.get_trust_score(n) for n in path)
        except Exception:
            return (self.get_trust_score(agent_a) + self.get_trust_score(agent_b)) / 2.0

    def _bfs(self, start: str, end: str) -> list[str]:
        visited = {start}
        q: deque = deque([[start]])
        while q:
            path = q.popleft()
            if path[-1] == end:
                return path
            for nb in self._g.get(path[-1], {}):
                if nb not in visited:
                    visited.add(nb)
                    q.append(path + [nb])
        return []

    # ── Incremental updates ───────────────────────────────────────────────────

    def update_graph(self, purchase: dict) -> None:
        """Merge a single trade; recomputes PageRank every _RECALC_EVERY updates."""
        buyer  = purchase.get("buyer_agent", "")
        seller = purchase.get("seller_agent", "")
        status = purchase.get("status", "pending")
        if not buyer or not seller or buyer == seller:
            return
        w = _trade_weight(status)
        if _NX:
            if self._g.has_edge(buyer, seller):
                ed = self._g[buyer][seller]
                ed["weight"] = (ed.get("weight", 1.0) + w) / 2.0
                ed["trades"] = ed.get("trades", 0) + 1
            else:
                self._g.add_edge(buyer, seller, weight=w, trades=1)
        else:
            self._g.setdefault(buyer, {})
            if seller in self._g[buyer]:
                old = self._g[buyer][seller]
                old["weight"] = (old["weight"] + w) / 2.0
                old["trades"] += 1
            else:
                self._g[buyer][seller] = {"weight": w, "trades": 1}
        with self._updates_lock:
            self._updates += 1
            do_recompute = self._updates % _RECALC_EVERY == 0
        if do_recompute:
            self._recompute()

    # ── Leaderboard ───────────────────────────────────────────────────────────

    def top_agents(self, n: int = 5) -> list[dict]:
        """Top N agents sorted descending by normalised TrustRank."""
        if not self._rank:
            return []
        max_r = max(self._rank.values()) or 1.0
        ranked = sorted(
            [{"agent_id": aid, "trust_rank": min(1.0, r / max_r)} for aid, r in self._rank.items()],
            key=lambda x: float(x["trust_rank"]),  # type: ignore[arg-type]
            reverse=True,
        )
        return ranked[:n]
