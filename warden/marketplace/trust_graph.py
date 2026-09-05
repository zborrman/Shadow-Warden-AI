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

import logging
import threading
from collections import defaultdict, deque
from typing import Any

from warden.config import data_path
from warden.db.connect import open_db_readonly
from warden.observability import Reason, record_failopen

log = logging.getLogger("warden.marketplace.trust_graph")

_DB_PATH          = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
_DB_PATH_AT_IMPORT = _DB_PATH   # pristine; never monkeypatched

def _db_path() -> str:
    """Resolve the DB path on every call.

    DE-6 P2: this used to be read once into a module-level ``_DB_PATH`` and then
    used as a *parameter default* (``db_path: str | None = None``). Defaults bind at
    def-time, so the first value seen by the process was frozen into ~79
    signatures — no later ``MARKETPLACE_DB_PATH`` change, and no monkeypatch,
    could move them. That is the repo's own documented trap (Track F: use
    ``= None`` and resolve dynamically), and it is why test files that set the
    env at import fought over one another's databases.

    ``_DB_PATH`` is kept for callers that still reference it directly.
    """
    # An explicit override wins. Tests across this repo use
    # `monkeypatch.setattr(module, "_DB_PATH", ...)`, and callers may assign
    # it directly; re-reading the env unconditionally would silently ignore
    # both. Only when _DB_PATH is still the pristine import-time value do we
    # resolve fresh -- which is what unfreezes the parameter defaults.
    if _DB_PATH != _DB_PATH_AT_IMPORT:
        return _DB_PATH
    return data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")

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

    def build_graph(self, db_path: str | None = None) -> None:
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

    def _load_trades(self, db_path: str | None = None) -> dict:
        """Aggregate buyer->seller trades.

        `db_path` was passed straight through to `open_db_readonly`, so the
        no-argument `build_graph()` — which is how every caller uses it —
        opened `file:None?mode=ro` and raised `unable to open database file`.
        `_load_trades` swallowed that, so TrustRank has been computed over an
        empty graph for the life of the feature: every score 0, every
        leaderboard empty, every Sybil check trivially clean.

        `_db_path()` was sitting right there, resolving on every call by
        design (DE-6 P2). It was simply never called from here.
        """
        agg: dict[tuple, list] = defaultdict(lambda: [0.0, 0])
        try:
            con = open_db_readonly(db_path or _db_path())
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
            # SR-6: an empty aggregate is indistinguishable from "no trades
            # yet", so the trust routes answer 200 with an empty graph and
            # nobody learns the database was unreachable. Debug-level logging
            # is not an observation.
            record_failopen("marketplace_trust_graph", Reason.BACKEND_ERROR, exc)
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

    def edges(self) -> list[dict]:
        """Weighted trade edges, independent of the networkx/dict backend.

        Added for the `/marketplace/trust/graph` route (SW-11), which first
        read `self._g` directly and had to re-implement the backend branch to
        do it. A caller reaching past the class for a structure whose shape is
        conditional is a bug waiting for the condition to change.
        """
        out: list[dict] = []
        if hasattr(self._g, "edges"):
            for src, dst, data in self._g.edges(data=True):
                out.append({"source": src, "target": dst,
                            "weight": round(float(data.get("weight", 0.0)), 4)})
        else:
            for src, targets in self._g.items():
                for dst, data in targets.items():
                    out.append({"source": src, "target": dst,
                                "weight": round(float(data.get("weight", 0.0)), 4)})
        return out

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
