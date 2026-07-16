"""
FinOps capacity + efficiency math (FM-4).

Two pure primitives for running a single small (4 GB) node economically:

1. **M/G/1 queueing** — the gateway is one server with Poisson-ish arrivals and a
   general (non-exponential) service-time distribution, so its latency-vs-load
   curve is the Pollaczek–Khinchine formula, not a hand-waved average. This lets
   us state a real capacity ceiling: the max requests/sec that still meets a P-mean
   response target, and the utilisation head-room at a given load. Above ρ=1 the
   queue is unstable — cost per request goes to infinity, which is the FinOps point.

2. **Memory-limit audit** — sum the per-service container memory limits and compare
   against the node's RAM. Over-commit means the kernel OOM-killer, not the
   scheduler, decides who dies under load; this flags it before it happens.

MILP bin-packing across nodes is deliberately NOT here: with a single node the
placement polytope is a point, so the optimiser is a no-op. It returns when there
are ≥2 nodes to pack (see docs/fintech-development-plan.md).

Pure math (no I/O). `parse_compose_mem_limits` is an optional resilient reader.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

log = logging.getLogger(__name__)


# ── M/G/1 queueing (Pollaczek–Khinchine) ──────────────────────────────────────

def utilization(arrival_rate: float, mean_service_s: float) -> float:
    """ρ = λ·E[S] — the fraction of time the server is busy."""
    return max(0.0, float(arrival_rate)) * max(0.0, float(mean_service_s))


def mg1_wait_seconds(arrival_rate: float, mean_service_s: float, service_cv2: float = 1.0) -> float:
    """
    Mean time a request spends waiting in queue (not counting its own service),
    from Pollaczek–Khinchine:  Wq = ρ·E[S]·(1 + Cv²) / (2·(1 − ρ)).

    `service_cv2` is the squared coefficient of variation of service time
    (Var/E[S]²): 0 = deterministic, 1 = exponential (M/M/1), >1 = bursty.
    Returns +inf at or beyond ρ=1 (unstable queue).
    """
    lam = max(0.0, float(arrival_rate))
    es = max(0.0, float(mean_service_s))
    cv2 = max(0.0, float(service_cv2))
    rho = lam * es
    if rho >= 1.0:
        return float("inf")
    if rho <= 0.0:
        return 0.0
    return rho * es * (1.0 + cv2) / (2.0 * (1.0 - rho))


def mg1_response_seconds(arrival_rate: float, mean_service_s: float, service_cv2: float = 1.0) -> float:
    """Mean end-to-end response = queue wait + service time. +inf when unstable."""
    wq = mg1_wait_seconds(arrival_rate, mean_service_s, service_cv2)
    if wq == float("inf"):
        return float("inf")
    return wq + max(0.0, float(mean_service_s))


def max_rps_for_utilization(mean_service_s: float, rho_cap: float = 0.80) -> float:
    """Max arrival rate keeping ρ ≤ rho_cap. λ = ρ_cap / E[S]."""
    es = max(0.0, float(mean_service_s))
    if es <= 0.0:
        return float("inf")
    return max(0.0, min(1.0, float(rho_cap))) / es


def max_rps_for_latency(
    mean_service_s: float, target_response_s: float, service_cv2: float = 1.0
) -> float:
    """
    Max arrival rate whose mean M/G/1 response stays ≤ target_response_s.

    Closed-form solve of W(λ)=T where W = E[S] + λ·E[S²]/(2(1−λE[S])):
        λ* = 2(T − E[S]) / (E[S²] + 2·E[S]·(T − E[S]))
    Returns 0 when the target is below one service time (unachievable at any load).
    """
    a = max(0.0, float(mean_service_s))           # E[S]
    t = float(target_response_s)
    if a <= 0.0:
        return float("inf")
    if t <= a:
        return 0.0  # can't beat a single service time
    b = a * a * (1.0 + max(0.0, float(service_cv2)))  # E[S²] = E[S]²(1+Cv²)
    lam = 2.0 * (t - a) / (b + 2.0 * a * (t - a))
    # never exceed the stability limit 1/E[S]
    return max(0.0, min(lam, (1.0 / a) - 1e-12))


@dataclass(frozen=True)
class CapacityCeiling:
    mean_service_s: float
    service_cv2: float
    rho_cap: float
    target_response_s: float
    max_rps_utilization: float   # ceiling from the ρ cap
    max_rps_latency: float       # ceiling from the response-time target
    max_rps: float               # the binding (smaller) of the two


def capacity_ceiling(
    mean_service_s: float,
    target_response_s: float,
    service_cv2: float = 1.0,
    rho_cap: float = 0.80,
) -> CapacityCeiling:
    """The node's sustainable RPS = min(utilisation ceiling, latency ceiling)."""
    ru = max_rps_for_utilization(mean_service_s, rho_cap)
    rl = max_rps_for_latency(mean_service_s, target_response_s, service_cv2)
    return CapacityCeiling(
        mean_service_s=mean_service_s,
        service_cv2=service_cv2,
        rho_cap=rho_cap,
        target_response_s=target_response_s,
        max_rps_utilization=ru,
        max_rps_latency=rl,
        max_rps=min(ru, rl),
    )


# ── Memory-limit audit ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class MemAudit:
    node_ram_mb: float
    committed_mb: float          # sum of per-service limits
    reserve_mb: float            # RAM held back for the OS/kernel
    available_mb: float          # node_ram − reserve
    headroom_mb: float           # available − committed (negative = over-commit)
    over_committed: bool
    services: dict[str, float]


def audit_mem_limits(
    service_limits_mb: dict[str, float],
    node_ram_mb: float = 4096.0,
    os_reserve_mb: float = 512.0,
) -> MemAudit:
    """
    Compare summed container memory limits against schedulable RAM
    (node_ram − os_reserve). Over-commit means the OOM-killer, not the
    scheduler, arbitrates under pressure. Pure — feed it parsed limits.
    """
    services = {k: max(0.0, float(v)) for k, v in service_limits_mb.items()}
    committed = sum(services.values())
    reserve = max(0.0, float(os_reserve_mb))
    available = max(0.0, float(node_ram_mb) - reserve)
    headroom = available - committed
    return MemAudit(
        node_ram_mb=float(node_ram_mb),
        committed_mb=committed,
        reserve_mb=reserve,
        available_mb=available,
        headroom_mb=headroom,
        over_committed=headroom < 0.0,
        services=services,
    )


def parse_compose_mem_limits(path: str) -> dict[str, float]:
    """
    Best-effort read of per-service memory limits (MB) from a docker-compose
    file, honouring both `mem_limit:` and `deploy.resources.limits.memory:`.
    Returns {} on any parse error — the audit degrades to "nothing known"
    rather than raising.
    """
    try:
        import importlib

        yaml = importlib.import_module("yaml")  # avoids the untyped-stub import error

        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
        out: dict[str, float] = {}
        for name, svc in (doc.get("services") or {}).items():
            if not isinstance(svc, dict):
                continue
            raw = svc.get("mem_limit")
            if raw is None:
                raw = (
                    ((svc.get("deploy") or {}).get("resources") or {})
                    .get("limits", {})
                    .get("memory")
                )
            mb = _to_mb(raw)
            if mb is not None:
                out[name] = mb
        return out
    except Exception as exc:  # resilient: unreadable compose → empty audit
        log.debug("compose mem-limit parse resolved to empty: %s", exc)
        return {}


def _to_mb(raw: object) -> float | None:
    """Convert a docker byte string ('512m', '2g', '1073741824') to MB."""
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        return float(raw) / (1024 * 1024)
    s = str(raw).strip().lower()
    if not s:
        return None
    try:
        if s.endswith("g") or s.endswith("gb"):
            return float(s.rstrip("gb")) * 1024.0
        if s.endswith("m") or s.endswith("mb"):
            return float(s.rstrip("mb"))
        if s.endswith("k") or s.endswith("kb"):
            return float(s.rstrip("kb")) / 1024.0
        return float(s) / (1024 * 1024)  # raw bytes
    except ValueError:
        return None
