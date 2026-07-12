"""
warden/marketplace/bayesian_stats.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Bayesian correlation test (Deep-Eng Phase 4).

Replaces a raw point-estimate Pearson-correlation threshold
(``abs(r) >= 0.80``) with the posterior probability that the *true*
correlation exceeds a reference value, ``P(rho > rho0 | data)``, using
Fisher's z-transformation with a (locally uniform / Jeffreys-equivalent)
prior. On thin data (n close to the minimum) the posterior is wide and the
probability stays low even when the sample r is high by chance — cutting
false collusion flags that a bare threshold would fire on 3-4 samples.

Pure math — no I/O, no external dependency (erf is in the stdlib ``math``
module), safe to unit test exhaustively.
"""
from __future__ import annotations

import math

# z-critical value for a two-sided 95% interval (Phi^-1(0.975)).
_Z_95 = 1.959963985

# Standard-normal CDF via the error function — no scipy dependency needed.


def _normal_cdf(x: float) -> float:
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def fisher_z(r: float) -> float:
    """Fisher z-transformation of a correlation coefficient, clamped to
    avoid the singularity at |r| = 1 (finite-sample r never truly reaches it)."""
    r = max(-0.999999, min(0.999999, r))
    return math.atanh(r)


def posterior_p_correlation_exceeds(r: float, n: int, rho0: float) -> float:
    """
    P(rho > rho0 | observed r, n) under the Fisher-z normal approximation.

    ``n`` is the number of paired observations (n >= 4 required — below that
    the approximation's standard error is undefined/degenerate, so this
    returns 0.0, matching "no basis to flag"). Monotonically increasing in
    ``r`` and in ``n`` for fixed ``r`` above ``rho0`` (more data → more
    confident the true correlation exceeds the reference).
    """
    if n < 4:
        return 0.0
    se = 1.0 / math.sqrt(n - 3)
    z_stat = (fisher_z(r) - fisher_z(rho0)) / se
    return _normal_cdf(z_stat)


def correlation_credible_interval_95(r: float, n: int) -> tuple[float, float]:
    """
    Two-sided 95% credible interval for the true correlation, via the
    Fisher-z normal approximation. Returns (-1.0, 1.0) — maximally
    uninformative — when n < 4 (approximation undefined).
    """
    if n < 4:
        return (-1.0, 1.0)
    se = 1.0 / math.sqrt(n - 3)
    z_r = fisher_z(r)
    lo, hi = math.tanh(z_r - _Z_95 * se), math.tanh(z_r + _Z_95 * se)
    return (max(-1.0, lo), min(1.0, hi))
