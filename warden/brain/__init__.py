"""
warden.brain — detection brain package.

`SemanticGuard` / `SemanticResult` are re-exported LAZILY (PEP 562).

Why this matters (P-3b): `warden.brain.semantic` imports torch and
sentence-transformers at module level. Re-exporting it eagerly here meant that
importing *any* module in this package — including torch-free ones like
`warden.brain.online_learner` — pulled the entire ML stack into the process.

The ARQ worker paid that cost for nothing. `warden/workers/settings.py` imports
`warden.brain.online_learner` to register the nightly job; that triggered this
`__init__`, which loaded torch + sentence-transformers + transformers + scipy +
scikit-learn into a container with a **1 GB memory limit**. Measured in
production 2026-07-27: ~500 MB resident, ~40% of the worker's budget, for models
it never runs — the worker delegates inference to `warden:8001` over HTTP.

Module-level `__getattr__` keeps `from warden.brain import SemanticGuard`
working for any caller that wants it, but defers the import until the attribute
is actually touched. `SecretRedactor` stays eager: `redactor.py` imports only
`re` + stdlib.
"""

from typing import TYPE_CHECKING, Any

from warden.brain.redactor import RedactionResult, SecretRedactor

if TYPE_CHECKING:  # type checkers resolve the real symbols; runtime does not
    from warden.brain.semantic import SemanticGuard, SemanticResult

__all__ = ["RedactionResult", "SecretRedactor", "SemanticGuard", "SemanticResult"]

_LAZY = {"SemanticGuard", "SemanticResult"}


def __getattr__(name: str) -> Any:
    if name in _LAZY:
        from warden.brain import semantic

        return getattr(semantic, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(__all__)
