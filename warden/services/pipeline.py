"""
warden/services/pipeline.py
────────────────────────────
FilterPipeline — the stable entry point for the 9-stage /filter flow
(architecture Phase 2).

Strangler-fig seam: this service is the public interface that HTTP routers call.
Today it delegates to the orchestrator that ``main`` publishes into
``warden.runtime`` at startup; the 900-line stage body will migrate here behind
this unchanged interface in a later step, with no caller changes.

Callers depend on ``warden.services.pipeline.FilterPipeline`` — never on
``warden.main`` internals — which is what lets Phase 3 dissolve ``main.py``.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from warden.runtime import runtime

if TYPE_CHECKING:  # avoid import cycles at module load
    from fastapi import BackgroundTasks

    from warden.auth_guard import AuthResult
    from warden.schemas import FilterRequest, FilterResponse

__all__ = ["FilterPipeline", "PipelineUnavailableError"]

# Runtime slot the orchestrator is published under (main.py lifespan).
_ORCHESTRATOR_SLOT = "filter_orchestrator"


class PipelineUnavailableError(RuntimeError):
    """Raised when the filter orchestrator has not been published to runtime."""


class FilterPipeline:
    """Facade over the 9-stage filter orchestration.

    Stateless — construct freely. Resolves the orchestrator from ``runtime`` on
    each call so it always uses the process-wide singleton published at startup.
    """

    async def run(
        self,
        payload: FilterRequest,
        request_id: str,
        auth: AuthResult,
        background_tasks: BackgroundTasks | None = None,
        client_ip: str = "",
    ) -> FilterResponse:
        """Run the full pipeline and return a FilterResponse.

        Fails closed: if no orchestrator is published (app not booted), raises
        PipelineUnavailableError rather than silently allowing the request.
        """
        orchestrator: Any = runtime.get(_ORCHESTRATOR_SLOT)
        if orchestrator is None:
            raise PipelineUnavailableError(
                "filter orchestrator not published to runtime — app not started"
            )
        return await orchestrator(payload, request_id, auth, background_tasks, client_ip)


def is_available() -> bool:
    """True if the orchestrator has been published (app is booted)."""
    return runtime.get(_ORCHESTRATOR_SLOT) is not None
