"""shadow_warden/errors.py — Exception hierarchy."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shadow_warden.models import FilterResult


class WardenError(Exception):
    """Base class for all Shadow Warden AI client errors."""


class WardenBlockedError(WardenError):
    """
    Raised when content is blocked by the Shadow Warden AI gateway
    and ``raise_on_block=True`` is passed to :meth:`WardenClient.filter`.
    """

    def __init__(self, result: FilterResult) -> None:
        self.result = result
        super().__init__(
            f"Content blocked by Shadow Warden AI "
            f"(risk={result.risk_level}, flags={result.flag_names})"
        )


class WardenGatewayError(WardenError):
    """
    Raised when the Shadow Warden AI gateway returns an unexpected
    HTTP error (4xx / 5xx other than 200).
    """

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        super().__init__(f"Gateway error {status_code}: {message}")


class WardenTimeoutError(WardenError):
    """Raised when the gateway does not respond within the configured timeout."""
