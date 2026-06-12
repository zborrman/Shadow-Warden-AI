"""Shadow Warden SDK exceptions."""
from __future__ import annotations


class WardenError(Exception):
    """Base exception for all Shadow Warden SDK errors."""

    def __init__(self, message: str, *, status_code: int = 0, response_body: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class AuthError(WardenError):
    """Raised on HTTP 401/403 — invalid or missing API key."""


class RateLimitError(WardenError):
    """Raised on HTTP 429 — request rate limit exceeded."""


class FilterBlockedError(WardenError):
    """Raised when raise_on_blocked=True and the filter verdict is BLOCK."""

    def __init__(self, response: object) -> None:  # response: FilterResponse, avoids circular import
        r = response  # type: ignore[assignment]
        super().__init__(
            f"Content blocked: risk_level={r.risk_level}, flags={r.flags}",  # type: ignore[attr-defined]
        )
        self.response = response
