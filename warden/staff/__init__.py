"""Digital Staff — Authorization Boundary Registry + Velocity Guard (STAFF-01)."""
from warden.staff.boundaries import (
    DEFAULT_BOUNDARIES,
    AgentRole,
    AuthorizationBoundary,
    BoundaryRegistry,
    BoundaryViolationError,
    get_registry,
)
from warden.staff.velocity import VelocityAlert, VelocityGuard

__all__ = [
    "AgentRole",
    "AuthorizationBoundary",
    "BoundaryViolationError",
    "BoundaryRegistry",
    "get_registry",
    "DEFAULT_BOUNDARIES",
    "VelocityGuard",
    "VelocityAlert",
]
