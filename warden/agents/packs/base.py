"""
warden/agents/packs/base.py
─────────────────────────────
Base class for ARC-like edge agent packs.

Each pack:
  - Declares a name, description, and list of required sensor types.
  - Implements analyze(sensor_data) → analysis dict.
  - Implements recommend_action(analysis) → human-readable action string.

Packs are registered in a module-level registry and can be deployed as
marketplace agents with capability "edge_analytics".
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import ClassVar

log = logging.getLogger("warden.agents.packs")

# Global pack registry: {pack_name: EdgeAgentPack class}
_REGISTRY: dict[str, type["EdgeAgentPack"]] = {}


def register(cls: type["EdgeAgentPack"]) -> type["EdgeAgentPack"]:
    """Class decorator that registers a pack in the global registry."""
    _REGISTRY[cls.name] = cls
    log.debug("EdgeAgentPack registered: %s", cls.name)
    return cls


def list_packs() -> list[dict]:
    """Return metadata for all registered packs."""
    return [
        {
            "name":             cls.name,
            "description":      cls.description,
            "required_sensors": cls.required_sensors,
            "version":          getattr(cls, "version", "1.0.0"),
        }
        for cls in _REGISTRY.values()
    ]


def get_pack(name: str) -> type["EdgeAgentPack"] | None:
    return _REGISTRY.get(name)


class EdgeAgentPack(ABC):
    """Abstract base for all edge agent packs."""

    name:             ClassVar[str]
    description:      ClassVar[str]
    required_sensors: ClassVar[list[str]]
    version:          ClassVar[str] = "1.0.0"

    @abstractmethod
    async def analyze(self, sensor_data: dict) -> dict:
        """Process sensor readings and return structured analysis."""

    @abstractmethod
    async def recommend_action(self, analysis: dict) -> str:
        """Generate a human-readable recommended action from analysis."""

    def validate_sensors(self, sensor_data: dict) -> list[str]:
        """Return list of missing required sensor keys."""
        return [k for k in self.required_sensors if k not in sensor_data]
