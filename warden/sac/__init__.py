"""
SAC — Shadow Agentic Container (runtime security core).

The "Inner Warden": an in-process execution guard that screens every agent tool
call before it runs and becomes the first producer for the GSAM observation
stream. It is the Python-native translation of the SAC spec's eBPF sensor —
kernel syscall interception is replaced by application-level policy checks that
run on the actual stack (Python/FastAPI, no bare-metal / Kata / eBPF required).

Two enforcement postures, deliberately different:
  • security decisions (SSRF / exfil URL block) fail-CLOSED;
  • telemetry emission (GSAM observation) fails-OPEN and never breaks dispatch.

Import rule: zero import-time side effects. Every heavy dependency
(``net_guard``, ``gsam_emit``) is imported lazily inside the functions.
"""
from __future__ import annotations

from warden.sac.guard import GuardVerdict, screen_and_emit, screen_tool_call

__all__ = ["GuardVerdict", "screen_and_emit", "screen_tool_call"]
