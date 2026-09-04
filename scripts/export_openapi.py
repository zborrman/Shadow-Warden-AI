#!/usr/bin/env python3
"""
scripts/export_openapi.py
──────────────────────────
Regenerate ``site/public/openapi.json`` from the live application.

The site publishes a copy of the OpenAPI document so that an agent reading
shadow-warden-ai.com can find the API without first discovering that the API
lives on a different host. That copy was hand-synced, and by 2026-09 it had
drifted a long way from what the gateway actually serves: it declared version
5.6.0 against a 7.9.0 gateway and was missing 96 paths, including every route
the site's own developer portal points at — ``/mcp/`` among them.

Run this whenever routes or the API description change:

    python scripts/export_openapi.py

Then commit the result. ``warden/tests/test_site_agent_readiness.py`` fails if
the published copy falls behind the gateway version again, and the CI landing
check fails if ``landing/`` is not rebuilt afterwards.

Optional routers
────────────────
The path count depends on which optional routers import successfully in the
environment this runs in. That is why the guard checks the version and a named
set of critical paths rather than demanding an exact byte match — a spec
exported on a machine missing one optional dependency is stale in a way nobody
would notice, but it is not wrong about the paths it does contain.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "site" / "public" / "openapi.json"

#: Routes the site advertises by name. Exporting a spec without them means an
#: optional router failed to mount, and publishing that would break the links.
REQUIRED_PATHS = (
    "/filter",
    "/filter/batch",
    "/health",
    "/mcp/",
    "/.well-known/mcp.json",
    "/.well-known/ai-market.json",
)


def main() -> int:
    sys.path.insert(0, str(ROOT))
    # Keep the export side-effect free: no Evolution Engine, no auth wall, no
    # Redis, and a writable model cache.
    os.environ.setdefault("ANTHROPIC_API_KEY", "")
    os.environ.setdefault("WARDEN_API_KEY", "")
    os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
    os.environ.setdefault("REDIS_URL", "memory://")

    from warden.main import app  # noqa: PLC0415

    spec = app.openapi()

    missing = [p for p in REQUIRED_PATHS if p not in spec["paths"]]
    if missing:
        print(f"refusing to export: routers did not mount, missing {missing}", file=sys.stderr)
        return 1
    if not spec.get("servers"):
        print("refusing to export: the spec has no servers block", file=sys.stderr)
        return 1

    TARGET.write_text(
        json.dumps(spec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"wrote {TARGET.relative_to(ROOT)} — v{spec['info']['version']}, {len(spec['paths'])} paths")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
