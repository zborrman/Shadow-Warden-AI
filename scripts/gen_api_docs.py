"""
scripts/gen_api_docs.py
───────────────────────
MkDocs gen-files plugin: auto-generate API reference pages from the
FastAPI OpenAPI schema.

Runs during `mkdocs build`. Output goes to docs/api/<router>.md.

For each FastAPI router (filter, community, security, soc, agent, secrets,
financial) it emits a Markdown page with:
  - Every endpoint (METHOD /path)
  - Summary / description from the route docstring
  - Request body fields (from OpenAPI schema)
  - Example curl snippet

Usage (in mkdocs.yml):
  plugins:
    - gen-files:
        scripts:
          - scripts/gen_api_docs.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow import from repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    import mkdocs_gen_files  # type: ignore
except ImportError:
    # Running outside mkdocs — just skip
    raise SystemExit(0)


_ROUTERS = {
    "filter":    ("/filter",         "Core filter pipeline"),
    "community": ("/community",      "Business Community"),
    "security":  ("/security",       "Cyber Security Hub"),
    "soc":       ("/soc",            "SOC Dashboard"),
    "agent":     ("/agent",          "SOVA Agent"),
    "secrets":   ("/secrets",        "Secrets Governance"),
    "financial": ("/financial",      "Financial Impact"),
    "obsidian":  ("/obsidian",       "Obsidian Integration"),
}


def _load_openapi() -> dict:
    """Load OpenAPI spec from the FastAPI app (import-time, no server needed)."""
    try:
        import os
        os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
        os.environ.setdefault("WARDEN_API_KEY", "")
        os.environ.setdefault("REDIS_URL", "memory://")
        os.environ.setdefault("LOGS_PATH", "/tmp/mkdocs_gen_logs.json")
        os.environ.setdefault("DYNAMIC_RULES_PATH", "/tmp/mkdocs_gen_rules.json")
        os.environ.setdefault("MODEL_CACHE_DIR", "/tmp/mkdocs_gen_models")

        from warden.main import app  # noqa: PLC0415
        return app.openapi()
    except Exception as exc:
        return {"info": {"title": "Shadow Warden AI", "version": "4.11"},
                "paths": {}, "_error": str(exc)}


def _method_badge(method: str) -> str:
    colors = {"get": "blue", "post": "green", "delete": "red",
              "put": "orange", "patch": "purple"}
    c = colors.get(method.lower(), "grey")
    return f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:4px;font-size:.8rem;font-weight:700">{method.upper()}</span>'


def _render_page(title: str, prefix: str, paths: dict) -> str:
    lines = [f"# {title}\n"]
    matched = {p: v for p, v in paths.items() if p.startswith(prefix)}
    if not matched:
        lines.append("*No endpoints found — run `mkdocs build` with the warden package installed.*\n")
        return "\n".join(lines)

    for path, methods in sorted(matched.items()):
        for method, op in methods.items():
            if method in ("parameters", "summary"):
                continue
            summary = op.get("summary", "")
            desc    = op.get("description", "")
            tags    = ", ".join(f"`{t}`" for t in op.get("tags", []))

            lines.append(f"## {_method_badge(method)} `{path}`\n")
            if summary:
                lines.append(f"**{summary}**\n")
            if tags:
                lines.append(f"Tags: {tags}\n")
            if desc:
                lines.append(f"{desc.strip()}\n")

            # Request body
            body = op.get("requestBody", {})
            schema_ref = (
                body.get("content", {})
                    .get("application/json", {})
                    .get("schema", {})
            )
            if schema_ref:
                lines.append("**Request body**\n")
                props = schema_ref.get("properties", {})
                required = schema_ref.get("required", [])
                if props:
                    lines.append("| Field | Type | Required | Description |")
                    lines.append("|-------|------|----------|-------------|")
                    for fname, fdef in props.items():
                        ftype = fdef.get("type", fdef.get("$ref", "object").split("/")[-1])
                        req   = "✓" if fname in required else ""
                        fdesc = fdef.get("description", "")
                        lines.append(f"| `{fname}` | {ftype} | {req} | {fdesc} |")
                    lines.append("")

            # Responses
            responses = op.get("responses", {})
            if responses:
                lines.append("**Responses:** " + " · ".join(
                    f"`{code}`" for code in responses
                ) + "\n")

            # curl snippet
            lines.append("```bash")
            lines.append(f"curl -X {method.upper()} http://localhost:8001{path} \\")
            lines.append('  -H "X-API-Key: $WARDEN_API_KEY" \\')
            if method.lower() in ("post", "put", "patch"):
                lines.append('  -H "Content-Type: application/json" \\')
                lines.append("  -d '{}'")
            lines.append("```\n")
            lines.append("---\n")

    return "\n".join(lines)


def main() -> None:
    spec  = _load_openapi()
    paths = spec.get("paths", {})
    info  = spec.get("info", {})

    # Overview page
    overview = (
        f"# API Reference\n\n"
        f"**{info.get('title','Shadow Warden AI')}** v{info.get('version','4.11')}\n\n"
        f"Base URL: `http://localhost:8001`\n\n"
        f"All endpoints require `X-API-Key` header unless noted.\n\n"
        "## Routers\n\n"
        + "\n".join(
            f"- [{title}]({key}.md) — `{prefix}/*`"
            for key, (prefix, title) in _ROUTERS.items()
        )
    )
    with mkdocs_gen_files.open("api/index.md", "w") as f:
        f.write(overview)

    # Per-router pages
    for key, (prefix, title) in _ROUTERS.items():
        content = _render_page(f"{title} API", prefix, paths)
        with mkdocs_gen_files.open(f"api/{key}.md", "w") as f:
            f.write(content)


main()
