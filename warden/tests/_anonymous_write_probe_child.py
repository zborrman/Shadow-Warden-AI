"""Child process for the anonymous write and read probes -- do not import.

Run as a script: the path to write results JSON to, then optionally ``read``
to probe GET routes instead of the write methods. It must
be a separate process with a canonical, deploy-like environment; the test
module explains why a same-process measurement reports a clean bill of health
it has not earned.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading

from fastapi.testclient import TestClient

import warden.auth_guard as ag

logging.basicConfig(level=logging.ERROR, stream=sys.stderr)

# Auth genuinely enabled: a probe run against a gateway in dev mode measures
# nothing. Patch the module globals rather than the env, because modules bind
# `require_api_key` by value at import.
ag._VALID_KEY = "r0-probe-key"
ag._KEYS_PATH = ""

import warden.main as m  # noqa: E402 - must follow the patch above

WRITE = ("post", "put", "patch", "delete")
_PROBE = "r0probe"


def _deref(schema: dict, defs: dict, depth: int = 0) -> dict:
    if depth > 6 or not isinstance(schema, dict):
        return {}
    if "$ref" in schema:
        name = schema["$ref"].rsplit("/", 1)[-1]
        return _deref(defs.get(name, {}), defs, depth + 1)
    for key in ("allOf", "anyOf", "oneOf"):
        if schema.get(key):
            merged = _deref(schema[key][0], defs, depth + 1)
            merged.update({k: v for k, v in schema.items() if k != key})
            return merged
    return schema


def _dummy(schema: dict, defs: dict, depth: int = 0):
    """Synthesise a minimal value that satisfies ``schema``.

    A 422 only proves validation rejected the payload *before* the handler ran,
    so a probe that posts ``{}`` everywhere cannot tell a gated route from a
    wide-open one. Bodies are built from the route's own OpenAPI schema.
    """
    schema = _deref(schema, defs, depth)
    if depth > 5:
        return None
    if "default" in schema:
        return schema["default"]
    if schema.get("enum"):
        return schema["enum"][0]
    t = schema.get("type")
    if isinstance(t, list):
        t = next((x for x in t if x != "null"), "string")
    if t == "object" or (t is None and "properties" in schema):
        props = schema.get("properties", {})
        return {n: _dummy(props.get(n, {}), defs, depth + 1) for n in schema.get("required", [])}
    if t == "array":
        if (schema.get("minItems") or 0) > 0:
            return [_dummy(schema.get("items", {}), defs, depth + 1)] * schema["minItems"]
        return []
    if t == "integer":
        return 1
    if t == "number":
        return 1.0
    if t == "boolean":
        return False
    if t == "null":
        return None
    if t == "string":
        pattern = schema.get("pattern")
        if pattern:
            for cand in ("low", "info", "medium", "high", "critical", "GENERAL",
                         "did:web:example.invalid", _PROBE, "2026-01-01"):
                try:
                    if re.search(pattern, cand):
                        return cand
                except re.error:
                    break
        minimum = schema.get("minLength") or 0
        if minimum > len(_PROBE):
            return _PROBE + "x" * (minimum - len(_PROBE))
    fmt = schema.get("format")
    if fmt == "date-time":
        return "2026-01-01T00:00:00Z"
    if fmt == "date":
        return "2026-01-01"
    if fmt == "email":
        return "probe@example.invalid"
    if fmt in ("uri", "url"):
        return "https://example.invalid/probe"
    return _PROBE


# A streaming GET (SSE) never returns under TestClient. Each request runs in a
# daemon thread with a deadline; a route that does not answer is recorded as
# -2 and the process leaves through os._exit so the stuck thread cannot hold it.
_DEADLINE_S = 8


def main(out_path: str, methods: tuple[str, ...] = WRITE) -> None:
    client = TestClient(m.app, raise_server_exceptions=False)
    spec = m.app.openapi()
    defs = spec.get("components", {}).get("schemas", {})
    results: dict[str, int] = {}

    for path, ops in spec.get("paths", {}).items():
        for method, op in ops.items():
            if method not in methods:
                continue
            url = path
            params: dict[str, object] = {}
            for p in op.get("parameters", []):
                name, loc = p.get("name"), p.get("in")
                if loc == "path":
                    url = url.replace("{" + str(name) + "}", _PROBE)
                elif loc == "query" and p.get("required"):
                    params[name] = _dummy(p.get("schema", {}), defs)
            body = None
            content = (op.get("requestBody") or {}).get("content", {})
            if "application/json" in content:
                body = _dummy(content["application/json"].get("schema", {}), defs)
            key = method.upper() + " " + path
            box: dict[str, int] = {}

            def _run(method=method, url=url, params=params, body=body, key=key, box=box):
                try:
                    resp = client.request(
                        method.upper(), url,
                        params=params or None,
                        json=body if body is not None else None,
                        follow_redirects=False,
                    )
                    box["s"] = resp.status_code
                except Exception as exc:  # noqa: BLE001 - a crash is a result, not a stop
                    box["s"] = -1
                    print(f"{key}: {type(exc).__name__}: {exc}", file=sys.stderr)

            worker = threading.Thread(target=_run, daemon=True)
            worker.start()
            worker.join(_DEADLINE_S)
            results[key] = box.get("s", -2)

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=1, sort_keys=True)


if __name__ == "__main__":
    main(sys.argv[1], ("get",) if sys.argv[2:3] == ["read"] else WRITE)
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)
