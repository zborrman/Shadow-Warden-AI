"""warden/tests/test_metrics_survive_multiple_workers.py

Forked uvicorn workers each keep their own prometheus_client registry.

`docker-compose.yml` runs warden with `UVICORN_WORKERS=4`. All four processes
share the listening socket, so every `/metrics` scrape is answered by whichever
worker the kernel hands the connection to — and each one reports only what it
personally recorded.

Measured on production 2026-08-29, ten consecutive scrapes of the same endpoint:

    http_requests_total -> [1, 1, 1, 51, 51, 51, 0, 0, 0, 0]

Prometheus reads every drop as a counter reset, so `rate()` over any warden
counter is noise, and every rate-based alert built on one is measuring nothing
in particular. It is also why a counter can look absent right after the code
that increments it demonstrably ran: the increment landed in a different
worker's registry than the scrape hit.

Two invariants keep that from coming back:

  1. More than one worker requires `PROMETHEUS_MULTIPROC_DIR`. The instrumentator
     builds a MultiProcessCollector registry when it is set, which is what makes
     /metrics aggregate across workers instead of reporting one of them.

  2. Every Gauge declares an explicit `multiprocess_mode`. Under a multiprocess
     registry the default is `all`, which exports one series per pid — so an
     alert of the shape `warden_x == 0` starts evaluating per-worker and fires
     whenever any single worker holds a zero. These gauges hold *shared* state
     (DB counts, corpus scores) that every worker computes identically, so the
     correct mode is `livemostrecent`: latest value, dead pids dropped. A sum
     would multiply by the worker count — 7 failing canaries reading as 28.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE = _ROOT / "docker-compose.yml"
_ENTRYPOINT = _ROOT / "warden" / "entrypoint.sh"
_METRIC_MODULES = (
    _ROOT / "warden" / "metrics.py",
    _ROOT / "warden" / "voice" / "metrics.py",
)

#: A Gauge declaration and everything up to its closing paren.
_GAUGE_BLOCK = re.compile(
    r"^(?P<indent>\s*)(?P<symbol>[A-Z][A-Z0-9_]*)\s*=\s*(?:cast\([^,]+,\s*)?Gauge\(\s*\n"
    r"(?P<body>.*?)^(?P=indent)\)",
    re.MULTILINE | re.DOTALL,
)


def _warden_environment() -> dict[str, str]:
    compose = yaml.safe_load(_COMPOSE.read_text(encoding="utf-8"))
    env: dict[str, str] = {}
    for entry in compose["services"]["warden"].get("environment", []):
        if isinstance(entry, str) and "=" in entry:
            key, _, value = entry.partition("=")
            env[key.strip()] = value.strip()
    return env


def test_multiple_workers_require_a_shared_registry_dir() -> None:
    env = _warden_environment()
    workers_raw = env.get("UVICORN_WORKERS", "")
    match = re.search(r"(\d+)", workers_raw)
    workers = int(match.group(1)) if match else 1

    if workers <= 1:
        pytest.skip(f"warden runs a single worker ({workers_raw!r}); no split possible")

    assert "PROMETHEUS_MULTIPROC_DIR" in env, (
        f"warden runs {workers} uvicorn workers but PROMETHEUS_MULTIPROC_DIR is not "
        "in its compose environment. Each forked worker then keeps its own "
        "prometheus registry and /metrics reports whichever one answered the "
        "scrape, so every counter appears to reset at random and no rate-based "
        "alert means anything"
    )


def test_the_entrypoint_clears_stale_pid_files() -> None:
    """Files are keyed by pid and outlive the process that wrote them.

    Left in place, a dead worker's file is summed into every future scrape, so
    counters only ever climb across restarts. The clear has to happen in the
    parent before the fork — doing it from the FastAPI lifespan would run once
    per worker, after forking, and delete the siblings' live files.
    """
    script = _ENTRYPOINT.read_text(encoding="utf-8")
    assert "PROMETHEUS_MULTIPROC_DIR" in script, (
        "entrypoint.sh never prepares the multiprocess directory"
    )
    assert re.search(r"rm\s+-f\s+\"?\$\{?PROMETHEUS_MULTIPROC_DIR", script), (
        "entrypoint.sh does not clear stale pid files from "
        "PROMETHEUS_MULTIPROC_DIR; counters will carry dead workers' values "
        "across every restart"
    )
    exec_at = script.find("exec gosu wardenuser uvicorn")
    clear_at = script.find("PROMETHEUS_MULTIPROC_DIR")
    if exec_at != -1:
        assert clear_at < exec_at, (
            "the multiprocess directory is prepared after uvicorn is exec'd"
        )


def test_every_gauge_declares_a_multiprocess_mode() -> None:
    """Default `all` exports one series per pid and changes what alerts mean."""
    missing: list[str] = []
    checked = 0
    for module in _METRIC_MODULES:
        if not module.exists():
            continue
        text = module.read_text(encoding="utf-8")
        for block in _GAUGE_BLOCK.finditer(text):
            checked += 1
            if "multiprocess_mode" not in block.group("body"):
                missing.append(f"{module.name}:{block.group('symbol')}")

    assert checked, "no Gauge declarations were found — the parser is broken"
    assert not missing, (
        "these gauges have no explicit multiprocess_mode, so under the "
        "multiprocess registry they export one series per worker pid. An alert "
        "like `metric == 0` then fires whenever any single worker holds zero:\n"
        + "\n".join(f"  {m}" for m in missing)
    )


def test_the_gauge_parser_actually_matches_something() -> None:
    """Guard the guard: a broken regex makes the sweep above pass vacuously."""
    sample = '''
    try:
        SOME_GAUGE = Gauge(
            "warden_some_gauge",
            "help text",
        )
    except ValueError:
        pass
'''
    found = list(_GAUGE_BLOCK.finditer(sample))
    assert len(found) == 1, f"the Gauge parser matched {len(found)} blocks, expected 1"
    assert found[0].group("symbol") == "SOME_GAUGE"
    assert "multiprocess_mode" not in found[0].group("body")
