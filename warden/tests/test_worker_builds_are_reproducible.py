"""
warden/tests/test_worker_builds_are_reproducible.py

Every Cloudflare Worker in this repo must build from a pinned dependency set.

Two of the four did not. `cloudflare/installer-worker` and
`cloudflare/preflight-worker` declared `wrangler: ^3.0.0` with **no
package-lock.json**, so Cloudflare Workers Builds resolved whatever 3.x was
newest at build time: the same commit could build differently on two different
days, and a dependency release could break a build with no change in this
repository. That is the defect class this project has an incident for already —
an unbounded pin broke a monkeypatch in `prometheus-fastapi-instrumentator`
0.8.11 and took the gateway down (PR #229).

It stopped being hypothetical: the `shadow-warden-installer` build went red on
2026-10-03 having been green on 2026-10-02, while `git log` shows the worker's
directory untouched since #515. With no lockfile there is no way to tell from
the repository what the two builds actually ran, which is most of why the
failure was hard to diagnose.

The other half of the rule is the major version. wrangler 3 is end-of-life and
prints "update to the latest version to prevent critical errors" on every
invocation; the two maintained workers (`worker/`,
`workers/shadow-warden-marketplace/`) were already on 4.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent.parent

# Directories holding a Worker: one wrangler.toml each.
_WORKER_DIRS = sorted(
    p.parent for p in _REPO.glob("*/wrangler.toml")
) + sorted(
    p.parent for p in _REPO.glob("*/*/wrangler.toml")
    if "node_modules" not in p.parts
)


def _worker_dirs() -> list[Path]:
    return [d for d in _WORKER_DIRS if (d / "package.json").is_file()]


def test_the_scan_found_the_workers() -> None:
    """A guard that enumerates nothing passes while protecting nothing."""
    names = {d.name for d in _worker_dirs()}
    assert {"installer-worker", "preflight-worker", "shadow-warden-marketplace"} <= names, (
        f"expected the known Workers, found {sorted(names)}"
    )


@pytest.mark.parametrize("worker", _worker_dirs(), ids=lambda d: d.name)
def test_worker_has_a_lockfile(worker: Path) -> None:
    lock = worker / "package-lock.json"
    assert lock.is_file(), (
        f"{worker.relative_to(_REPO).as_posix()} has no package-lock.json — its build "
        f"resolves fresh dependency versions every run, so the same commit can build "
        f"differently on two days and a release elsewhere can break it with no change "
        f"here. Run `npm install --package-lock-only` in that directory and commit it."
    )


@pytest.mark.parametrize("worker", _worker_dirs(), ids=lambda d: d.name)
def test_worker_pins_a_supported_wrangler_major(worker: Path) -> None:
    pkg = json.loads((worker / "package.json").read_text(encoding="utf-8"))
    spec = (pkg.get("devDependencies", {}) | pkg.get("dependencies", {})).get("wrangler")
    assert spec, f"{worker.name} declares no wrangler dependency"
    major = spec.lstrip("^~>=< ").split(".")[0]
    assert major == "4", (
        f"{worker.relative_to(_REPO).as_posix()} pins wrangler {spec}. wrangler 3 is "
        f"end-of-life and warns on every run that it may cause critical errors."
    )


def test_no_workflow_deploys_with_a_floating_wrangler() -> None:
    """Pinning the dependency is worthless if the thing that deploys ignores it.

    The first version of this guard checked `package.json` and the lockfile and
    stopped there, while `.github/workflows/ci.yml` deployed the preflight Worker
    with a literal `npx wrangler@3 deploy` — so the Worker's pinned Wrangler 4
    was never the one that ran. A guard that inspects the declaration and not the
    caller is the defect this repository keeps finding in its own rules.
    """
    bad: list[str] = []
    for wf in sorted((_REPO / ".github" / "workflows").glob("*.yml")):
        for n, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"\bnpx\s+(?:--yes\s+)?wrangler@", line):
                bad.append(f"{wf.name}:{n}: {line.strip()}")
    assert not bad, (
        "a workflow pins its own Wrangler on the command line, bypassing the "
        "Worker's package.json and lockfile:\n  " + "\n  ".join(bad)
        + "\nRun `npm ci` in the worker directory and call `npx wrangler` instead."
    )


@pytest.mark.parametrize("worker", _worker_dirs(), ids=lambda d: d.name)
def test_lockfile_agrees_with_the_declared_range(worker: Path) -> None:
    """A lockfile that resolved a different major is worse than none: it reads
    as a pin while the build runs something else."""
    lock_path = worker / "package-lock.json"
    if not lock_path.is_file():
        pytest.skip("covered by test_worker_has_a_lockfile")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    entry = lock.get("packages", {}).get("node_modules/wrangler")
    assert entry, f"{worker.name}: lockfile does not contain wrangler"
    assert entry["version"].split(".")[0] == "4", (
        f"{worker.name}: lockfile pins wrangler {entry['version']}"
    )
