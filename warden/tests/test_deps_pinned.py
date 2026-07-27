"""
warden/tests/test_deps_pinned.py
────────────────────────────────
P-0 ratchet: every dependency that reaches a built image is *version-decided*.

Why this exists
───────────────
On 2026-07-26 the production API returned 502 for every request. The cause was
not a code change: `warden/requirements.txt` said
``prometheus-fastapi-instrumentator>=8.0.0``, a rebuild resolved 8.1.0, and
8.1.0 changed the arity of ``_get_route_name`` — which `warden/main.py`
monkeypatches. CI had been green the whole time because CI installs with
``-c warden/constraints.txt`` and had tested 8.0.2. The Dockerfile did not pass
``-c``.

Measuring the gap the next day: **48** packages differed between the CI-tested
set and the running production image. One of them had already fired.

The invariant
─────────────
requirements.txt states *intent* (floors). constraints.txt states the *answer*.
Anything installed into an image is decided by an explicit ``==`` or by a
constraints file — never by "whatever PyPI serves at build time".

These tests are cheap, hermetic (no network, no Docker) and pure text analysis.
"""
from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]

# Installed outside the constraints-governed resolution, pinned explicitly in
# warden/Dockerfile instead. Both are justified in constraints.txt's header:
#   torch         — `+cpu` local version lives only on the PyTorch CPU index
#   liboqs-python — cmake source build, deliberately fail-open
_CONSTRAINTS_EXEMPT = {"torch", "liboqs-python"}

# Flags whose *next* token is a value, not a package spec.
_ARG_TAKING = {
    "-r", "--requirement", "-c", "--constraint", "-t", "--target",
    "--index-url", "-i", "--extra-index-url", "--find-links", "-f",
    "--python-version", "--platform", "--abi", "--implementation",
    "--cache-dir", "--prefix", "--root", "--upgrade-strategy",
}

# Shell operators that end the pip command proper.
_STOP = {"||", "&&", ";", "|", ">", ">>", "<", "2>", "2>>"}


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def _version_tuple(v: str) -> tuple:
    out: list[tuple[int, int]] = []
    for part in re.split(r"[.\-+]", v):
        out.append((0, int(part)) if part.isdigit() else (1, 0))
    return tuple(out)


def _parse_pep508(path: Path) -> list[tuple[str, str, str]]:
    """-> [(normalised_name, version_spec, raw_line)] for a requirements/constraints file."""
    entries: list[tuple[str, str, str]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$", line)
        if m:
            entries.append((_norm(m.group(1)), m.group(3).strip(), raw.strip()))
    return entries


def _run_commands(dockerfile: Path) -> list[str]:
    """Join line-continuations and return one string per RUN instruction."""
    text = dockerfile.read_text(encoding="utf-8")
    text = re.sub(r"\\\s*\n\s*", " ", text)          # fold continuations
    text = re.sub(r"^\s*#.*$", "", text, flags=re.M)  # drop comment lines
    return [
        line.strip()
        for line in text.splitlines()
        if re.match(r"^\s*RUN\b", line) and "pip install" in line
    ]


def _pip_invocations(run_cmd: str) -> list[list[str]]:
    """Split a RUN body into the token lists of each `pip install ...` it contains."""
    try:
        tokens = shlex.split(run_cmd, posix=True)
    except ValueError:  # unbalanced quotes — surface as a parse failure, not a pass
        pytest.fail(f"Could not tokenise Dockerfile RUN line: {run_cmd[:120]}")

    invocations: list[list[str]] = []
    current: list[str] | None = None
    for i, tok in enumerate(tokens):
        if tok in _STOP or tok.startswith(("2>", ">")):
            if current is not None:
                invocations.append(current)
                current = None
            continue
        if tok == "install" and i > 0 and Path(tokens[i - 1]).name.startswith("pip"):
            if current is not None:
                invocations.append(current)
            current = []
            continue
        if current is not None:
            current.append(tok)
    if current is not None:
        invocations.append(current)
    return invocations


def _dockerfiles_with_pip() -> list[Path]:
    found = [
        p for p in sorted(_REPO.glob("*/Dockerfile"))
        if "pip install" in p.read_text(encoding="utf-8")
    ]
    assert found, "no Dockerfile with a pip install found — has the layout changed?"
    return found


# ─────────────────────────────────────────────────────────────────────────────
# 1. The lockfile itself
# ─────────────────────────────────────────────────────────────────────────────
def test_constraints_are_all_exact_pins():
    """A constraints file with a range in it does not constrain anything."""
    con = _REPO / "warden" / "constraints.txt"
    loose = [raw for _n, spec, raw in _parse_pep508(con) if not spec.startswith("==")]
    assert not loose, (
        "warden/constraints.txt must contain only exact `==` pins; found:\n  "
        + "\n  ".join(loose)
    )


def test_exactly_one_lockfile():
    """Two lockfiles means one of them is silently stale (conflict C-B)."""
    rogue = [
        p.relative_to(_REPO).as_posix()
        for p in _REPO.rglob("requirements-lock.txt")
        if ".claude" not in p.parts and "node_modules" not in p.parts
    ]
    assert not rogue, (
        "warden/constraints.txt is the single lockfile. Found a competing one: "
        f"{rogue}. Fold its pins into constraints.txt and delete it."
    )


# ─────────────────────────────────────────────────────────────────────────────
# 2. requirements.txt <-> constraints.txt agreement
# ─────────────────────────────────────────────────────────────────────────────
def test_every_requirement_is_constrained():
    req = _parse_pep508(_REPO / "warden" / "requirements.txt")
    con = {n for n, _s, _r in _parse_pep508(_REPO / "warden" / "constraints.txt")}
    missing = sorted(
        n for n, _s, _r in req if n not in con and n not in _CONSTRAINTS_EXEMPT
    )
    assert not missing, (
        "these requirements have no pin in warden/constraints.txt, so their version "
        f"is decided at build time: {missing}"
    )


def test_no_constraint_violates_a_requirement_floor():
    """An unsatisfiable pair fails the build — catch it here, not in Docker."""
    con = {n: spec for n, spec, _r in _parse_pep508(_REPO / "warden" / "constraints.txt")}
    bad = []
    for name, spec, _raw in _parse_pep508(_REPO / "warden" / "requirements.txt"):
        pin = con.get(name)
        floor = re.match(r">=\s*([0-9][^,;\s]*)", spec)
        if pin and floor and _version_tuple(pin.lstrip("=")) < _version_tuple(floor.group(1)):
            bad.append(f"{name}: requires >={floor.group(1)} but pinned to {pin}")
    assert not bad, "constraints contradict requirements:\n  " + "\n  ".join(bad)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Every image install path is version-decided
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("dockerfile", _dockerfiles_with_pip(), ids=lambda p: p.parent.name)
def test_dockerfile_installs_are_version_decided(dockerfile: Path):
    problems: list[str] = []

    for run_cmd in _run_commands(dockerfile):
        for tokens in _pip_invocations(run_cmd):
            has_constraint = any(t in ("-c", "--constraint") for t in tokens)
            req_files: list[str] = []
            packages: list[str] = []

            skip_next = False
            for i, tok in enumerate(tokens):
                if skip_next:
                    skip_next = False
                    if tokens[i - 1] in ("-r", "--requirement"):
                        req_files.append(tok)
                    continue
                if tok in _ARG_TAKING:
                    skip_next = True
                    continue
                if tok.startswith("-") or "://" in tok:
                    continue
                packages.append(tok)

            for pkg in packages:
                if "==" not in pkg:
                    problems.append(
                        f"unpinned package `{pkg}` — use an exact `==` version"
                    )

            # `-r file` is fine when a constraints file decides versions, or when
            # that requirements file is itself fully pinned.
            for rf in req_files:
                if has_constraint:
                    continue
                resolved = (dockerfile.parent / rf).resolve()
                if not resolved.exists():
                    problems.append(f"`-r {rf}` with no `-c` and the file is not in the build context")
                    continue
                loose = [s for _n, s, _raw in _parse_pep508(resolved) if not s.startswith("==")]
                if loose:
                    problems.append(
                        f"`-r {rf}` has {len(loose)} non-exact requirement(s) and no "
                        f"`-c constraints.txt` — build-time resolution decides the version"
                    )

    assert not problems, (
        f"{dockerfile.relative_to(_REPO).as_posix()} can resolve dependencies at build "
        "time:\n  " + "\n  ".join(problems)
    )


def test_warden_image_keeps_torch_cpu_only():
    """
    P-3a: the CPU-only-torch invariant, guarded in text as well as at build time.

    The multi-stage refactor initially staged installs with `pip install
    --prefix=/install`. That keeps /install off sys.path, so the step installing
    requirements.txt could not see the CPU torch installed a step earlier;
    sentence-transformers depends on torch, pip re-resolved it from the default
    index, and the image gained 2.7 GB of nvidia-* wheels plus 691 MB of triton
    — a CUDA build, shipped to a CPU-only host.

    The Dockerfile now asserts this at build time. This test guards the
    assertion itself, so deleting it fails CI in seconds instead of silently
    reopening the hole.
    """
    body = (_REPO / "warden" / "Dockerfile").read_text(encoding="utf-8")
    # The comment block explains *why* `--prefix` is wrong, so the ban has to be
    # checked against instructions only — not against the prose describing it.
    instructions = "\n".join(
        ln for ln in body.splitlines() if not ln.lstrip().startswith("#")
    )

    assert "download.pytorch.org/whl/cpu" in instructions, (
        "torch must come from the PyTorch CPU index; the default index serves the "
        "CUDA build and this product targets CPU-only hosts"
    )
    assert "--prefix=/install" not in instructions, (
        "`pip install --prefix=...` hides earlier installs from later resolution "
        "steps, which is how the CUDA torch got pulled in. Install into the "
        "builder's real site-packages and COPY that."
    )
    for needle, why in (
        ("+cpu", "assert the resolved torch is the +cpu local version"),
        ("find_spec('nvidia')", "assert no nvidia-* CUDA wheels were pulled in"),
        ("find_spec('triton')", "assert the GPU compiler was not pulled in"),
    ):
        assert needle in body, f"warden/Dockerfile lost its build-time check to {why}"


def test_warden_runtime_stage_ships_no_compiler():
    """
    P-3a: a C/C++ toolchain in the running gateway turns a file-write primitive
    into code execution. The build stage may have one; the runtime stage may not.
    """
    body = (_REPO / "warden" / "Dockerfile").read_text(encoding="utf-8")
    stages = re.split(r"^FROM\s+", body, flags=re.M)[1:]
    assert len(stages) >= 2, (
        "warden/Dockerfile is expected to be multi-stage (builder + runtime); "
        "a single stage necessarily ships its own build toolchain"
    )

    runtime = stages[-1]
    apt_lines = [ln for ln in runtime.splitlines() if "apt-get install" in ln or (
        ln.strip().startswith(("gcc", "g++", "cmake", "ninja", "astyle", "libssl-dev"))
    )]
    banned = {"gcc", "g++", "cmake", "ninja-build", "astyle", "libssl-dev"}
    # Only look at the package list, not at prose in comments.
    pkg_text = " ".join(ln.split("#", 1)[0] for ln in apt_lines)
    present = sorted(p for p in banned if re.search(rf"(?<![\w-]){re.escape(p)}(?![\w-])", pkg_text))
    assert not present, (
        f"the runtime stage installs build tooling: {present}. Build it in the "
        "builder stage and COPY the artefacts."
    )


def test_warden_image_uses_the_lockfile():
    """The specific regression that caused the 2026-07-26 outage."""
    body = (_REPO / "warden" / "Dockerfile").read_text(encoding="utf-8")
    install = [ln for ln in body.splitlines() if "pip install -r requirements.txt" in ln]
    assert install, "warden/Dockerfile no longer installs requirements.txt — update this test"
    for line in install:
        assert "-c constraints.txt" in line, (
            "warden/Dockerfile must install with `-c constraints.txt`. Without it the "
            "image resolves floating `>=` requirements at build time and drifts away "
            f"from the set CI tested. Offending line: {line.strip()}"
        )
    assert "COPY requirements.txt constraints.txt" in body, (
        "constraints.txt must be COPYed into the build context alongside requirements.txt"
    )
