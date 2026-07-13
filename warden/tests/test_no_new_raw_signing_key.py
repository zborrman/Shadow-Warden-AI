"""
warden/tests/test_no_new_raw_signing_key.py — Phase 7 key-hygiene ratchet.

Counts raw-env reads of *signing-key-shaped* secrets (HMAC / SIGNING / JWT_SECRET /
*_SECRET / *_INTENT_KEY) across warden/, excluding the sanctioned homes. Enforces a
committed baseline that may only DROP.

Why a ratchet and not a ban: a few of these genuinely cannot be derived — third-party
webhook verification secrets (Stripe, Lemon Squeezy) are issued by the provider, so
they must be read raw. Freezing the count blocks *new* forgeable-key paths while the
remaining legitimate reads stay put.

The rule for new code: a key you SIGN with must come from
``warden.secret_keys.resolve_key(env_name, purpose=...)``, which honours an explicit
operator override, else derives a domain-separated subkey from the boot-validated
VAULT_MASTER_KEY, else RAISES. Never `os.getenv("X_SECRET", "")` + "skip the check if
empty" — that is a fail-open signature bypass (exactly the hole Phase 7 closed in
agentic/mandate.py, where an unset MANDATE_SECRET accepted unsigned payment mandates).

Regenerate after a genuine reduction (an increase fails before it can write):

    UPDATE_SIGNING_KEY_BASELINE=1 pytest warden/tests/test_no_new_raw_signing_key.py
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

_WARDEN = Path(__file__).resolve().parent.parent
_BASELINE = Path(__file__).parent / "raw_signing_key_baseline.json"

# os.getenv("X_SECRET") / os.environ["X_HMAC_KEY"] / os.environ.get("X_JWT_SECRET")
_PAT = re.compile(
    r"""os\.(?:getenv|environ(?:\.get)?)\s*[(\[]\s*["']"""
    r"""([A-Z0-9_]*(?:HMAC|SIGNING|JWT_SECRET|_SECRET|INTENT_KEY)[A-Z0-9_]*)["']"""
)

# Sanctioned to read signing secrets from env:
#   secret_keys.py — IS the resolver (it must read the env var and the master key)
#   config.py      — the typed config home
_EXEMPT = {"secret_keys.py", "config.py"}


def count_raw_signing_keys() -> tuple[int, dict[str, int]]:
    total = 0
    per_file: dict[str, int] = {}
    for py in sorted(_WARDEN.rglob("*.py")):
        rel = py.relative_to(_WARDEN)
        if rel.parts[0] == "tests" or py.name in _EXEMPT:
            continue
        try:
            src = py.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        n = len(_PAT.findall(src))
        if n:
            per_file[str(rel).replace("\\", "/")] = n
        total += n
    return total, per_file


def test_no_new_raw_signing_key():
    total, per_file = count_raw_signing_keys()
    current = {"total": total, "per_file": dict(sorted(per_file.items()))}

    if os.getenv("UPDATE_SIGNING_KEY_BASELINE") == "1" or not _BASELINE.exists():
        _BASELINE.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        if os.getenv("UPDATE_SIGNING_KEY_BASELINE") == "1":
            import pytest
            pytest.skip(f"raw signing-key baseline regenerated: total={total}")

    base = json.loads(_BASELINE.read_text(encoding="utf-8"))
    assert total <= base["total"], (
        f"Raw-env signing-key reads rose: {total} > baseline {base['total']}. "
        "A key you sign with must be resolved via "
        "warden.secret_keys.resolve_key(env_name, purpose=...) so it fails CLOSED "
        "when unset — never os.getenv(...) with a 'skip the check if empty' fallback. "
        "After a genuine reduction: UPDATE_SIGNING_KEY_BASELINE=1 pytest "
        "warden/tests/test_no_new_raw_signing_key.py"
    )
