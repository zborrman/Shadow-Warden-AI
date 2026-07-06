"""
warden/secret_keys.py
───────────────────────
Fail-closed resolver for HMAC signing keys.

Historically several modules defaulted their signing secret to a **public,
git-committed constant** (``"shadow-warden-l402-dev"``, ``"federation-default-key"``,
…).  Because the source is public, anyone could forge the corresponding token
(payment macaroons, KYA trust assertions, cross-agent task tokens) whenever the
matching env var happened to be unset in a deployment.

:func:`resolve_key` closes that hole:

  1. If the module's own env var is set, use it verbatim (operator override).
  2. Else derive a **domain-separated subkey** from the boot-validated master
     secret (``VAULT_MASTER_KEY`` / ``COMMUNITY_VAULT_KEY``) via
     ``HMAC(master, "warden.signing.<purpose>")`` — distinct per purpose so an
     L402 token can never be replayed as a KYA assertion.
  3. Else, in dev/test only (``ALLOW_UNAUTHENTICATED=true`` or
     ``ALLOW_INSECURE_SECRETS=true``), derive from a clearly-marked insecure
     master so the suite runs without provisioning every key.
  4. Otherwise **raise** — production must never sign with a guessable key.

The master key is always present in a correct deployment: startup halts unless
``VAULT_MASTER_KEY`` is a valid Fernet key (see ``main.py`` #1).
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os

log = logging.getLogger("warden.secret_keys")

__all__ = ["resolve_key", "InsecureKeyError"]

_INSECURE_DEV_MASTER = b"warden-insecure-dev-master-do-not-use-in-prod"


class InsecureKeyError(RuntimeError):
    """Raised when no secure signing key can be resolved in a production context."""


def _dev_mode() -> bool:
    return (
        os.getenv("ALLOW_UNAUTHENTICATED", "false").strip().lower() == "true"
        or os.getenv("ALLOW_INSECURE_SECRETS", "false").strip().lower() == "true"
    )


def _master_secret() -> str | None:
    return os.getenv("VAULT_MASTER_KEY") or os.getenv("COMMUNITY_VAULT_KEY")


def resolve_key(env_name: str, *, purpose: str) -> bytes:
    """Return the signing key bytes for *purpose*, failing closed in production.

    Parameters
    ----------
    env_name : str
        Operator-override env var (e.g. ``"L402_HMAC_KEY"``). If set, wins.
    purpose : str
        Stable domain-separation label (e.g. ``"l402"``). Changing it rotates
        every derived token, so keep it constant across releases.
    """
    explicit = os.getenv(env_name)
    if explicit:
        return explicit.encode()

    label = f"warden.signing.{purpose}".encode()

    master = _master_secret()
    if master:
        return hmac.new(master.encode(), label, hashlib.sha256).digest()

    if _dev_mode():
        log.warning(
            "secret_keys: deriving INSECURE dev key for %s (%s). Never use in production.",
            env_name, purpose,
        )
        return hmac.new(_INSECURE_DEV_MASTER, label, hashlib.sha256).digest()

    raise InsecureKeyError(
        f"FATAL: no signing key for {purpose!r}. Set {env_name} or VAULT_MASTER_KEY. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
