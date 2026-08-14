"""
SEP / sovereign / data-pod key material must fail CLOSED, never fall back to a
git-committed public constant (vuln-0003 / CWE-798).

Strix forged sovereignty attestations and causal-transfer proofs that passed
Warden's own verifiers, and derived the data-pod Fernet key, purely from public
source constants ("dev-sep-key-insecure", "dev-sovereign-attest-key-insecure",
"dev-vault-key-insecure-do-not-use") reachable whenever the master key was unset
(boot only warns). Those constants are gone; the resolvers now raise in prod.
"""
from __future__ import annotations

import pytest

import warden.secret_keys as sk
from warden.secret_keys import InsecureKeyError

_OLD_PUBLIC_CONSTANTS = {
    b"dev-sep-key-insecure",
    b"dev-sovereign-attest-key-insecure",
    b"dev-vault-key-insecure-do-not-use",
}


@pytest.fixture
def _prod_no_master(monkeypatch):
    """Production posture with no master key configured — resolve_key must raise."""
    monkeypatch.setattr(sk, "_master_secret", lambda: "")
    monkeypatch.setattr(sk, "_dev_mode", lambda: False)


def test_sep_transfer_proof_key_fails_closed(_prod_no_master):
    from warden.communities.sep import _sep_key
    with pytest.raises(InsecureKeyError):
        _sep_key()


def test_knock_key_fails_closed(_prod_no_master):
    from warden.communities.knock import _sep_key
    with pytest.raises(InsecureKeyError):
        _sep_key()


def test_peering_key_fails_closed(_prod_no_master):
    from warden.communities.peering import _sep_key
    with pytest.raises(InsecureKeyError):
        _sep_key()


def test_sovereign_attest_key_fails_closed(_prod_no_master):
    from warden.sovereign.attestation import _attest_key
    with pytest.raises(InsecureKeyError):
        _attest_key()


def test_data_pod_fernet_key_fails_closed(monkeypatch):
    # data_pod keeps its sha256(master) derivation (to protect at-rest data) but
    # must raise in prod rather than use the public constant.
    from warden.config import settings
    monkeypatch.setattr(settings, "warden_env", "production", raising=False)
    monkeypatch.setattr(settings, "allow_unauthenticated", False, raising=False)
    monkeypatch.delenv("COMMUNITY_VAULT_KEY", raising=False)
    monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
    from warden.communities.data_pod import _vault_key
    with pytest.raises(InsecureKeyError):
        _vault_key()


def test_dev_keys_are_not_the_public_constants():
    """Even in dev, the derived key must not equal any old committed constant."""
    from warden.communities.sep import _sep_key as sep_key
    from warden.sovereign.attestation import _attest_key
    assert sep_key() not in _OLD_PUBLIC_CONSTANTS
    assert _attest_key() not in _OLD_PUBLIC_CONSTANTS
