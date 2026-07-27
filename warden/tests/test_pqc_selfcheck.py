"""
warden/tests/test_pqc_selfcheck.py
──────────────────────────────────
P-3a: PQC must never again be silently absent.

Background — the failure this guards against is not hypothetical. From v4.7
(`967303cd`) until 2026-07-27, PQC was non-functional in *every* deployed image:

  * `warden/Dockerfile` ran `pip install liboqs-python`, which installs the
    Python **bindings** only. The native liboqs C library is a separate CMake
    build the Dockerfile never performed, despite a comment claiming it did.
  * That step was `|| echo "⚠ liboqs-python build failed …"` — fail-open — so
    the image build always succeeded.
  * At import, `oqs` raised `RuntimeError: No oqs shared libraries found`, and
    `pqc.py` caught it alongside `ImportError` and logged
    "liboqs-python not installed". An operator checking `pip freeze` would see
    liboqs-python present, judge the message stale, and move on.

Verified against production on 2026-07-27: no `liboqs.so` on disk,
`pqc_status()` -> `{'available': False, ...}`. PQC is sold on the Enterprise
tier, so hybrid signing had been degrading to classical Ed25519 unnoticed.

Three things are now true and are pinned here:
  1. the two failure modes are reported distinctly (bindings vs native library),
  2. `pqc_selfcheck()` checks the algorithms are *enabled*, not just importable,
  3. it never raises — it runs on the startup and health paths.
"""
from __future__ import annotations

import warden.crypto.pqc as pqc


def test_selfcheck_never_raises_and_returns_a_pair():
    """Runs on startup and in /health/pipeline — it must not be able to throw."""
    result = pqc.pqc_selfcheck()
    assert isinstance(result, tuple) and len(result) == 2
    ok, detail = result
    assert isinstance(ok, bool)
    assert isinstance(detail, str) and detail


def test_selfcheck_agrees_with_availability_when_unavailable():
    if pqc.is_pqc_available():
        return  # covered by test_selfcheck_passes_when_liboqs_present
    ok, detail = pqc.pqc_selfcheck()
    assert ok is False
    assert detail, "an unavailable PQC stack must explain itself"


def test_selfcheck_passes_when_liboqs_present():
    """On a correctly built image this is the assertion that matters."""
    if not pqc.is_pqc_available():
        return  # dev machines legitimately have no liboqs
    ok, detail = pqc.pqc_selfcheck()
    assert ok is True, f"liboqs imported but self-check failed: {detail}"
    assert pqc._SIG_ALGO in detail


def test_status_explains_itself_when_unavailable():
    """`available: False` with no reason is what made this undiagnosable."""
    status = pqc.pqc_status()
    assert "available" in status
    if not status["available"]:
        assert "unavailable_reason" in status, (
            "pqc_status() must say WHY it is unavailable — 'bindings-missing' and "
            "'native-library-missing' are different problems with different fixes"
        )


def test_unavailable_reason_distinguishes_bindings_from_native_library():
    """
    The whole diagnostic failure was collapsing these two into one message.
    Whichever state this machine is in, the recorded reason must be classified.
    """
    reason = pqc._OQS_UNAVAILABLE_REASON
    if pqc.is_pqc_available():
        assert reason is None
    else:
        assert reason is not None
        assert reason.startswith(("bindings-missing:", "native-library-missing:")), (
            f"unclassified PQC failure reason: {reason!r}"
        )


def test_selfcheck_detects_a_liboqs_missing_the_required_algorithms(monkeypatch):
    """
    A liboqs built without ML-DSA-65 imports fine and fails at first use.
    `is_pqc_available()` cannot catch that; `pqc_selfcheck()` must.
    """
    if not pqc.is_pqc_available():
        return

    monkeypatch.setattr(pqc.oqs, "get_enabled_sig_mechanisms", lambda: ["Falcon-512"])
    ok, detail = pqc.pqc_selfcheck()
    assert ok is False
    assert pqc._SIG_ALGO in detail and "not enabled" in detail


def test_selfcheck_survives_a_broken_liboqs_query(monkeypatch):
    if not pqc.is_pqc_available():
        return

    def _boom():
        raise OSError("liboqs exploded")

    monkeypatch.setattr(pqc.oqs, "get_enabled_sig_mechanisms", _boom)
    ok, detail = pqc.pqc_selfcheck()
    assert ok is False
    assert "OSError" in detail
