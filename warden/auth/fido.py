"""
warden/auth/fido.py
FIDO2 / WebAuthn Passkey authentication for AP2 mandate signing.
Uses py_webauthn library; falls back gracefully if not installed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import sqlite3
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from warden.config import settings
from warden.db.connect import open_db
from warden.db.ddl_registry import register

log = logging.getLogger("warden.auth.fido")

_DB_PATH  = settings.fido_db_path
_RP_ID    = settings.fido_rp_id
_RP_NAME  = settings.fido_rp_name
_ORIGIN   = settings.fido_origin
_db_lock  = threading.RLock()

_FIDO_DDL = """
    CREATE TABLE IF NOT EXISTS fido_credentials (
        id              TEXT PRIMARY KEY,
        tenant_id       TEXT NOT NULL,
        credential_id   TEXT NOT NULL UNIQUE,
        public_key      TEXT NOT NULL,
        sign_count      INTEGER DEFAULT 0,
        created_at      TEXT NOT NULL,
        last_used       TEXT
    );
    CREATE TABLE IF NOT EXISTS fido_challenges (
        challenge   TEXT PRIMARY KEY,
        tenant_id   TEXT NOT NULL,
        purpose     TEXT NOT NULL,
        created_at  TEXT NOT NULL
    );
"""

register("fido", "fido", _FIDO_DDL)


def _stub_allowed() -> bool:
    """
    Whether the scaffolding path may report a credential as verified.

    This is an authentication primitive, so it fails CLOSED: without py_webauthn
    the verifiers now refuse rather than accept. The stub is opt-in for local
    scaffolding only and is never honoured in production, whatever the env says.

    Read per call — an import-time snapshot would capture the value before the
    process environment is populated.
    """
    if settings.is_prod:
        return False
    return os.getenv("FIDO_ALLOW_STUB", "").strip().lower() == "true"


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    with open_db("fido", _DB_PATH, module_default_path=_DB_PATH) as con:
        yield con


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _random_challenge() -> str:
    return _b64url(os.urandom(32))


# An assertion must answer a challenge issued for it within this window.
CHALLENGE_TTL_S = 300


def _client_challenge(assertion: dict[str, Any]) -> str:
    """The challenge the authenticator signed, read from its own clientDataJSON."""
    try:
        raw = assertion["response"]["clientDataJSON"]
        return str(json.loads(_b64url_decode(raw))["challenge"])
    except Exception:
        return ""


def _take_challenge(con: sqlite3.Connection, challenge: str, tenant_id: str, purpose: str) -> bool:
    """
    Consume one live challenge, or report that there is none. A single DELETE,
    so four workers cannot accept the same assertion twice: a passkey whose
    sign counter stays at 0 (most synced passkeys) is otherwise replayable.
    """
    if not challenge:
        return False
    oldest = datetime.fromtimestamp(datetime.now(UTC).timestamp() - CHALLENGE_TTL_S, UTC).isoformat()
    cur = con.execute(
        "DELETE FROM fido_challenges WHERE challenge=? AND tenant_id=? AND purpose=? AND created_at>=?",
        (challenge, tenant_id, purpose, oldest),
    )
    return cur.rowcount == 1


class FIDOProvider:
    """
    Server-side WebAuthn / FIDO2 handler.

    When py_webauthn is available: full FIDO2 registration/authentication.
    Without it: returns challenge/response stubs for UI scaffolding.
    """

    def generate_registration_options(self, tenant_id: str, display_name: str) -> dict[str, Any]:
        challenge = _random_challenge()
        user_id   = _b64url(hashlib.sha256(tenant_id.encode()).digest()[:16])

        with _db_lock, _conn() as con:
            con.execute(
                "INSERT OR REPLACE INTO fido_challenges(challenge, tenant_id, purpose, created_at) "
                "VALUES(?,?,?,?)",
                (challenge, tenant_id, "registration", datetime.now(UTC).isoformat()),
            )

        try:
            from webauthn import generate_registration_options as _gen
            from webauthn.helpers.structs import (
                AuthenticatorSelectionCriteria,
                ResidentKeyRequirement,
                UserVerificationRequirement,
            )
            opts = _gen(
                rp_id=_RP_ID,
                rp_name=_RP_NAME,
                user_id=user_id.encode(),
                user_name=tenant_id,
                user_display_name=display_name,
                challenge=challenge.encode(),
                authenticator_selection=AuthenticatorSelectionCriteria(
                    resident_key=ResidentKeyRequirement.REQUIRED,
                    user_verification=UserVerificationRequirement.REQUIRED,
                ),
            )
            if hasattr(opts, "model_dump_json"):
                return json.loads(opts.model_dump_json())
            if hasattr(opts, "json"):
                return json.loads(opts.json())
            # py_webauthn 2.x removed .json(); use options_to_json()
            from webauthn import options_to_json as _otj  # noqa: PLC0415
            return json.loads(_otj(opts))
        except ImportError:
            return {
                "challenge": challenge,
                "rp": {"id": _RP_ID, "name": _RP_NAME},
                "user": {"id": user_id, "name": tenant_id, "displayName": display_name},
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                "timeout": 60000,
                "attestation": "none",
                "_stub": True,
            }

    def verify_registration(
        self,
        tenant_id: str,
        credential: dict[str, Any],
    ) -> dict[str, Any]:
        with _db_lock, _conn() as con:
            row = con.execute(
                "SELECT challenge FROM fido_challenges WHERE tenant_id=? AND purpose='registration' "
                "ORDER BY created_at DESC LIMIT 1",
                (tenant_id,),
            ).fetchone()
        if not row:
            return {"verified": False, "reason": "no_challenge"}

        try:
            from webauthn import verify_registration_response as _verify
            from webauthn.helpers import parse_registration_credential_json
            try:
                # py_webauthn 3.x structs are dataclasses: there is no
                # model_validate_json, and calling it sent every real
                # registration down the refusal path below.
                parsed = parse_registration_credential_json(json.dumps(credential))
            except Exception:
                # Credential cannot be parsed as a real WebAuthn response — use stub path
                raise ImportError from None  # falls to stub handler below
            result = _verify(
                credential=parsed,
                expected_challenge=row["challenge"].encode(),
                expected_rp_id=_RP_ID,
                expected_origin=_ORIGIN,
            )
            # The id an assertion names its credential by is base64url; str() of
            # the bytes stored "b'...'", so no registered key could ever sign in.
            cred_id = _b64url(result.credential_id)
            pub_key = base64.b64encode(result.credential_public_key).decode()
            self._store_credential(tenant_id, cred_id, pub_key, result.sign_count)
            return {"verified": True, "credential_id": cred_id}
        except ImportError:
            # Reached when py_webauthn is missing OR the credential does not parse
            # as a real WebAuthn response. Accepting here enrolled an unverified
            # credential against an arbitrary tenant, so it now fails closed.
            if not _stub_allowed():
                log.warning("fido: registration refused — webauthn verification unavailable")
                return {"verified": False, "reason": "webauthn_unavailable"}
            cred_id = credential.get("id", str(uuid.uuid4()))
            self._store_credential(tenant_id, cred_id, "stub-key", 0)
            return {"verified": True, "credential_id": cred_id, "_stub": True}
        except Exception as exc:
            return {"verified": False, "reason": str(exc)}

    def generate_authentication_options(self, tenant_id: str) -> dict[str, Any]:
        challenge = _random_challenge()
        with _db_lock, _conn() as con:
            con.execute(
                "INSERT OR REPLACE INTO fido_challenges(challenge, tenant_id, purpose, created_at) "
                "VALUES(?,?,?,?)",
                (challenge, tenant_id, "authentication", datetime.now(UTC).isoformat()),
            )
            creds = con.execute(
                "SELECT credential_id FROM fido_credentials WHERE tenant_id=?",
                (tenant_id,),
            ).fetchall()

        allow_creds = [{"type": "public-key", "id": r["credential_id"]} for r in creds]
        return {
            "challenge": challenge,
            "timeout": 60000,
            "rpId": _RP_ID,
            "allowCredentials": allow_creds,
            "userVerification": "required",
        }

    def verify_authentication(
        self,
        tenant_id: str,
        assertion: dict[str, Any],
    ) -> dict[str, Any]:
        return self.verify_bound(tenant_id, "authentication", assertion)

    def issue_bound_challenge(self, tenant_id: str, purpose: str) -> dict[str, Any]:
        """Authentication options whose challenge is valid only for ``purpose``."""
        challenge = _random_challenge()
        with _db_lock, _conn() as con:
            con.execute(
                "INSERT INTO fido_challenges(challenge, tenant_id, purpose, created_at)"
                " VALUES(?,?,?,?)",
                (challenge, tenant_id, purpose, datetime.now(UTC).isoformat()),
            )
            creds = con.execute(
                "SELECT credential_id FROM fido_credentials WHERE tenant_id=?", (tenant_id,),
            ).fetchall()
        return {
            "challenge": challenge,
            "timeout": CHALLENGE_TTL_S * 1000,
            "rpId": _RP_ID,
            "allowCredentials": [{"type": "public-key", "id": r["credential_id"]} for r in creds],
            "userVerification": "required",
        }

    def verify_bound(self, tenant_id: str, purpose: str, assertion: dict[str, Any]) -> dict[str, Any]:
        """
        Verify a WebAuthn assertion that answers a challenge issued to this
        tenant for this purpose. The challenge is consumed before the signature
        is checked, so a failed attempt cannot be retried with the same one.
        Fails CLOSED: no py_webauthn, no stub opt-in, no verification.
        """
        if not isinstance(assertion, dict):
            return {"verified": False, "reason": "malformed_assertion"}
        challenge = _client_challenge(assertion)
        with _db_lock, _conn() as con:
            if not _take_challenge(con, challenge, tenant_id, purpose):
                return {"verified": False, "reason": "no_challenge"}
            cred_row = con.execute(
                "SELECT * FROM fido_credentials WHERE tenant_id=? AND credential_id=?",
                (tenant_id, assertion.get("id", "")),
            ).fetchone()
        if not cred_row:
            # An assertion naming a credential this tenant never registered is
            # never a successful authentication.
            return {"verified": False, "reason": "unknown_credential"}

        try:
            from webauthn import verify_authentication_response as _verify
            from webauthn.helpers import parse_authentication_credential_json
        except ImportError:
            if not _stub_allowed():
                log.warning("fido: authentication refused — webauthn verification unavailable")
                return {"verified": False, "reason": "webauthn_unavailable"}
            return {"verified": True, "tenant_id": tenant_id, "_stub": True}
        try:
            result = _verify(
                credential=parse_authentication_credential_json(json.dumps(assertion)),
                # The options carry the challenge base64url-encoded; the client
                # signs its decoded bytes, and py_webauthn compares bytes.
                expected_challenge=_b64url_decode(challenge),
                expected_rp_id=_RP_ID,
                expected_origin=_ORIGIN,
                credential_public_key=base64.b64decode(cred_row["public_key"]),
                credential_current_sign_count=cred_row["sign_count"],
                require_user_verification=True,
            )
        except Exception as exc:
            return {"verified": False, "reason": type(exc).__name__}
        with _db_lock, _conn() as con:
            con.execute(
                "UPDATE fido_credentials SET sign_count=?, last_used=? WHERE id=?",
                (result.new_sign_count, datetime.now(UTC).isoformat(), cred_row["id"]),
            )
        return {"verified": True, "tenant_id": tenant_id}

    def _store_credential(self, tenant_id: str, cred_id: str, pub_key: str, sign_count: int) -> None:
        with _db_lock, _conn() as con:
            con.execute(
                "INSERT OR REPLACE INTO fido_credentials"
                "(id, tenant_id, credential_id, public_key, sign_count, created_at) "
                "VALUES(?,?,?,?,?,?)",
                (str(uuid.uuid4()), tenant_id, cred_id, pub_key,
                 sign_count, datetime.now(UTC).isoformat()),
            )

    def list_credentials(self, tenant_id: str) -> list[dict]:
        with _db_lock, _conn() as con:
            rows = con.execute(
                "SELECT id, credential_id, sign_count, created_at, last_used "
                "FROM fido_credentials WHERE tenant_id=? ORDER BY created_at DESC",
                (tenant_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_credential(self, tenant_id: str, cred_id: str) -> bool:
        with _db_lock, _conn() as con:
            cur = con.execute(
                "DELETE FROM fido_credentials WHERE tenant_id=? AND credential_id=?",
                (tenant_id, cred_id),
            )
        return cur.rowcount > 0
