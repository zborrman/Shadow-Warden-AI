"""
warden/security/certificate_authority.py
──────────────────────────────────────────
ANS Certificate Authority — issues X.509 certificates to marketplace agents.

Subject CN = agent-{agent_id}.{community_id}.shadow-warden.ai
Certificates are signed with the community's private key (Ed25519).
CRL (Certificate Revocation List) stored in Redis.
Certificates stored in SQLite by default; optionally written to MinIO.

Falls back to a self-signed ephemeral CA key when no community keypair is
available (development mode).
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
from datetime import UTC, datetime, timedelta

from warden.config import data_path
from warden.db.connect import open_persistent_db
from warden.db.ddl_registry import register

log = logging.getLogger("warden.security.certificate_authority")

_DB_PATH   = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
_CERT_TTL_DAYS = int(os.getenv("ANS_CERT_TTL_DAYS", "365"))
_db_lock   = threading.RLock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ans_certificates (
    cert_id       TEXT PRIMARY KEY,
    agent_id      TEXT NOT NULL,
    community_id  TEXT NOT NULL DEFAULT '',
    subject_cn    TEXT NOT NULL,
    cert_pem      TEXT NOT NULL,
    issued_at     TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    revoked       INTEGER NOT NULL DEFAULT 0,
    revoked_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_ans_agent ON ans_certificates(agent_id);
"""
register("marketplace", "warden.security.certificate_authority", _SCHEMA)


def _get_stable_ca_key():
    """
    Return a stable Ed25519 CA signing key.

    Uses HSMSigner's software-key singleton so the CA key is consistent across
    certificate issuances within a process (or HSM-backed when available).
    Falls back to a fresh ephemeral key only if HSMSigner cannot be imported.
    """
    try:
        from warden.crypto.hsm import get_signer
        return get_signer()._get_sw_key()
    except Exception:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        return Ed25519PrivateKey.generate()


def _conn(db_path: str = _DB_PATH) -> sqlite3.Connection:
    # No Turso routing here (unlike open_db) — this class holds a connection
    # across a get/close pair rather than a single call, same tradeoff as
    # open_persistent_db's other self._conn-holding callers.
    return open_persistent_db("marketplace", db_path)


def _redis():
    try:
        import redis as _r  # noqa: PLC0415
        if _REDIS_URL.startswith("memory://"):
            return None
        return _r.from_url(_REDIS_URL, decode_responses=True)
    except Exception:
        return None


def _crl_key(community_id: str) -> str:
    return f"ans:crl:{community_id}"


class CertificateAuthority:
    """
    Issues and revokes X.509 agent certificates.

    When the `cryptography` library is available, real DER-encoded X.509 certs
    are generated.  When unavailable, a JSON-based synthetic certificate is
    produced (suitable for test environments).
    """

    def __init__(self, db_path: str = _DB_PATH) -> None:
        self.db_path = db_path
        self._mem_conn: sqlite3.Connection | None = None
        if db_path == ":memory:":
            self._mem_conn = _conn(db_path)
        else:
            with _conn(db_path):
                pass

    def _get_conn(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        return _conn(self.db_path)

    def _close_conn(self, con: sqlite3.Connection) -> None:
        if self._mem_conn is None:
            con.close()

    # ── Issue ─────────────────────────────────────────────────────────────────

    def issue_agent_certificate(
        self,
        agent_id:    str,
        community_id: str,
        public_key_pem: str = "",
    ) -> dict:
        """
        Issue an X.509 certificate for *agent_id* in *community_id*.

        Returns dict with: cert_id, subject_cn, cert_pem, issued_at, expires_at.
        Falls back to a synthetic JSON cert when cryptography is unavailable.
        """
        subject_cn = f"agent-{agent_id}.{community_id}.shadow-warden.ai"
        cert_id    = f"CERT-{uuid.uuid4().hex[:12].upper()}"
        now        = datetime.now(UTC)
        expires    = now + timedelta(days=_CERT_TTL_DAYS)

        cert_pem = self._generate_cert(
            cert_id, subject_cn, public_key_pem, now, expires,
        )

        row = {
            "cert_id":      cert_id,
            "agent_id":     agent_id,
            "community_id": community_id,
            "subject_cn":   subject_cn,
            "cert_pem":     cert_pem,
            "issued_at":    now.isoformat(),
            "expires_at":   expires.isoformat(),
            "revoked":      0,
            "revoked_at":   None,
        }
        with _db_lock:
            con = self._get_conn()
            con.execute(
                """INSERT OR REPLACE INTO ans_certificates
                   (cert_id, agent_id, community_id, subject_cn, cert_pem,
                    issued_at, expires_at, revoked, revoked_at)
                   VALUES (:cert_id,:agent_id,:community_id,:subject_cn,:cert_pem,
                           :issued_at,:expires_at,:revoked,:revoked_at)""",
                row,
            )
            con.commit()
            self._close_conn(con)

        log.info("ANS: cert issued cert_id=%s agent=%s cn=%s", cert_id, agent_id, subject_cn)
        return {k: v for k, v in row.items() if k != "revoked"}

    def _generate_cert(
        self,
        cert_id:    str,
        subject_cn: str,
        public_key_pem: str,
        issued_at:  datetime,
        expires_at: datetime,
    ) -> str:
        try:
            from cryptography import x509  # noqa: PLC0415
            from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
            from cryptography.x509.oid import NameOID  # noqa: PLC0415

            ca_key = _get_stable_ca_key()

            # Use provided public key or generate ephemeral subject key
            if public_key_pem:
                subject_pub = serialization.load_pem_public_key(public_key_pem.encode())
            else:
                subject_key = Ed25519PrivateKey.generate()
                subject_pub = subject_key.public_key()

            builder = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
                .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Shadow Warden Community CA")]))
                .public_key(subject_pub)  # type: ignore[arg-type]
                .serial_number(int.from_bytes(hashlib.sha256(cert_id.encode()).digest()[:16], "big") | 1)
                .not_valid_before(issued_at.replace(tzinfo=None))
                .not_valid_after(expires_at.replace(tzinfo=None))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(subject_cn)]), critical=False)
            )
            cert = builder.sign(ca_key, None)
            return cert.public_bytes(serialization.Encoding.PEM).decode()
        except ImportError:
            # cryptography not installed — return a signed JSON envelope
            payload = {
                "cert_id":    cert_id,
                "subject_cn": subject_cn,
                "issued_at":  issued_at.isoformat(),
                "expires_at": expires_at.isoformat(),
                "issuer":     "Shadow Warden Community CA (synthetic)",
            }
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
            return base64.b64encode(json.dumps({**payload, "sig": digest}).encode()).decode()

    # ── Revoke ────────────────────────────────────────────────────────────────

    def revoke_certificate(self, agent_id: str) -> bool:
        """Add agent certificate to CRL and mark revoked in DB. Returns True if found."""
        try:
            now  = datetime.now(UTC).isoformat()
            with _db_lock:
                con = self._get_conn()
                row = con.execute(
                    "SELECT cert_id, community_id FROM ans_certificates WHERE agent_id=? AND revoked=0",
                    (agent_id,),
                ).fetchone()
                if not row:
                    self._close_conn(con)
                    return False
                cert_id      = row["cert_id"]
                community_id = row["community_id"]
                con.execute(
                    "UPDATE ans_certificates SET revoked=1, revoked_at=? WHERE cert_id=?",
                    (now, cert_id),
                )
                con.commit()
                self._close_conn(con)

            # Redis CRL set
            r = _redis()
            if r:
                r.sadd(_crl_key(community_id), cert_id)
                r.expire(_crl_key(community_id), 86_400 * 365 * 7)

            log.info("ANS: cert revoked cert_id=%s agent=%s", cert_id, agent_id)
            return True
        except Exception as exc:
            log.warning("ANS revoke_certificate error: %s", exc)
            return False

    # ── Verify ────────────────────────────────────────────────────────────────

    def verify_certificate(self, cert_pem: str) -> dict:
        """
        Validate a certificate PEM/base64 envelope.
        Checks: found in DB, not revoked, not expired.
        """
        # Attempt to decode synthetic JSON cert
        try:
            decoded   = json.loads(base64.b64decode(cert_pem.encode()).decode())
            cert_id   = decoded.get("cert_id", "")
        except Exception:
            # Real X.509 — extract serial from PEM
            cert_id = self._extract_cert_id_from_pem(cert_pem)

        if not cert_id:
            return {"valid": False, "reason": "unrecognized_format"}

        try:
            with _db_lock:
                con = self._get_conn()
                row = con.execute(
                    "SELECT * FROM ans_certificates WHERE cert_id=?", (cert_id,)
                ).fetchone()
                self._close_conn(con)
            if not row:
                return {"valid": False, "reason": "not_found"}
            if row["revoked"]:
                return {"valid": False, "reason": "revoked", "revoked_at": row["revoked_at"]}
            now = datetime.now(UTC)
            exp = datetime.fromisoformat(row["expires_at"])
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=UTC)
            if now > exp:
                return {"valid": False, "reason": "expired", "expires_at": row["expires_at"]}
            return {"valid": True, "cert_id": cert_id, "subject_cn": row["subject_cn"],
                    "agent_id": row["agent_id"], "expires_at": row["expires_at"]}
        except Exception as exc:
            return {"valid": False, "reason": str(exc)}

    def _extract_cert_id_from_pem(self, cert_pem: str) -> str:
        """Try to extract cert_id by looking up cert_pem in DB. Fail-open → empty."""
        try:
            with _db_lock:
                con = self._get_conn()
                row = con.execute(
                    "SELECT cert_id FROM ans_certificates WHERE cert_pem=?", (cert_pem,)
                ).fetchone()
                self._close_conn(con)
            return row["cert_id"] if row else ""
        except Exception:
            return ""

    # ── Get ───────────────────────────────────────────────────────────────────

    def issue_tunnel_certificate(
        self,
        tunnel_id:    str,
        community_id: str,
        public_key_pem: str = "",
    ) -> dict:
        """
        Issue an X.509 certificate for a MASQUE tunnel (CR-15).

        Subject CN = tunnel-{tunnel_id}.{community_id}.shadow-warden.ai.
        Stored with agent_id = "tunnel:{tunnel_id}" for revocation lookup.
        Returns the same dict shape as issue_agent_certificate().
        """
        agent_id = f"tunnel:{tunnel_id}"
        subject_cn = f"tunnel-{tunnel_id}.{community_id}.shadow-warden.ai"
        cert_id    = f"TCERT-{uuid.uuid4().hex[:12].upper()}"
        now        = datetime.now(UTC)
        expires    = now + timedelta(days=_CERT_TTL_DAYS)

        cert_pem = self._generate_cert(cert_id, subject_cn, public_key_pem, now, expires)

        row = {
            "cert_id":      cert_id,
            "agent_id":     agent_id,
            "community_id": community_id,
            "subject_cn":   subject_cn,
            "cert_pem":     cert_pem,
            "issued_at":    now.isoformat(),
            "expires_at":   expires.isoformat(),
            "revoked":      0,
            "revoked_at":   None,
        }
        with _db_lock:
            con = self._get_conn()
            con.execute(
                """INSERT OR REPLACE INTO ans_certificates
                   (cert_id, agent_id, community_id, subject_cn, cert_pem,
                    issued_at, expires_at, revoked, revoked_at)
                   VALUES (:cert_id,:agent_id,:community_id,:subject_cn,:cert_pem,
                           :issued_at,:expires_at,:revoked,:revoked_at)""",
                row,
            )
            con.commit()
            self._close_conn(con)

        log.info("CR-15: tunnel cert issued cert_id=%s tunnel=%s", cert_id, tunnel_id)
        return {k: v for k, v in row.items() if k != "revoked"}

    def revoke_certificate_by_id(self, cert_id: str) -> bool:
        """Revoke a specific certificate by cert_id (used for CR-15 rollback). Returns True if found."""
        try:
            now = datetime.now(UTC).isoformat()
            with _db_lock:
                con = self._get_conn()
                row = con.execute(
                    "SELECT cert_id, community_id FROM ans_certificates WHERE cert_id=? AND revoked=0",
                    (cert_id,),
                ).fetchone()
                if not row:
                    self._close_conn(con)
                    return False
                community_id = row["community_id"]
                con.execute(
                    "UPDATE ans_certificates SET revoked=1, revoked_at=? WHERE cert_id=?",
                    (now, cert_id),
                )
                con.commit()
                self._close_conn(con)

            r = _redis()
            if r:
                r.sadd(_crl_key(community_id), cert_id)
                r.expire(_crl_key(community_id), 86_400 * 365 * 7)

            log.info("CR-15: cert revoked by id cert_id=%s", cert_id)
            return True
        except Exception as exc:
            log.warning("revoke_certificate_by_id error: %s", exc)
            return False

    def get_agent_certificate(self, agent_id: str) -> dict | None:
        try:
            with _db_lock:
                con = self._get_conn()
                row = con.execute(
                    "SELECT * FROM ans_certificates WHERE agent_id=? ORDER BY issued_at DESC LIMIT 1",
                    (agent_id,),
                ).fetchone()
                self._close_conn(con)
            return dict(row) if row else None
        except Exception:
            return None


# ── Singleton ─────────────────────────────────────────────────────────────────

_ca: CertificateAuthority | None = None


def get_ca(db_path: str = _DB_PATH) -> CertificateAuthority:
    global _ca
    if _ca is None:
        _ca = CertificateAuthority(db_path)
    return _ca
