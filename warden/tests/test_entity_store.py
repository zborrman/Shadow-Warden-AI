"""
warden/tests/test_entity_store.py
───────────────────────────────────
Tests for warden/communities/entity_store.py — S3-backed encrypted entity persistence.

Coverage
────────
  store_entity()              — stores meta in DB; S3 fallback (inline) when no S3
  get_entity_meta()           — round-trip metadata retrieval
  get_entity_payload()        — payload fetch (S3 fallback path)
  get_entity_presigned_url()  — None when no S3 key
  delete_entity()             — soft-delete + storage release
  list_entities()             — pagination + clearance filter
  expire_entities()           — retention reaper deletes expired rows
  _s3_key()                   — format correctness
"""
from __future__ import annotations

import base64
import os
import tempfile
import unittest
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

# Isolate DB paths
os.environ.setdefault("ENTITY_DB_PATH", "/tmp/warden_test_entity_store.db")
os.environ.setdefault("QUOTA_DB_PATH",  "/tmp/warden_test_quota_es.db")


# ── Minimal stub for ClearanceEnvelope ───────────────────────────────────────

@dataclass
class _Envelope:
    entity_id:       str
    kid:             str
    clearance:       str
    cek_wrapped_b64: str
    nonce_b64:       str
    pay_nonce_b64:   str
    sig_b64:         str
    sender_mid:      str
    payload_b64:     str   # base64-encoded ciphertext bytes


def _make_envelope(clearance: str = "PUBLIC", size_bytes: int = 128) -> _Envelope:
    raw = os.urandom(size_bytes)
    return _Envelope(
        entity_id       = str(uuid.uuid4()),
        kid             = "kid-" + uuid.uuid4().hex[:8],
        clearance       = clearance,
        cek_wrapped_b64 = base64.b64encode(os.urandom(48)).decode(),
        nonce_b64       = base64.b64encode(os.urandom(12)).decode(),
        pay_nonce_b64   = base64.b64encode(os.urandom(12)).decode(),
        sig_b64         = base64.b64encode(os.urandom(64)).decode(),
        sender_mid      = "mid-" + uuid.uuid4().hex[:8],
        payload_b64     = base64.b64encode(raw).decode(),
    )


# ── Base class: fresh DB per test ─────────────────────────────────────────────

class _StoreBase(unittest.TestCase):

    def setUp(self):
        import contextlib

        import warden.communities.entity_store as es
        import warden.communities.quota as q
        with contextlib.suppress(Exception):
            pass  # suppress unused import warning
        self._entity_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)  # noqa: SIM115
        self._quota_db  = tempfile.NamedTemporaryFile(suffix=".db", delete=False)  # noqa: SIM115
        os.environ["ENTITY_DB_PATH"] = self._entity_db.name
        os.environ["QUOTA_DB_PATH"]  = self._quota_db.name
        es._ENTITY_DB_PATH = self._entity_db.name
        q._QUOTA_DB_PATH   = self._quota_db.name

    def tearDown(self):
        import contextlib
        for path in (self._entity_db.name, self._quota_db.name):
            with contextlib.suppress(OSError):
                os.unlink(path)


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestS3KeyFormat(unittest.TestCase):

    def test_key_format(self):
        from warden.communities.entity_store import _s3_key
        key = _s3_key("comm-abc", "ent-xyz")
        self.assertEqual(key, "communities/comm-abc/ent-xyz.enc")

    def test_no_pii_in_key(self):
        from warden.communities.entity_store import _s3_key
        key = _s3_key("cid", "eid")
        self.assertNotIn("user", key)
        self.assertNotIn("email", key)
        self.assertNotIn("content-type", key)


class TestStoreAndGetMeta(_StoreBase):

    def _store(self, cid: str = "cid-test", tier: str = "business") -> object:
        from warden.communities.entity_store import store_entity
        env = _make_envelope()
        return store_entity(env, cid, tier, content_type="application/octet-stream")

    def test_store_returns_entity_meta(self):
        from warden.communities.entity_store import EntityMeta
        meta = self._store()
        self.assertIsInstance(meta, EntityMeta)
        self.assertEqual(meta.status, "ACTIVE")
        self.assertIsNotNone(meta.entity_id)

    def test_get_meta_roundtrip(self):
        from warden.communities.entity_store import get_entity_meta, store_entity
        cid = "cid-roundtrip"
        env = _make_envelope(clearance="RESTRICTED")
        meta = store_entity(env, cid, "business")
        fetched = get_entity_meta(meta.entity_id, cid)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.entity_id, meta.entity_id)
        self.assertEqual(fetched.clearance, "RESTRICTED")
        self.assertEqual(fetched.kid, env.kid)

    def test_get_meta_wrong_community_returns_none(self):
        from warden.communities.entity_store import get_entity_meta, store_entity
        meta = store_entity(_make_envelope(), "cid-A", "business")
        result = get_entity_meta(meta.entity_id, "cid-B")
        self.assertIsNone(result)

    def test_byte_size_recorded_correctly(self):
        from warden.communities.entity_store import store_entity
        env = _make_envelope(size_bytes=512)
        meta = store_entity(env, "cid-size", "business")
        self.assertEqual(meta.byte_size, 512)

    def test_expires_at_set_for_individual(self):
        from warden.communities.entity_store import store_entity
        meta = store_entity(_make_envelope(), "cid-exp", "individual")
        self.assertIsNotNone(meta.expires_at)

    def test_expires_at_none_for_mcp(self):
        """MCP tier has retention_days=-1 (unlimited) — no expiry."""
        from warden.communities.entity_store import store_entity
        meta = store_entity(_make_envelope(), "cid-mcp", "mcp")
        self.assertIsNone(meta.expires_at)

    def test_quota_recorded_after_store(self):
        from warden.communities.entity_store import store_entity
        from warden.communities.quota import get_storage_used
        cid = "cid-quota-check"
        env = _make_envelope(size_bytes=256)
        store_entity(env, cid, "business")
        self.assertEqual(get_storage_used(cid), 256)


class TestGetPayload(_StoreBase):
    """
    S3 is unavailable in unit tests — store_entity falls back to s3_key=None.
    get_entity_payload returns None when s3_key is None (inline not implemented).
    """

    def test_payload_returns_none_without_s3(self):
        from warden.communities.entity_store import get_entity_payload, store_entity
        meta = store_entity(_make_envelope(), "cid-pay", "business")
        # S3 unavailable in tests → s3_key is None → payload is None
        payload = get_entity_payload(meta.entity_id, "cid-pay")
        self.assertIsNone(payload)

    def test_payload_returns_none_for_missing_entity(self):
        from warden.communities.entity_store import get_entity_payload
        result = get_entity_payload("no-such-id", "cid-x")
        self.assertIsNone(result)


class TestPresignedUrl(_StoreBase):

    def test_presign_none_when_no_s3_key(self):
        from warden.communities.entity_store import (
            get_entity_presigned_url,
            store_entity,
        )
        meta = store_entity(_make_envelope(), "cid-presign", "business")
        url = get_entity_presigned_url(meta.entity_id, "cid-presign")
        # S3 unavailable in tests — s3_key stored as None
        self.assertIsNone(url)

    def test_presign_none_for_missing_entity(self):
        from warden.communities.entity_store import get_entity_presigned_url
        url = get_entity_presigned_url("ghost-id", "cid-ghost")
        self.assertIsNone(url)


class TestDeleteEntity(_StoreBase):

    def test_delete_marks_entity_deleted(self):
        from warden.communities.entity_store import (
            delete_entity,
            get_entity_meta,
            store_entity,
        )
        cid = "cid-del"
        meta = store_entity(_make_envelope(), cid, "business")
        result = delete_entity(meta.entity_id, cid)
        self.assertTrue(result)
        # get_entity_meta filters status='ACTIVE' — should return None
        self.assertIsNone(get_entity_meta(meta.entity_id, cid))

    def test_delete_releases_storage_quota(self):
        from warden.communities.entity_store import delete_entity, store_entity
        from warden.communities.quota import get_storage_used
        cid = "cid-del-quota"
        env = _make_envelope(size_bytes=1024)
        meta = store_entity(env, cid, "business")
        self.assertEqual(get_storage_used(cid), 1024)
        delete_entity(meta.entity_id, cid)
        self.assertEqual(get_storage_used(cid), 0)

    def test_delete_nonexistent_returns_false(self):
        from warden.communities.entity_store import delete_entity
        result = delete_entity("no-entity", "no-community")
        self.assertFalse(result)

    def test_double_delete_returns_false(self):
        from warden.communities.entity_store import delete_entity, store_entity
        cid = "cid-double-del"
        meta = store_entity(_make_envelope(), cid, "business")
        self.assertTrue(delete_entity(meta.entity_id, cid))
        self.assertFalse(delete_entity(meta.entity_id, cid))


class TestListEntities(_StoreBase):

    def _store_n(self, cid: str, n: int, clearance: str = "PUBLIC") -> list:
        from warden.communities.entity_store import store_entity
        return [store_entity(_make_envelope(clearance), cid, "business") for _ in range(n)]

    def test_list_returns_active_entities(self):
        from warden.communities.entity_store import list_entities
        cid = "cid-list"
        self._store_n(cid, 3)
        results = list_entities(cid)
        self.assertEqual(len(results), 3)

    def test_list_pagination(self):
        from warden.communities.entity_store import list_entities
        cid = "cid-paginate"
        self._store_n(cid, 5)
        page1 = list_entities(cid, limit=3, offset=0)
        page2 = list_entities(cid, limit=3, offset=3)
        self.assertEqual(len(page1), 3)
        self.assertEqual(len(page2), 2)
        ids1 = {m.entity_id for m in page1}
        ids2 = {m.entity_id for m in page2}
        self.assertEqual(len(ids1 & ids2), 0)   # no overlap

    def test_clearance_filter(self):
        from warden.communities.entity_store import list_entities, store_entity
        cid = "cid-clearance-filter"
        store_entity(_make_envelope("PUBLIC"),     cid, "business")
        store_entity(_make_envelope("PUBLIC"),     cid, "business")
        store_entity(_make_envelope("RESTRICTED"), cid, "business")
        pub = list_entities(cid, clearance_filter="PUBLIC")
        res = list_entities(cid, clearance_filter="RESTRICTED")
        self.assertEqual(len(pub), 2)
        self.assertEqual(len(res), 1)

    def test_deleted_entities_excluded_from_list(self):
        from warden.communities.entity_store import delete_entity, list_entities, store_entity
        cid = "cid-del-list"
        m1 = store_entity(_make_envelope(), cid, "business")
        m2 = store_entity(_make_envelope(), cid, "business")
        delete_entity(m1.entity_id, cid)
        results = list_entities(cid)
        ids = [r.entity_id for r in results]
        self.assertNotIn(m1.entity_id, ids)
        self.assertIn(m2.entity_id, ids)


class TestExpireEntities(_StoreBase):

    def test_expired_entities_are_deleted(self):
        from warden.communities.entity_store import (
            _get_conn,
            expire_entities,
            list_entities,
            store_entity,
        )
        cid = "cid-expire"
        meta = store_entity(_make_envelope(), cid, "individual")

        # Backdate expires_at to the past directly in DB
        past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
        with _get_conn() as conn:
            conn.execute(
                "UPDATE community_entities SET expires_at=? WHERE entity_id=?",
                (past, meta.entity_id),
            )
            conn.commit()

        count = expire_entities(cid)
        self.assertEqual(count, 1)
        self.assertEqual(len(list_entities(cid)), 0)

    def test_non_expired_entities_not_deleted(self):
        from warden.communities.entity_store import expire_entities, list_entities, store_entity
        cid = "cid-no-expire"
        store_entity(_make_envelope(), cid, "individual")   # future expires_at
        count = expire_entities(cid)
        self.assertEqual(count, 0)
        self.assertEqual(len(list_entities(cid)), 1)

    def test_mcp_entities_never_expire(self):
        """MCP retention_days=-1 → expires_at=None → reaper never touches them."""
        from warden.communities.entity_store import expire_entities, list_entities, store_entity
        cid = "cid-mcp-no-expire"
        store_entity(_make_envelope(), cid, "mcp")
        count = expire_entities(cid)
        self.assertEqual(count, 0)
        self.assertEqual(len(list_entities(cid)), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
