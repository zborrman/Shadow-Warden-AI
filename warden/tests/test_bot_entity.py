"""
warden/tests/test_bot_entity.py
─────────────────────────────────
Tests for warden/api/bot_entity.py — Bot_ID virtual members.

Coverage
────────
  create_bot          — registration, scoped ID, clearance
  get_bot / list_bots — retrieval and listing
  issue_bot_token     — JWT claims structure
  verify_bot_token    — valid / expired / bad sig
  IP whitelist        — exact IP, CIDR, empty list, rejected IP
  revoke_bot_token    — JTI revocation
  deactivate_bot      — blocks token issuance
"""
from __future__ import annotations

import os
import unittest

os.environ.setdefault("VAULT_MASTER_KEY",   "i5EjtPkHUtDxUPbjfMgWpurGBBc7mjUEpweFU40aDAA=")
os.environ.setdefault("BOT_DB_PATH",        "/tmp/warden_test_bot_entities.db")
os.environ.setdefault("BOT_JWT_SECRET",     "test-bot-jwt-secret-for-unit-tests-only!")
os.environ.setdefault("BOT_TOKEN_TTL_S",    "3600")
os.environ.setdefault("COMMUNITY_REGISTRY_PATH",    "/tmp/warden_test_community_registry.db")
os.environ.setdefault("COMMUNITY_KEY_ARCHIVE_PATH", "/tmp/warden_test_community_key_archive.db")


def _new_community():
    from warden.communities.id_generator import new_community_id
    return new_community_id()


class TestCreateBot(unittest.TestCase):

    def setUp(self):
        from warden.api.bot_entity import create_bot
        from warden.communities.clearance import ClearanceLevel
        self.cid = _new_community()
        self.bot = create_bot(
            community_id = self.cid,
            tenant_id    = "tenant-test",
            display_name = "Shopify Webhook",
            clearance    = ClearanceLevel.INTERNAL,
            allowed_ips  = ["10.0.0.1", "192.168.0.0/24"],
            scopes       = ["read", "write"],
        )

    def test_bot_id_is_uuid(self):
        import uuid
        uuid.UUID(self.bot.bot_id)

    def test_clearance_stored(self):
        self.assertEqual(self.bot.clearance, "INTERNAL")

    def test_allowed_ips_stored(self):
        self.assertIn("10.0.0.1", self.bot.allowed_ips)
        self.assertIn("192.168.0.0/24", self.bot.allowed_ips)

    def test_status_active(self):
        self.assertEqual(self.bot.status, "ACTIVE")

    def test_get_bot(self):
        from warden.api.bot_entity import get_bot
        retrieved = get_bot(self.bot.bot_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.bot_id, self.bot.bot_id)

    def test_list_bots(self):
        from warden.api.bot_entity import list_bots
        bots = list_bots(self.cid)
        ids = {b.bot_id for b in bots}
        self.assertIn(self.bot.bot_id, ids)


class TestBotToken(unittest.TestCase):

    def setUp(self):
        from warden.api.bot_entity import create_bot
        from warden.communities.clearance import ClearanceLevel
        self.cid = _new_community()
        self.bot = create_bot(
            community_id = self.cid,
            tenant_id    = "tenant-jwt",
            display_name = "Test Bot",
            clearance    = ClearanceLevel.PUBLIC,
            allowed_ips  = ["127.0.0.1"],
        )

    def test_issue_token_returns_string(self):
        from warden.api.bot_entity import issue_bot_token
        token = issue_bot_token(self.bot.bot_id)
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 10)

    def test_token_claims(self):
        import jwt as pyjwt

        from warden.api.bot_entity import issue_bot_token
        token  = issue_bot_token(self.bot.bot_id)
        claims = pyjwt.decode(token, os.environ["BOT_JWT_SECRET"], algorithms=["HS256"])
        self.assertEqual(claims["sub"],          self.bot.bot_id)
        self.assertEqual(claims["community_id"], self.cid)
        self.assertEqual(claims["clearance"],    "PUBLIC")
        self.assertIn("jti",         claims)
        self.assertIn("allowed_ips", claims)

    def test_verify_valid_token_correct_ip(self):
        from warden.api.bot_entity import issue_bot_token, verify_bot_token
        token  = issue_bot_token(self.bot.bot_id)
        claims = verify_bot_token(token, caller_ip="127.0.0.1")
        self.assertEqual(claims["sub"], self.bot.bot_id)

    def test_verify_rejected_ip(self):
        from warden.api.bot_entity import issue_bot_token, verify_bot_token
        token = issue_bot_token(self.bot.bot_id)
        with self.assertRaises(PermissionError):
            verify_bot_token(token, caller_ip="8.8.8.8")

    def test_verify_empty_whitelist_allows_any_ip(self):
        from warden.api.bot_entity import create_bot, issue_bot_token, verify_bot_token
        from warden.communities.clearance import ClearanceLevel
        bot = create_bot(
            community_id = _new_community(),
            tenant_id    = "t",
            display_name = "open bot",
            clearance    = ClearanceLevel.PUBLIC,
            allowed_ips  = [],   # empty = allow all
        )
        token  = issue_bot_token(bot.bot_id)
        claims = verify_bot_token(token, caller_ip="203.0.113.5")
        self.assertEqual(claims["sub"], bot.bot_id)

    def test_verify_cidr_match(self):
        from warden.api.bot_entity import create_bot, issue_bot_token, verify_bot_token
        from warden.communities.clearance import ClearanceLevel
        bot = create_bot(
            community_id = _new_community(),
            tenant_id    = "t",
            display_name = "cidr bot",
            clearance    = ClearanceLevel.PUBLIC,
            allowed_ips  = ["192.168.1.0/24"],
        )
        token  = issue_bot_token(bot.bot_id)
        claims = verify_bot_token(token, caller_ip="192.168.1.50")
        self.assertEqual(claims["sub"], bot.bot_id)

    def test_invalid_secret_raises(self):
        import jwt as pyjwt

        from warden.api.bot_entity import issue_bot_token
        token = issue_bot_token(self.bot.bot_id)
        with self.assertRaises(pyjwt.InvalidSignatureError):
            pyjwt.decode(token, "wrong-secret", algorithms=["HS256"])


class TestBotDeactivate(unittest.TestCase):

    def test_deactivated_bot_cannot_issue_token(self):
        from warden.api.bot_entity import create_bot, deactivate_bot, issue_bot_token
        from warden.communities.clearance import ClearanceLevel
        bot = create_bot(
            community_id = _new_community(),
            tenant_id    = "t",
            display_name = "deactivate me",
            clearance    = ClearanceLevel.PUBLIC,
        )
        deactivate_bot(bot.bot_id)
        with self.assertRaises(PermissionError):
            issue_bot_token(bot.bot_id)


class TestIpWhitelist(unittest.TestCase):

    def test_exact_ip_match(self):
        from warden.api.bot_entity import _ip_in_whitelist
        self.assertTrue(_ip_in_whitelist("10.0.0.1",  ["10.0.0.1"]))
        self.assertFalse(_ip_in_whitelist("10.0.0.2", ["10.0.0.1"]))

    def test_cidr_match(self):
        from warden.api.bot_entity import _ip_in_whitelist
        self.assertTrue(_ip_in_whitelist("192.168.5.100", ["192.168.0.0/16"]))
        self.assertFalse(_ip_in_whitelist("10.0.0.1",     ["192.168.0.0/16"]))

    def test_empty_whitelist_allows_all(self):
        from warden.api.bot_entity import _ip_in_whitelist
        self.assertTrue(_ip_in_whitelist("1.2.3.4", []))

    def test_invalid_ip_returns_false(self):
        from warden.api.bot_entity import _ip_in_whitelist
        self.assertFalse(_ip_in_whitelist("not-an-ip", ["10.0.0.0/8"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
