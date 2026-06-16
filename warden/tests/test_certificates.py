"""Tests for ANS Certificate Authority (MKT-13)."""
from __future__ import annotations

from warden.security.certificate_authority import CertificateAuthority, get_ca


class TestCertificateAuthority:

    def setup_method(self):
        self.ca = CertificateAuthority(db_path=":memory:")

    def test_issue_certificate_returns_dict(self):
        result = self.ca.issue_agent_certificate(
            agent_id="agent-cert-1",
            community_id="com-xyz",
        )
        assert "cert_id" in result
        assert "cert_pem" in result
        assert "agent_id" in result
        assert result["agent_id"] == "agent-cert-1"

    def test_subject_cn_format(self):
        result = self.ca.issue_agent_certificate(
            agent_id="agent-cn-test",
            community_id="com-abc",
        )
        assert "agent-cn-test.com-abc.shadow-warden.ai" in result["subject_cn"]

    def test_get_agent_certificate(self):
        self.ca.issue_agent_certificate(agent_id="agent-get-1", community_id="com-g")
        cert = self.ca.get_agent_certificate("agent-get-1")
        assert cert is not None
        assert cert["agent_id"] == "agent-get-1"

    def test_get_missing_agent_returns_none(self):
        result = self.ca.get_agent_certificate("agent-nonexistent-xyz")
        assert result is None

    def test_revoke_existing_certificate(self):
        self.ca.issue_agent_certificate(agent_id="agent-rev-1", community_id="com-r")
        revoked = self.ca.revoke_certificate("agent-rev-1")
        assert revoked is True

    def test_revoke_nonexistent_returns_false(self):
        revoked = self.ca.revoke_certificate("agent-no-cert-xyz")
        assert revoked is False

    def test_verify_certificate_valid(self):
        issued = self.ca.issue_agent_certificate(agent_id="agent-verify-1", community_id="com-v")
        result = self.ca.verify_certificate(issued["cert_pem"])
        assert result["valid"] is True

    def test_verify_revoked_returns_invalid(self):
        issued = self.ca.issue_agent_certificate(agent_id="agent-rev-verify", community_id="com-rv")
        self.ca.revoke_certificate("agent-rev-verify")
        result = self.ca.verify_certificate(issued["cert_pem"])
        assert result["valid"] is False

    def test_singleton_get_ca(self):
        a = get_ca()
        b = get_ca()
        assert a is b

    def test_cert_pem_not_empty(self):
        issued = self.ca.issue_agent_certificate(agent_id="agent-pem-1", community_id="com-p")
        assert len(issued["cert_pem"]) > 10
