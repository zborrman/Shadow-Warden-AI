# Shadow Warden AI — Documentation

**Version 5.6** | [shadow-warden-ai.com](https://shadow-warden-ai.com) | [Portal](https://portal.shadow-warden-ai.com)

Shadow Warden AI is a self-contained, GDPR-compliant AI security gateway. It sits in front of every AI request, blocking jailbreak attempts, stripping secrets/PII, and self-improving via Claude Opus — all without sending sensitive data to third parties.

---

## Documents

| Document | Description | Audience |
|---|---|---|
| [architecture-overview.md](architecture-overview.md) | High-level system design, modules, tech stack, design principles | Engineers, architects |
| [deployment-guide.md](deployment-guide.md) | Docker Compose + Kubernetes install, secrets, TLS, HA, upgrade | DevOps, platform engineers |
| [developer-guide.md](developer-guide.md) | Repo structure, local setup, adding modules, CI, code style | Contributors, developers |
| [api-reference.md](api-reference.md) | All public REST endpoints, auth, pagination, error codes | Integrators, API consumers |
| [sdk-guide.md](sdk-guide.md) | Node.js/TypeScript SDK, AI-framework integrations (LangChain, CrewAI) | Application developers |
| [marketplace-guide.md](marketplace-guide.md) | Register agents, tokenize assets, listings, escrow, disputes | Marketplace participants |
| [compliance-guide.md](compliance-guide.md) | GDPR/SOC2/ISO27001/HIPAA posture dashboard, gaps, reports | Compliance officers, CISOs |
| [security-model.md](security-model.md) | 9-layer filter, PQC, FIDO2, STIX audit, threat model | Security auditors, CISOs |
| [community-creation-guide.md](community-creation-guide.md) | Create communities, manage members, peering, data pods | Community owners |
| [troubleshooting.md](troubleshooting.md) | Common errors and fixes — preflight, escrow, compliance, auth | Operators, DevSecOps |
| [changelog.md](changelog.md) | Version history from v1.0 to v6.3 | Everyone |
| [sla.md](sla.md) | Pro 99.9% / Enterprise 99.95% uptime, P99 latency, credits | Enterprise customers |
| [dpia.md](dpia.md) | GDPR Art. 35 Data Protection Impact Assessment | DPOs, legal teams |
| [soc2-evidence.md](soc2-evidence.md) | SOC 2 Type II control mapping and auditor collection guide | Auditors, compliance teams |

---

## Quick links

- **API playground:** `https://api.shadow-warden-ai.com/docs` (Swagger UI)
- **Grafana dashboards:** `http://your-host:3000`
- **SOC Dashboard:** `http://your-host:3002`
- **Streamlit analytics:** `http://your-host:8501`
- **Prometheus metrics:** `http://your-host:9090`

---

## Getting started in 60 seconds

```bash
# 1. Clone
git clone https://github.com/shadow-warden-ai/shadow-warden-ai.git
cd shadow-warden-ai

# 2. Configure
cp .env.example .env   # edit WARDEN_API_KEY, VAULT_MASTER_KEY, ANTHROPIC_API_KEY

# 3. Start
docker compose up --build

# 4. Verify
curl http://localhost:8001/health
# {"status":"ok","version":"5.6.0"}
```

For full production deployment see [deployment-guide.md](deployment-guide.md).
