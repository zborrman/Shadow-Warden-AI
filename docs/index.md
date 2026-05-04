# Shadow Warden AI

**Self-contained, GDPR-compliant AI security gateway** · v4.11

Shadow Warden sits in front of every AI request, blocking jailbreak attempts,
stripping secrets and PII, and self-improving via Claude Opus — without sending
sensitive data to third parties.

---

## What It Does

<div class="grid cards" markdown>

-   :shield: **9-Layer Defense**

    ---
    Topology → Obfuscation → Secrets → Semantic → Brain → Causal → Phishing → ERS → Decision.
    Each layer adds a millisecond, not a second.

    [:octicons-arrow-right-24: Filter pipeline](architecture/pipeline.md)

-   :robot: **Autonomous SOVA Operator**

    ---
    Claude Opus agentic loop with 37 tools. Morning briefs, threat syncs,
    key rotation checks, community moderation — all automated.

    [:octicons-arrow-right-24: SOVA guide](guides/sova.md)

-   :busts_in_silhouette: **Business Community**

    ---
    NVIDIA NIM content moderation, Obsidian bridge, member management,
    and automated watchdog with auto-block on WARN ≥ 0.85.

    [:octicons-arrow-right-24: Community guide](guides/community.md)

-   :lock: **Post-Quantum Crypto**

    ---
    HybridSigner (Ed25519 + ML-DSA-65) and HybridKEM (X25519 + ML-KEM-768).
    Enterprise-tier feature, liboqs fail-open.

    [:octicons-arrow-right-24: Security model](security-model.md)

</div>

---

## Quick Links

| Resource | Link |
|----------|------|
| Quick Start | [guides/quickstart.md](guides/quickstart.md) |
| API Reference | [api.md](api.md) |
| Architecture | [architecture/overview.md](architecture/overview.md) |
| GDPR DPIA | [dpia.md](dpia.md) |
| SOC 2 Evidence | [soc2-evidence.md](soc2-evidence.md) |
| SLA | [sla.md](sla.md) |
| Changelog | [changelog/index.md](changelog/index.md) |

---

## Version

Current: **v4.11** · [Full changelog](changelog/index.md)

```
Week 1    Phase 0  Foundation & CI
Week 2-3  Phase 1  Business Community (NIM + Obsidian)
Week 3-4  Phase 2  Cyber Security Hub (CVE scanner + SOC dashboard)
Week 4-5  Phase 3  Documentation (this site)
Week 5-6  Phase 4  Settings Integration
Week 6-7  Phase 5  Payment Plan
```
