# Seller Protection Programme

**Status:** adopted by the owner on 2026-11-24. This is the canonical plan for
the product; the root `CLAUDE.md` points here.

## The product

A secure workspace that helps Amazon sellers keep their accounts and their
business. It finds account-health, listing, labelling and documentation risks
early, and keeps the evidence ready for when Amazon asks for it. The platform
estimates risk from the seller's own data. It does not decide anything for
Amazon, and it never promises that a seller will avoid suspension.

The AI security gateway is the internal engine. It screens text, holds keys,
encrypts personal data, backs up and records evidence. It is not sold on its
own.

## Owner decisions (2026-11-24)

| # | Question | Decision | Who decided |
|---|----------|----------|-------------|
| 1 | One product? | Seller protection is the only product; the gateway is an internal engine with no separate sale | Owner |
| 2 | Homepage | Rewrite it for sellers | Owner |
| 3 | Freeze | S0–S5 and R8 are exempt, inside `warden/m2m_store/` and the portal only (see `CLAUDE.md`) | Delegated, owner asked for the best call |
| 4 | Legal entity | Register it **before the public launch and before taking any payment**, not "at the very end" | Delegated |
| 5 | Console language | English for now. Revisit after the pilot, using the marketplaces pilot sellers actually trade on | Delegated |
| 6 | Order | S1 → S3 → S4 → S2 (below) | Delegated |

Why this order. S1 (account health) is the cheapest feature to build and the
one a seller returns to every week, which a pilot needs. S3 and S4 (evidence
and appeals) are where sellers are most willing to pay. S4 depends on S3. S2
(the requirements registry) is the most expensive to keep correct, and its
value rises once there are catalogues to re-check. Until S2 exists, the
existing listing check covers the same ground with a static rule set.

Why the entity moves forward. Without a legal entity there is no payment
rail, no DPA an EU seller can sign, and no SP-API access. Taking it "last"
means the riskiest assumption, that sellers will pay, is tested last. The
pilot runs free and closed until the entity exists.

## Phases

| Phase | Scope | Needs the entity |
|-------|-------|------------------|
| **S0 Governance** | `CLAUDE.md` restructured (product first; gateway map in `warden/CLAUDE.md`); freeze exemption; SP-01…SP-07; banned seller claims in the matrix; this document | no |
| **S1 Account health** | Import the reports a seller downloads from Seller Central; keep a history per metric; trend and an early warning before a threshold; email notice to the seller. Thresholds in one dated table (SP-07) | no |
| **S3 Evidence vault** | Supplier invoices, brand authorisations and certificates (CPC, CE, SDS, GPSR documents), with expiry dates and reminders; an evidence pack per complaint type. Built on the Evidence Vault (MinIO + Fernet) and the expiry pattern from secrets lifecycle | no |
| **S4 Appeal workspace** | Plan of Action draft (root cause → corrective action → prevention), assembled from S3 documents and the account timeline; an AI draft that a person reviews and sends (SP-03) | no |
| **Pilot** | 3–5 real sellers, free and closed, after S1. Kill criterion: fewer than 2 of 5 upload a second report within 30 days → stop and re-think before building S3 | no |
| **S2 Requirements registry** | Rules as data (marketplace, scope, check, action, source, effective dates, `verified_at`, state draft → review → live → retired); watchers → diff → `/filter` → model draft → human approval → re-check catalogues → notify only the sellers affected (SP-05) | no |
| **S5 Connect** | Entity → paid seller plans, a DPA, SP-API (notifications and reports instead of manual exports) | **yes** |

## Running alongside

- **Narrowing.** Surfaces that only served the gateway as a product move to
  `lab`, one cohort per PR. The method is in
  `docs/surface-decision-2026-11-14.md`.
- **Public copy.** The homepage is rewritten for sellers. The gateway tier
  ladder leaves the headline. The seller ladder (Free / Guardian / Shield /
  Fortress) is published only after a payment rail has settled a real charge.
- **Claims.** Every new feature adds a row to `docs/capability-matrix.md`.
  Seller promises the product cannot keep are listed in its `banned-claims`
  block and enforced by `warden/tests/test_public_claims_reconciled.py`.

## Sources

- R7 research (2026-11-14): buyer-PII limits, the messaging rules, and the
  cancelled SP-API fee.
- Account-health thresholds come from third-party sources. Check them against
  Amazon's own help pages before any surface shows them (SP-07).
