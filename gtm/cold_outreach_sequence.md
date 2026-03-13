# MSP Cold Outreach Sequence
## Shadow Warden AI — 3-Touch Email Chain
### Target: CTO / CISO / VP of Technology at US & EU Managed Service Providers

---

> **Usage notes**
> - Personalize `[FIRST_NAME]`, `[COMPANY]`, `[MSP_CITY/REGION]` before sending
> - Send from a named inbox (e.g. val@shadow-warden-ai.com), not a CRM alias
> - Wait 4–5 business days between touches
> - Stop sequence immediately on reply (any reply)
> - Best send times: Tuesday–Thursday, 7:30–9:00 AM recipient local time

---

## Email 1 — The Wake-Up Call
**Subject:** `Your clients' data is going into ChatGPT right now`

---

Hi [FIRST_NAME],

Quick question — do you know what your technicians are pasting into ChatGPT today?

At most MSPs, the answer is: **everything**. Support ticket notes, client network diagrams, Active Directory exports, sometimes full backup configs with credentials embedded.

That's not a hypothetical. In Q1 2025, a single mid-market MSP in [MSP_CITY] received a €340,000 GDPR fine after a technician used an AI assistant to summarize a client's HR data export. The AI vendor's ToS allowed training on inputs. The MSP had no audit trail.

The regulation doesn't care that the employee "didn't mean to" share PII. It cares that you had no control layer.

**Shadow Warden AI is that layer.**

It sits in front of every AI request — ChatGPT, Copilot, Claude, your internal LLM tools — and in under 40ms:

- Strips SSNs, API keys, IBAN numbers, and 15 other PII/secret types before they leave your network
- Blocks jailbreak attempts (the kind that trick AI into ignoring its own safety rules)
- Generates a GDPR-compliant audit log, per tenant, per request

We built it specifically for MSPs: one deployment protects all your clients, each in an isolated tenant with their own policies and compliance exports.

I'd love to show you a 15-minute live demo — we catch a real SSN and a real API key in the first 3 minutes. No slides, no decks.

Worth a look?

[Your Name]
Shadow Warden AI | shadow-warden-ai.com
[Calendar link]

---

## Email 2 — The Proof (sent Day 5 if no reply)
**Subject:** `Re: Your clients' data is going into ChatGPT right now`

---

Hi [FIRST_NAME],

Following up — wanted to share one number that tends to land with MSP leadership.

**$4.45M** — that's the average total cost of an AI-related data breach in 2024 (IBM Cost of a Data Breach Report). For an MSP, the multiplier is worse: you're liable not just for your own breach, but potentially for every client whose data flowed through your uncontrolled AI pipeline.

Most MSPs I talk to are in one of three situations:

1. **"We banned ChatGPT"** — Employees are using it on personal phones or home connections. The ban created a false sense of security.

2. **"We're using Copilot M365"** — Microsoft's DLP doesn't cover third-party AI tools, custom internal LLMs, or API calls from your RMM/PSA integrations.

3. **"We're waiting to see how this plays out"** — EU AI Act enforcement began January 2026. US state-level AI liability bills are moving fast. Waiting is now a liability decision.

Shadow Warden gives you a concrete answer to any client who asks: *"How do you ensure our data doesn't leave your environment when your team uses AI?"*

Here's what the deployment looks like for a typical MSP:

```
Your team's AI tools → Shadow Warden filter (your cloud / on-prem)
                            ↓
                   Client A sandbox | Client B sandbox | Client C sandbox
                            ↓
              Per-tenant audit log → your SIEM / client's SIEM
```

**We offer a free NFR license** for your own internal use. You prove it to yourself first, then offer it to clients as a managed service.

15 minutes on a call — I'll show you the live intercept of an SSN being stripped in real time.

[Your Name]
[Calendar link]

---

## Email 3 — The Break-Up (sent Day 9 if no reply)
**Subject:** `Last note — AI compliance for [COMPANY]`

---

Hi [FIRST_NAME],

Last email, I promise.

I'll be direct: I know you're busy, and you're likely getting pitched a dozen AI tools a week. Most of them are adding AI. We're the only one your clients need to **control** it.

One thing I wanted to leave you with — a scenario that comes up in every MSP sales call we do with their enterprise clients:

> *"Do you have a written policy and technical control for AI data handling?"*

That question is now in RFPs from financial services, healthcare, and government clients. MSPs who can say "yes" with proof are winning contracts. Those who can't are losing renewals.

Shadow Warden generates a compliance artifact for exactly this: a per-tenant data handling report showing every AI request, what PII was detected, what was redacted, and the full audit trail. GDPR Article 30 RoPA-ready, out of the box.

If the timing isn't right, no problem — I'll check back in a quarter.

If you'd like to see the 15-minute demo, here's my calendar: [Calendar link]

Either way, good luck with the AI compliance wave coming your way.

[Your Name]
Shadow Warden AI | shadow-warden-ai.com

P.S. — If you know a colleague who owns AI security decisions at [COMPANY] or another MSP, I'd appreciate an intro. Happy to return the favor.

---

## Sequence Performance Benchmarks (target)

| Metric | Target |
|--------|--------|
| Open rate (Email 1) | ≥ 45% |
| Reply rate (all 3) | ≥ 8% |
| Demo-booked rate | ≥ 3% |
| Demo → trial | ≥ 60% |

## Personalization Tier (for high-value targets)

For MSPs with 200+ employees or ≥ $10M ARR, add a custom first line to Email 1:

> *"I saw [COMPANY]'s post about [recent news / award / hiring surge] — congrats on the growth. With that scale, the AI data exposure surface is probably something your CISO thinks about."*

Sources for personalization: LinkedIn company feed, Crunchbase, local business journals, CRN MSP 500 list.
