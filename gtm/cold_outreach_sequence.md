# MSP Cold Outreach Sequence
## Shadow Warden AI — 3-Touch Email Chain
### Target: CTO / CISO / VP of Technology at US & EU Managed Service Providers

---

> **Merge tags** (Instantly.ai column names → CSV columns from `apollo_scraper.py`)
> - `{{first_name}}` → `first_name`
> - `{{company}}`    → `company`
> - `{{personalization}}` → `personalization` (auto-generated opening line)
>
> **Rules**
> - Send from `vz@shadow-warden-ai.com` — named inbox, never a CRM alias
> - 4–5 business days between touches; stop on any reply
> - Best window: Tue–Thu, 7:30–9:00 AM recipient local time
> - Keep Email 1 under 100 words — friction kills open-to-reply conversion

---

## Email 1 — The Wake-Up Call
**Subject:** `Your clients' data is in ChatGPT. Do you know what's in there?`

---

Hi {{first_name}},

{{personalization}}

One thing most MSPs don't have: a record of what their technicians send to AI tools on behalf of clients. SSNs, API keys, network diagrams — it all flows out in plaintext, with no audit trail.

Shadow Warden sits in front of every AI request and strips PII in under 40ms. One deployment, every client isolated, GDPR Article 30 log auto-generated.

Open to a 15-minute demo? I'll show you a live SSN intercept in the first 3 minutes — no slides.

Val
shadow-warden-ai.com | {{calendar_link}}

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
