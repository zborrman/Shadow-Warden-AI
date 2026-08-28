# Pricing — Shadow Warden AI

Serves both <https://shadow-warden-ai.com/pricing> and
<https://shadow-warden-ai.com/price>. Monthly list prices in USD. Annual plans
are derived from the monthly price, never typed by hand — see the pricing page
for the current annual figure.

## Plans

| Plan | Price | Requests / month | Notes |
|---|---|---|---|
| **Starter** | Free | 1,000 | Full nine-stage pipeline |
| **Individual** | $5.00/month | 5,000 | Single developer |
| **Community Business** | $39.99/month | 15,000 | File Scanner, Shadow AI Monitor, 3 communities, 180-day retention |
| **Pro** | $99.99/month | 50,000 | MasterAgent included (200 agent turns/month) |
| **Enterprise** | $249.00/month | Unlimited | Post-quantum crypto, sovereign routing |

## Add-ons

| Add-on | Price | Minimum plan |
|---|---|---|
| Shadow AI Discovery | $15.00/month | Pro |
| XAI Audit | $9.00/month | Individual |
| SMB Governance Suite | $29.00/month | Individual |

## Metered

Flex Credits are prepaid and need no wallet: 100 credits $0.10, 500 credits
$0.45, 1,000 credits $0.85, 5,000 credits $4.00. The marketplace search fee and
the credit unit price are the same constant, so the x402 and credit rails cost
the same for the same work.

## Gate semantics

An HTTP `403` from a gated endpoint means the plan is below the minimum tier —
the caller should upgrade. An HTTP `402` means the plan is eligible but the
add-on has not been purchased — the caller should check out.

## Buying

Checkout is handled by Lemon Squeezy as merchant of record. Purchase of a paid
plan is not yet validated end to end against the live payment rail; treat the
published prices as the list, not as a completed purchase path.

- Human page: <https://shadow-warden-ai.com/price>
- Comparison and add-on calculator: <https://shadow-warden-ai.com/pricing>
