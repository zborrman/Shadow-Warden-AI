# Shadow Warden AI

> A workspace for Amazon sellers: catch listing, labelling, barcode and
> account-health risks early, from the seller's own data. Independent of
> Amazon; it never logs in to Seller Central and never asks for an Amazon
> password.

- Homepage: <https://shadow-warden-ai.com/>
- For sellers: <https://shadow-warden-ai.com/sellers>
- Machine index: <https://shadow-warden-ai.com/llms.txt>
- Agent instructions (when to use this): <https://shadow-warden-ai.com/.well-known/agent-instructions.md>
- OpenAPI 3.1: <https://shadow-warden-ai.com/openapi.json>
- API base URL: `https://api.shadow-warden-ai.com`

## Available now

- **Listing check**: flags pesticide, medical, green and absolute claims in the
  seller's own titles and descriptions, each with its public basis (EPA/FIFRA,
  FDA, FTC Green Guides, EU 2024/825). Advice only; it cannot know what a
  marketplace will remove.
- **Account-health calculator**: order defect, late shipment, cancellation and
  valid-tracking rates from numbers the seller types. Nothing is read from Amazon.
- **GTIN check**: GS1 check digit verified before a number is saved. A valid
  check digit does not mean GS1 licensed the number.
- **Labels**: print-ready FNSKU and barcode labels (A4, US Letter, 50 x 25 mm
  rolls, ZPL). Not tested by any fulfilment centre.
- **EU product safety (GPSR)**: manufacturer, EU responsible person and warnings
  shown on the seller's storefront. Entered by the seller, not verified by us.
- **Own storefront and customer list**: five languages; the platform sends no
  email and moves no money.

## In development (not available)

Account-health history from uploaded reports, an evidence vault for invoices
and certificates, and an appeal (plan of action) workspace.

## What it will not do

It never acts inside Seller Central, never sends messages or appeals on the
seller's behalf, and does not decide anything for Amazon: it estimates risk.
No tool can guarantee an account stays open.

## Developer interfaces (the screening engine)

The workspace runs on a text-screening gateway that also has a public API.

| Interface | Entry point |
|---|---|
| REST API | `POST https://api.shadow-warden-ai.com/filter` |
| OpenAI-compatible proxy | `POST https://api.shadow-warden-ai.com/v1/chat/completions` |
| Python SDK | `pip install shadow-warden-sdk` |
| TypeScript SDK | `npm install @shadow-warden/sdk` |
| CLI | `warden filter "text"` — console script of `shadow-warden-sdk` >= 1.1.0 |
| Agent Card (A2A / ADP) | `GET https://shadow-warden-ai.com/.well-known/agent.json` |
| DID document | `GET https://shadow-warden-ai.com/.well-known/did.json` |

## Where to go next

- [Documentation](https://shadow-warden-ai.com/doc.md)
- [SDK and CLI](https://shadow-warden-ai.com/sdk.md)
- [CLI (`warden`)](https://shadow-warden-ai.com/cli.md)
- [API versioning policy](https://shadow-warden-ai.com/versioning.md)
- [About](https://shadow-warden-ai.com/about.md)
- [Pricing](https://shadow-warden-ai.com/pricing.md)
- [Trust centre](https://shadow-warden-ai.com/trust.md)
- [Sitemap](https://shadow-warden-ai.com/sitemap-index.xml)

## Maturity

Capability statuses — what is live, what is testnet, what is built but not
deployed — are published in the repository's capability matrix and are the
authority over any marketing copy. Nothing on this site should be read as a
certification, and the marketplace has no production traffic.
