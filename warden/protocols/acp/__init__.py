"""
Agentic Commerce Protocol (ACP) — Stripe/OpenAI spec alignment.

Adds Shared Payment Tokens, cart→checkout flow, and refund requests
on top of the existing AP2 mandate infrastructure (CM-40).

Security invariant: checkout requires BOTH a valid SPT (merchant-level ceiling)
AND a valid AP2 mandate (tenant-level ceiling). Neither alone is sufficient.
"""
