"""
Per-tool pricing for the paid MCP gateway.

Pricing philosophy:
  • Compliance / regulatory tools: $0.03–$0.10  (high-liability, high-value)
  • Analytics / intelligence tools: $0.01–$0.02  (medium-value data products)
  • CRM / workflow tools:           $0.005–$0.01  (operational leverage)
  • KB lookup / status tools:       $0.001         (commodity, volume play)

Sensitive internal tools (issue_refund, get_billing_status) are NOT exposed —
they are absent from MCP_EXPOSED_TOOLS regardless of price.
"""
from __future__ import annotations

from decimal import Decimal

# Per-tool fees in USD
TOOL_PRICES_USD: dict[str, Decimal] = {
    # Compliance / KYC-AML
    "screen_sanctions_list":  Decimal("0.05"),
    "score_kyc_profile":      Decimal("0.03"),
    "generate_sar":           Decimal("0.10"),
    # Growth intelligence
    "fetch_market_signals":   Decimal("0.01"),
    "generate_seo_content":   Decimal("0.02"),
    "adjust_ad_budget":       Decimal("0.03"),
    # BDR / CRM
    "crm_search":             Decimal("0.005"),
    "crm_upsert_lead":        Decimal("0.01"),
    "send_email_draft":       Decimal("0.01"),
    "schedule_meeting_slot":  Decimal("0.005"),
    # Support
    "get_ticket":             Decimal("0.001"),
    "resolve_ticket_kb":      Decimal("0.001"),
}

DEFAULT_PRICE_USD = Decimal("0.01")

# Tools published in tools/list and executable via tools/call.
# issue_refund + get_billing_status are intentionally absent.
MCP_EXPOSED_TOOLS: frozenset[str] = frozenset(TOOL_PRICES_USD)


def price_for(tool_name: str) -> Decimal:
    return TOOL_PRICES_USD.get(tool_name, DEFAULT_PRICE_USD)
