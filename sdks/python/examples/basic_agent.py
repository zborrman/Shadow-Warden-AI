"""
examples/basic_agent.py
Demonstrates SecureAgent usage for AI-driven procurement.
"""
from shadow_warden_sdk import ShadowWardenClient, SecureAgent


# ── Direct client usage ───────────────────────────────────────────────────────

def direct_client_example():
    client = ShadowWardenClient(
        api_key="sw-your-api-key",
        base_url="https://api.shadow-warden-ai.com",
    )

    # Filter a user prompt before passing to LLM
    result = client.filter("Summarise this document for me")
    print(f"Blocked: {result['blocked']} | Risk: {result.get('risk_score', 0):.2f}")

    # Create a spending mandate
    mandate = client.create_mandate(
        tenant_id="acme",
        max_amount=200.0,
        currency="USD",
        allowed_merchants=["shop.example.com"],
    )
    print(f"Mandate: {mandate['id']} | Max: ${mandate['max_amount']}")

    # Place an order within the mandate
    order = client.create_order(
        tenant_id="acme",
        store_url="https://shop.example.com",
        mandate_id=mandate["id"],
        items=[{"name": "API Credit Pack", "qty": 1, "unit_price": 49.99,
                "product_id": "api-credits-100k", "currency": "USD"}],
    )
    print(f"Order: {order.get('order_id')} | Total: ${order.get('total', 0):.2f}")

    # Tax calculation
    tax = client.calculate_tax(net_amount=49.99, buyer_country="DE")
    print(f"Tax: {tax['rate_pct']:.1f}% | Total with VAT: ${tax['total_with_tax']:.2f}")


# ── SecureAgent mixin usage ───────────────────────────────────────────────────

class MyProcurementAgent(SecureAgent):
    def run_task(self, task: str):
        filtered = self.filter_prompt(task)
        if filtered.get("blocked"):
            return {"error": "Task blocked by Shadow Warden", "score": filtered["risk_score"]}

        intent_result = self.submit_purchase_intent(task)
        return intent_result


def agent_example():
    agent = MyProcurementAgent(
        api_key="sw-your-api-key",
        tenant_id="acme",
        max_default_amount=100.0,
    )
    result = agent.run_task("Buy a cloud monitoring subscription for up to $80")
    print(result)
    print("Spend report:", agent.get_spend_report())


if __name__ == "__main__":
    print("=== Direct Client Example ===")
    direct_client_example()
    print("\n=== Secure Agent Example ===")
    agent_example()
