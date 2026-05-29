# shadow-warden-sdk

Official Python SDK for **Shadow Warden AI** — zero-trust AI security gateway.

## Installation

```bash
pip install shadow-warden-sdk
```

## Quick Start

```python
from shadow_warden_sdk import ShadowWardenClient

client = ShadowWardenClient(
    api_key="sw-your-api-key",
    base_url="https://api.shadow-warden-ai.com",
)

# Filter a prompt through the 9-layer pipeline
result = client.filter("Your user prompt here")
if result["blocked"]:
    print(f"Blocked (risk={result['risk_score']:.2f})")

# Create a spending mandate for AI-driven procurement
mandate = client.create_mandate(tenant_id="acme", max_amount=200.0)

# Place an order within the mandate
order = client.create_order(
    tenant_id="acme",
    store_url="https://shop.example.com",
    mandate_id=mandate["id"],
    items=[{"name": "API Credits", "qty": 1, "unit_price": 49.99,
            "product_id": "api-100k", "currency": "USD"}],
)

# Calculate VAT for German buyer
tax = client.calculate_tax(net_amount=49.99, buyer_country="DE")
print(f"Total with VAT: ${tax['total_with_tax']:.2f}")
```

## SecureAgent

```python
from shadow_warden_sdk import SecureAgent

class MyAgent(SecureAgent):
    def run(self, task: str):
        filtered = self.filter_prompt(task)
        if filtered.get("blocked"):
            raise ValueError("Task blocked by Shadow Warden")
        return self.submit_purchase_intent(task)

agent = MyAgent(api_key="sw-...", tenant_id="acme")
result = agent.run("Buy a cloud monitoring tool under $80/mo")
```

## Documentation

Full API reference: [docs.shadow-warden-ai.com](https://docs.shadow-warden-ai.com)

## License

MIT
