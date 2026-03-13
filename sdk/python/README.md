# shadow-warden-client

Python SDK for the [Shadow Warden AI](https://shadowwarden.ai) security gateway.

## Install

```bash
pip install shadow-warden-client
```

## Quick start

```python
from shadow_warden import WardenClient

with WardenClient(gateway_url="http://localhost:8001", api_key="sk_...") as warden:
    result = warden.filter("Summarise the contract for client@example.com")
    if result.allowed:
        # safe to forward to your AI model
        ...
    else:
        print("Blocked:", result.risk_level, result.flag_names)
```

## OpenAI wrapper (drop-in)

```python
import openai
from shadow_warden import WardenClient

warden = WardenClient(api_key="sk_warden_...")
client = warden.wrap_openai(openai.OpenAI(api_key="sk-openai-..."))

# Identical to the standard OpenAI API — Warden intercepts transparently
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "..."}],
    raise_on_block=True,    # raises WardenBlockedError if blocked
)
```

## Async

```python
from shadow_warden import AsyncWardenClient

async with AsyncWardenClient(gateway_url="...", api_key="...") as warden:
    result = await warden.filter("user prompt")
```

## Batch filtering

```python
results = warden.filter_batch([
    "What is the capital of France?",
    {"content": "My SSN is 123-45-6789", "strict": True},
])
```

## Fail-open mode

```python
# If the gateway is unreachable, return a permissive result instead of raising
warden = WardenClient(fail_open=True)
```

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `gateway_url` | `http://localhost:8001` | Warden gateway base URL |
| `api_key` | `""` | `X-API-Key` header value |
| `tenant_id` | `"default"` | Default tenant for all requests |
| `timeout` | `10.0` | HTTP timeout in seconds |
| `fail_open` | `False` | Return permissive result on network errors |

## Error handling

```python
from shadow_warden import WardenBlockedError, WardenGatewayError, WardenTimeoutError

try:
    result = warden.filter(content, raise_on_block=True)
except WardenBlockedError as e:
    print("Blocked:", e.result.risk_level)
except WardenTimeoutError:
    print("Gateway timeout")
except WardenGatewayError as e:
    print(f"HTTP {e.status_code}: {e.detail}")
```

## FilterResult fields

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | `bool` | Whether the content passed all filters |
| `blocked` | `bool` | Convenience inverse of `allowed` |
| `risk_level` | `str` | `low` / `medium` / `high` / `block` |
| `filtered_content` | `str` | Content after PII redaction |
| `secrets_found` | `list[SecretFinding]` | Detected secrets/PII |
| `semantic_flags` | `list[SemanticFlag]` | Triggered semantic rules |
| `flag_names` | `list[str]` | Shorthand for flag names |
| `has_secrets` | `bool` | True if any secrets were found |
| `has_pii` | `bool` | True if `pii_detected` flag is present |
| `processing_ms` | `dict[str, float]` | Per-stage timing breakdown |
