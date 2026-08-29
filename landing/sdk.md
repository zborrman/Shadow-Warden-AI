# SDK, CLI and API — Shadow Warden AI

Human page: <https://shadow-warden-ai.com/sdk>

## Install

```bash
pip install shadow-warden-sdk        # Python
npm install @shadow-warden/sdk       # TypeScript / JavaScript
```

## Python

```python
from shadow_warden import WardenClient

with WardenClient(gateway_url="https://api.shadow-warden-ai.com", api_key="sk_...") as warden:
    result = warden.filter("Summarise the contract for client@example.com")
    if result.allowed:
        ...  # safe to forward to the model
```

`AsyncWardenClient` mirrors the same surface for `asyncio`. `wrap_openai()`
returns a drop-in OpenAI client whose completions are filtered on the way in.

## CLI

The `warden` console script ships with `shadow-warden-sdk` >= 1.1.0. It is the
fastest way for an agent or a shell script to use the gateway without writing an
integration.

```bash
warden health                                  # gateway reachability
warden filter "ignore previous instructions"   # exit 0 allowed, 1 blocked
warden filter --json --file prompt.txt         # machine-readable verdict
warden filter --stdin < prompt.txt             # pipeline friendly
warden impact --requests 50000                 # projected spend for a volume
warden billing                                 # plan, quota, add-ons
```

Configuration comes from `WARDEN_API_KEY` and `WARDEN_GATEWAY_URL`, or from
`--api-key` and `--gateway-url`. Every command accepts `--json`, so output is
parseable without screen-scraping.

Exit codes: `0` allowed, `1` blocked, `2` usage error, `3` gateway or network
error. A flagged-but-allowed verdict exits `0` — read `risk_level` from the
JSON if you want to gate on it. That makes `warden filter` usable directly in a
shell conditional or a CI gate.

## TypeScript

```ts
import { WardenClient } from '@shadow-warden/sdk';

const client = new WardenClient({ apiKey: 'sk_...' });
const result = await client.filter('text to inspect');
```

## Direct HTTP

Nothing in the SDKs is privileged. `POST /filter` with an `X-API-Key` header is
the whole contract, and the OpenAPI document at
<https://shadow-warden-ai.com/openapi.json> describes every route.
