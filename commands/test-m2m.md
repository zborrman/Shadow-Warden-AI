Run the M2M marketplace test suite and report results.

```bash
ALLOW_UNAUTHENTICATED=true WARDEN_API_KEY="" ANTHROPIC_API_KEY="" LOGS_PATH="/tmp/warden_test_logs.json" DYNAMIC_RULES_PATH="/tmp/dr.json" REDIS_URL="memory://" MODEL_CACHE_DIR="/tmp/warden_test_models" python -m pytest warden/tests/test_marketplace_m2m.py -v --tb=short --no-cov 2>&1
```

After running, summarize:
- Total passed / failed
- Any FAILED tests with their error message
- Whether the First-Proposal Bias Guard tests passed (class `TestFirstProposalBiasGuard`)
- Whether the protocol endpoint tests passed (class `TestProtocolEndpoint`)

If any tests failed, diagnose the root cause and propose a fix.
