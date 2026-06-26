Report the current status of the M2M marketplace subsystem.

Read `data/AGENTS.md` (the ARQ loop state file) and summarize:
1. **Active negotiations** — count and list up to 5 with buyer/seller DIDs and round count
2. **Pending/funded escrows** — count and total USD at risk
3. **Fairness metrics (last 7d)** — avg candidates evaluated, first-offer acceptance rate vs policy minimum
4. **MAESTRO flags** — count and list any high-threat agents

Then check the lint status:

```bash
python -m ruff check warden/marketplace/ --ignore E501 --select E,F,W,I 2>&1 | head -10
```

Finally, check that the three M2M base endpoints respond:

```bash
curl -s http://localhost:8001/marketplace/protocol | python3 -c "import sys,json; d=json.load(sys.stdin); print('protocol_version:', d.get('protocol_version'), '| actions:', len(d.get('supported_actions',[])))" 2>&1 || echo "warden not running locally"
```

Produce a one-paragraph health summary.
