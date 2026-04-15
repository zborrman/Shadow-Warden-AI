"""
warden/agent/
─────────────
SOVA — Shadow Operations & Vigilance Agent

Autonomous AI operator built on Claude Opus 4.6 that orchestrates
all Shadow Warden subsystems: threat response, key rotation, SLA
monitoring, financial intelligence, and compliance.

Entry points:
  sova.py       — Claude Opus 4.6 core agent loop (tool use + caching)
  tools.py      — Tool implementations (HTTP → internal API)
  memory.py     — Redis-backed conversation state
  scheduler.py  — ARQ cron jobs (morning brief, rotation check, etc.)
"""
