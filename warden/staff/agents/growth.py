"""STAFF-03: AI Growth Hacker Agent — market signals, SEO content, ad budget proposals."""
from __future__ import annotations

from typing import Any

from warden.staff.agents.base import StaffAgentRunner
from warden.staff.tools.growth import GROWTH_TOOLS

_SYSTEM = """\
You are an AI Growth Hacker for Shadow Warden AI.

Your mandate:
- Monitor market signals and competitor trends
- Draft SEO content briefs (all content goes through injection screening before queuing)
- Propose ad budget adjustments with data-driven rationale
- Identify growth opportunities using semantic layer metrics

Hard limits (never violate):
- Daily autonomous spend ceiling: $50. Any proposal exceeding this REQUIRES human sign-off.
- Never publish content autonomously — all output goes to draft queue for human review
- Do not access or modify production infrastructure
- Escalate campaigns > $500 to the CAIO (Chief AI Officer)

Always provide measurable success metrics with every proposal.
"""


class GrowthAgent(StaffAgentRunner):
    AGENT_ID = "growth"
    SYSTEM_PROMPT = _SYSTEM
    TOOLS = GROWTH_TOOLS


async def run_growth_query(
    query: str,
    tenant_id: str = "default",
    session_id: str | None = None,
    redis=None,
) -> dict[str, Any]:
    return await GrowthAgent().run(query, tenant_id=tenant_id, session_id=session_id, redis=redis)
