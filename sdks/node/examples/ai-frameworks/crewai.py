"""
Shadow Warden AI — CrewAI integration example

Registers Shadow Warden as a CrewAI Tool so that every agent call is
automatically screened before reaching the underlying LLM.

Prerequisites:
    pip install crewai requests

Usage:
    SHADOW_WARDEN_API_KEY=<key> python crewai.py
"""
from __future__ import annotations

import os

import requests
from crewai import Agent, Crew, Process, Task
from crewai.tools import BaseTool
from pydantic import BaseModel, Field


# ── Shadow Warden filter tool ─────────────────────────────────────────────────


class FilterInput(BaseModel):
    content: str = Field(..., description="Text to screen for policy violations.")
    tenant_id: str = Field(default="default", description="Tenant identifier.")


class ShadowWardenFilterTool(BaseTool):
    name: str = "shadow_warden_filter"
    description: str = (
        "Screens text for jailbreak attempts, prompt injection, PII, and secrets. "
        "Returns the risk verdict. Always call this before processing user input."
    )
    args_schema: type[BaseModel] = FilterInput

    _base_url: str = os.getenv("SHADOW_WARDEN_URL", "https://api.shadow-warden-ai.com")
    _api_key: str = os.getenv("SHADOW_WARDEN_API_KEY", "")

    def _run(self, content: str, tenant_id: str = "default") -> str:
        try:
            resp = requests.post(
                f"{self._base_url}/filter",
                json={"content": content, "tenant_id": tenant_id},
                headers={"X-API-Key": self._api_key},
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("blocked") or not data.get("allowed", True):
                flags = ", ".join(data.get("flags", []))
                return (
                    f"BLOCKED — risk_level={data.get('risk_level','unknown')} "
                    f"flags=[{flags}]"
                )
            return f"ALLOWED — risk_level={data.get('risk_level','low')}"
        except requests.RequestException as exc:
            # Fail-open: log and allow so CrewAI can continue
            return f"FILTER_UNAVAILABLE — {exc}"


class CompliancePostureTool(BaseTool):
    name: str = "get_compliance_posture"
    description: str = (
        "Returns the real-time compliance posture score (GDPR/SOC2/ISO27001/HIPAA) "
        "for a tenant. Use when the user asks about compliance status."
    )

    _base_url: str = os.getenv("SHADOW_WARDEN_URL", "https://api.shadow-warden-ai.com")
    _api_key: str = os.getenv("SHADOW_WARDEN_API_KEY", "")

    def _run(self, tenant_id: str = "default") -> str:  # type: ignore[override]
        try:
            resp = requests.get(
                f"{self._base_url}/compliance/posture",
                params={"tenant_id": tenant_id},
                headers={"X-API-Key": self._api_key},
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json()
            score = data.get("overall_score", "N/A")
            grade = data.get("grade", "N/A")
            frameworks = data.get("frameworks", {})
            summary = ", ".join(f"{k}={v}" for k, v in frameworks.items())
            return f"Score={score} Grade={grade} | {summary}"
        except requests.RequestException as exc:
            return f"COMPLIANCE_UNAVAILABLE — {exc}"


# ── Crew definition ───────────────────────────────────────────────────────────

def build_security_crew(tenant_id: str = "default") -> Crew:
    filter_tool = ShadowWardenFilterTool()
    compliance_tool = CompliancePostureTool()

    security_analyst = Agent(
        role="AI Security Analyst",
        goal="Screen all inputs for policy violations and report security posture.",
        backstory=(
            "You are a security analyst powered by Shadow Warden AI. "
            "Before processing any user request, you always call shadow_warden_filter. "
            "You also monitor compliance posture on request."
        ),
        tools=[filter_tool, compliance_tool],
        verbose=True,
        allow_delegation=False,
    )

    compliance_reporter = Agent(
        role="Compliance Reporter",
        goal="Generate a human-readable compliance summary for the tenant.",
        backstory=(
            "You translate technical compliance data into clear executive summaries. "
            "You rely on the security analyst for raw posture data."
        ),
        tools=[compliance_tool],
        verbose=True,
        allow_delegation=True,
    )

    screen_task = Task(
        description=(
            f"Screen the following user input for policy violations "
            f"(tenant: {tenant_id}):\n\n{{user_input}}"
        ),
        expected_output="A short verdict: ALLOWED or BLOCKED with reason.",
        agent=security_analyst,
    )

    compliance_task = Task(
        description=f"Retrieve and summarise the compliance posture for tenant '{tenant_id}'.",
        expected_output="One paragraph compliance summary with score, grade, and top gaps.",
        agent=compliance_reporter,
    )

    return Crew(
        agents=[security_analyst, compliance_reporter],
        tasks=[screen_task, compliance_task],
        process=Process.sequential,
        verbose=True,
    )


# ── Demo ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    api_key = os.getenv("SHADOW_WARDEN_API_KEY", "")
    if not api_key:
        raise SystemExit("Set SHADOW_WARDEN_API_KEY before running this example.")

    crew = build_security_crew(tenant_id="demo")

    # Safe input
    result = crew.kickoff(inputs={"user_input": "What is the current threat level?"})
    print("\n=== Crew Result ===")
    print(result)
