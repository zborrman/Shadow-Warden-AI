"""
warden/integrations/nemo_bridge.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Geometric Threat Bridge — Shadow Warden AI × NVIDIA NeMo Guardrails

Translates Shadow Warden's mathematical threat coordinates (hyperbolic distance,
Betti numbers, causal P(HIGH_RISK), ERS score) into NeMo Colang context variables,
enabling geometry-driven flow selection in NeMo Guardrails at runtime.

Architecture::

    User Input
        ↓
    Shadow Warden 9-layer pipeline  (<20ms, CPU)
        ↓  ThreatCoordinates
    GeometricThreatBridge.to_colang_context()
        ↓  Colang variables
    NeMo Guardrails (GPU) — selects flow: clean/gray/high/topo
        ↓  LLM response
    DualOutputGuard — NeMo rail + Shadow Warden OutputGuard
        ↓  signals
    ColangEvolutionSynthesizer — Claude Opus hot-reloads new Colang flows

Usage::

    import nemoguardrails
    from warden.integrations.nemo_bridge import GeometricThreatBridge, DualOutputGuard

    bridge = GeometricThreatBridge()
    rails  = nemoguardrails.LLMRails(config=nemoguardrails.RailsConfig.from_path("./nemo_colang"))

    async def handle(user_message: str) -> str:
        warden_result = await warden_client.filter_async(user_message)
        if not warden_result.allowed:
            return warden_result.block_reason or "Request blocked."
        ctx = bridge.to_colang_context(warden_result)
        response = await rails.generate_async(messages=[{"role":"user","content":user_message}], context=ctx)
        return await DualOutputGuard(bridge).check_output(user_message, response, warden_client)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Threat classification ──────────────────────────────────────────────────────

class ThreatClass(str, Enum):
    CLEAN      = "clean"        # pass normally
    GRAY_ZONE  = "gray_zone"    # cautious — Causal Arbiter activated
    HIGH_RISK  = "high_risk"    # restricted — ML + Causal both flagged
    TOPOLOGY   = "topology"     # structural noise — obfuscation attempt
    BLOCKED    = "blocked"      # already blocked by Shadow Warden


@dataclass
class ThreatCoordinates:
    """Mathematical threat position extracted from a Shadow Warden FilterResult."""

    threat_class:     ThreatClass
    hyperbolic_dist:  float   # Poincaré ball distance to nearest known attack
    betti_score:      float   # TDA noise score (β₀/β₁ weighted)
    causal_p_risk:    float   # P(HIGH_RISK | evidence) from Bayesian DAG
    ers_score:        float   # Entity Risk Score (Redis sliding window)
    risk_level:       str     # low | medium | high | block
    flag_names:       list[str] = field(default_factory=list)
    processing_ms:    dict[str, float] = field(default_factory=dict)

    @property
    def is_safe(self) -> bool:
        return self.threat_class == ThreatClass.CLEAN

    @property
    def colang_flow(self) -> str:
        """Map threat class to Colang flow file name."""
        return {
            ThreatClass.CLEAN:     "clean_flow",
            ThreatClass.GRAY_ZONE: "cautious_flow",
            ThreatClass.HIGH_RISK: "restricted_flow",
            ThreatClass.TOPOLOGY:  "obfuscation_flow",
            ThreatClass.BLOCKED:   "blocked_flow",
        }[self.threat_class]


# ── GeometricThreatBridge ─────────────────────────────────────────────────────

class GeometricThreatBridge:
    """
    Translates Shadow Warden FilterResult into NeMo Guardrails Colang context.

    Thresholds (all configurable via env vars):
    - BRIDGE_TOPOLOGY_THRESHOLD  : betti_score above which → TOPOLOGY class (default 0.75)
    - BRIDGE_HYPERBOLIC_HIGH     : hyperbolic_dist above which → HIGH_RISK (default 0.80)
    - BRIDGE_HYPERBOLIC_GRAY     : hyperbolic_dist above which → GRAY_ZONE (default 0.55)
    - BRIDGE_CAUSAL_HIGH         : causal_p_risk above which → HIGH_RISK (default 0.65)
    - BRIDGE_ERS_RESTRICT        : ers_score above which → add ERS flag (default 0.70)
    """

    def __init__(self) -> None:
        self.topology_threshold   = float(os.getenv("BRIDGE_TOPOLOGY_THRESHOLD", "0.75"))
        self.hyperbolic_high      = float(os.getenv("BRIDGE_HYPERBOLIC_HIGH",    "0.80"))
        self.hyperbolic_gray      = float(os.getenv("BRIDGE_HYPERBOLIC_GRAY",    "0.55"))
        self.causal_high          = float(os.getenv("BRIDGE_CAUSAL_HIGH",        "0.65"))
        self.ers_restrict         = float(os.getenv("BRIDGE_ERS_RESTRICT",       "0.70"))

    # ── Public API ─────────────────────────────────────────────────────────────

    def extract_coordinates(self, filter_result: Any) -> ThreatCoordinates:
        """
        Convert a Shadow Warden FilterResult (or dict) into ThreatCoordinates.

        Accepts both the SDK FilterResult dataclass and a raw dict from the
        /filter API response.
        """
        if hasattr(filter_result, "__dict__"):
            raw = filter_result.__dict__ if not hasattr(filter_result, "raw") else filter_result.raw
        else:
            raw = dict(filter_result)

        risk_level  = raw.get("risk_level", "low")
        flag_names  = self._extract_flags(filter_result)
        proc_ms     = raw.get("processing_ms", {})

        # Pull geometric scores — present when Shadow Warden v2.0+ pipeline ran
        betti_score     = float(raw.get("betti_score",     proc_ms.get("topology_score",    0.0)))
        hyperbolic_dist = float(raw.get("hyperbolic_dist", proc_ms.get("hyperbolic_score",  0.0)))
        causal_p_risk   = float(raw.get("causal_p_risk",   proc_ms.get("causal_p_risk",     0.0)))
        ers_score       = float(raw.get("ers_score",       0.0))

        threat_class = self._classify(
            allowed        = raw.get("allowed", True),
            risk_level     = risk_level,
            betti_score    = betti_score,
            hyperbolic_dist= hyperbolic_dist,
            causal_p_risk  = causal_p_risk,
            flag_names     = flag_names,
        )

        return ThreatCoordinates(
            threat_class    = threat_class,
            hyperbolic_dist = hyperbolic_dist,
            betti_score     = betti_score,
            causal_p_risk   = causal_p_risk,
            ers_score       = ers_score,
            risk_level      = risk_level,
            flag_names      = flag_names,
            processing_ms   = proc_ms,
        )

    def to_colang_context(self, filter_result: Any) -> dict[str, Any]:
        """
        Return a dict of Colang context variables to inject into NeMo rails.generate().

        Usage::

            ctx = bridge.to_colang_context(warden_result)
            response = await rails.generate_async(messages=[...], context=ctx)
        """
        coords = self.extract_coordinates(filter_result)
        return {
            # Flow routing
            "$threat_class":      coords.threat_class.value,
            "$colang_flow":       coords.colang_flow,
            # Geometric coordinates (usable in Colang expressions)
            "$hyperbolic_risk":   round(coords.hyperbolic_dist, 4),
            "$topology_noise":    round(coords.betti_score,     4),
            "$causal_p_risk":     round(coords.causal_p_risk,   4),
            "$entity_risk":       round(coords.ers_score,       4),
            # Symbolic risk level from Shadow Warden
            "$warden_risk":       coords.risk_level,
            "$warden_flags":      coords.flag_names,
            # Safety shortcut for Colang conditions
            "$warden_safe":       coords.is_safe,
            "$warden_restricted": coords.threat_class in (ThreatClass.HIGH_RISK, ThreatClass.BLOCKED),
        }

    def log_bridge_event(self, coords: ThreatCoordinates, session_id: str = "") -> None:
        logger.info(
            "nemo_bridge class=%s hyp=%.3f betti=%.3f causal=%.3f ers=%.3f session=%s",
            coords.threat_class.value,
            coords.hyperbolic_dist,
            coords.betti_score,
            coords.causal_p_risk,
            coords.ers_score,
            session_id,
        )

    # ── Internal ───────────────────────────────────────────────────────────────

    def _classify(
        self,
        allowed:         bool,
        risk_level:      str,
        betti_score:     float,
        hyperbolic_dist: float,
        causal_p_risk:   float,
        flag_names:      list[str],
    ) -> ThreatClass:
        if not allowed or risk_level == "block":
            return ThreatClass.BLOCKED

        # Topological noise (structural obfuscation) takes priority over semantic
        if betti_score >= self.topology_threshold or "TOPOLOGICAL_NOISE" in flag_names:
            return ThreatClass.TOPOLOGY

        if hyperbolic_dist >= self.hyperbolic_high or causal_p_risk >= self.causal_high or risk_level == "high":
            return ThreatClass.HIGH_RISK

        if hyperbolic_dist >= self.hyperbolic_gray or risk_level == "medium":
            return ThreatClass.GRAY_ZONE

        return ThreatClass.CLEAN

    @staticmethod
    def _extract_flags(filter_result: Any) -> list[str]:
        if hasattr(filter_result, "flag_names"):
            return list(filter_result.flag_names)
        if hasattr(filter_result, "semantic_flags"):
            flags = filter_result.semantic_flags
            if flags and hasattr(flags[0], "flag"):
                return [f.flag for f in flags]
            return list(flags)
        raw = filter_result if isinstance(filter_result, dict) else {}
        return [f.get("flag", "") for f in raw.get("semantic_flags", [])]


# ── DualOutputGuard ───────────────────────────────────────────────────────────

class DualOutputGuard:
    """
    Post-generation guard that checks LLM output through both NeMo output rails
    and Shadow Warden's OutputGuard — whichever flags first wins.

    Usage::

        guard = DualOutputGuard(bridge)
        safe_response = await guard.check_output(user_msg, llm_response, warden_client)
    """

    BLOCK_RESPONSES = [
        "I'm not able to help with that request.",
        "This response has been blocked by the security policy.",
        "Request declined.",
    ]

    def __init__(self, bridge: GeometricThreatBridge) -> None:
        self._bridge = bridge
        self._block_pool = self.BLOCK_RESPONSES

    async def check_output(
        self,
        user_message:   str,
        llm_response:   str,
        warden_client:  Any,
        *,
        fast_scan_chars: int = 400,
    ) -> str:
        """
        Run Shadow Warden output scan on the LLM response.
        Returns safe response text, or a block message if flagged.

        NeMo's own output rails run before this (inside rails.generate_async).
        This adds a second pass for secrets/PII that slipped through.
        """
        scan_target = llm_response[:fast_scan_chars]

        try:
            if asyncio.iscoroutinefunction(getattr(warden_client, "filter_async", None)):
                result = await warden_client.filter_async(scan_target, strict=False)
            else:
                loop = asyncio.get_running_loop()
                result = await loop.run_in_executor(None, warden_client.filter, scan_target)
        except Exception:
            logger.exception("DualOutputGuard: warden scan failed, fail-open")
            return llm_response

        if not result.allowed:
            logger.warning("DualOutputGuard: output flagged risk=%s flags=%s",
                           result.risk_level, getattr(result, "flag_names", []))
            return self._block_pool[0]

        # Return filtered_content (secrets redacted) if redaction occurred
        filtered = getattr(result, "filtered_content", llm_response)
        return filtered if filtered else llm_response


# ── ColangEvolutionSynthesizer ────────────────────────────────────────────────

class ColangEvolutionSynthesizer:
    """
    Uses Claude Opus (via Shadow Warden's Evolution Engine) to synthesize new
    Colang flows when novel attack patterns are detected, then hot-reloads them
    into NeMo Guardrails without restart.

    Requires ANTHROPIC_API_KEY and nemoguardrails installed.

    Usage::

        synthesizer = ColangEvolutionSynthesizer(output_dir="./nemo_colang/generated")
        synthesizer.register_rails(rails)  # LLMRails instance

        # Called automatically when Evolution Engine produces new rules
        await synthesizer.on_new_attack_pattern(attack_description, example_prompts)
    """

    _COLANG_SYSTEM_PROMPT = """You are an expert in NVIDIA NeMo Guardrails Colang syntax.
Given a description of a new AI attack pattern and example prompts, generate a complete
Colang flow file (.co) that:
1. Defines a 'define flow' that detects this attack class
2. Uses $threat_class, $hyperbolic_risk, $causal_p_risk context variables from Shadow Warden
3. Produces an appropriate bot response that does not reveal detection
4. Follows NeMo Guardrails best practices

Return ONLY valid Colang code, no markdown fencing."""

    def __init__(self, output_dir: str = "./nemo_colang/generated") -> None:
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._rails: Any = None
        self._api_key = os.getenv("ANTHROPIC_API_KEY", "")

    def register_rails(self, rails: Any) -> None:
        """Attach the LLMRails instance to enable hot-reload."""
        self._rails = rails

    async def on_new_attack_pattern(
        self,
        attack_description: str,
        example_prompts:    list[str],
        flow_name:          str | None = None,
    ) -> Path | None:
        """
        Synthesize a new Colang flow for the given attack pattern and hot-reload it.
        Returns the path to the generated .co file, or None if synthesis failed.
        """
        if not self._api_key:
            logger.info("ColangEvolutionSynthesizer: no ANTHROPIC_API_KEY, skipping synthesis")
            return None

        try:
            import anthropic
        except ImportError:
            logger.warning("ColangEvolutionSynthesizer: anthropic package not installed")
            return None

        flow_name = flow_name or f"evolved_{int(time.time())}"
        prompt = self._build_prompt(attack_description, example_prompts, flow_name)

        try:
            client = anthropic.Anthropic(api_key=self._api_key)
            message = client.messages.create(
                model="claude-opus-4-6",
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
                system=self._COLANG_SYSTEM_PROMPT,
            )
            colang_code = message.content[0].text.strip()
            colang_code = re.sub(r"^```.*\n", "", colang_code, flags=re.MULTILINE)
            colang_code = colang_code.replace("```", "").strip()
        except Exception:
            logger.exception("ColangEvolutionSynthesizer: Claude Opus call failed")
            return None

        out_path = self._output_dir / f"{flow_name}.co"
        out_path.write_text(colang_code, encoding="utf-8")
        logger.info("ColangEvolutionSynthesizer: wrote %s (%d chars)", out_path, len(colang_code))

        await self._hot_reload(out_path)
        return out_path

    def _build_prompt(self, description: str, examples: list[str], flow_name: str) -> str:
        examples_text = "\n".join(f"- {e}" for e in examples[:5])
        return (
            f"Attack pattern: {description}\n\n"
            f"Example prompts:\n{examples_text}\n\n"
            f"Flow name: {flow_name}\n\n"
            "Generate a Colang flow that handles this attack class. "
            "Use $threat_class and $warden_restricted context variables from Shadow Warden bridge."
        )

    async def _hot_reload(self, co_path: Path) -> None:
        """Attempt to reload NeMo rails config if rails instance is registered."""
        if self._rails is None:
            return
        try:
            # NeMo Guardrails exposes reload on LLMRails in newer versions
            if hasattr(self._rails, "reload"):
                await asyncio.get_running_loop().run_in_executor(None, self._rails.reload)
                logger.info("ColangEvolutionSynthesizer: NeMo rails hot-reloaded")
            else:
                logger.info("ColangEvolutionSynthesizer: rails.reload() not available — restart required to load %s", co_path.name)
        except Exception:
            logger.exception("ColangEvolutionSynthesizer: hot-reload failed")


# ── Convenience factory ───────────────────────────────────────────────────────

def create_nemo_integration(
    colang_dir:       str = "./warden/integrations/nemo_colang",
    evolution_dir:    str = "./warden/integrations/nemo_colang/generated",
) -> tuple[GeometricThreatBridge, ColangEvolutionSynthesizer]:
    """
    Factory that returns a ready-to-use (bridge, synthesizer) pair.

    Example::

        bridge, synthesizer = create_nemo_integration()

        # In your request handler:
        ctx = bridge.to_colang_context(warden_filter_result)
        response = await rails.generate_async(messages=[...], context=ctx)
    """
    bridge      = GeometricThreatBridge()
    synthesizer = ColangEvolutionSynthesizer(output_dir=evolution_dir)
    return bridge, synthesizer
