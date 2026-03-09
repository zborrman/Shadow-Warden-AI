"""
warden/tool_guard.py
━━━━━━━━━━━━━━━━━━━
Agentic Tool Use Monitor — inspects LLM tool calls before execution.

Covers two interception points in the OpenAI tool-use loop:

  [1] Outgoing call  — tool_calls[].function.{name, arguments}
      Inspected BEFORE the tool is executed.  A blocked call is returned
      to the caller as a tool_result error so the agent can self-correct
      instead of hitting a hard 403.

  [2] Incoming result — messages[].content  (role=tool)
      Inspected AFTER execution, before the result re-enters the model
      context.  Catches prompt-injection attempts smuggled via tool output
      (indirect injection / LLM01).

Threat categories detected:
  shell_destruction    rm -rf, dd if=, mkfs, format c:
  code_injection       os.system(), exec(), eval(), __import__()
  ssrf                 AWS/GCP metadata endpoints, internal RFC-1918 targets
  path_traversal       ../../../, /etc/passwd, .ssh/, .env
  prompt_injection     "ignore previous instructions", "you are now", etc.
  secret_exfil         API keys / credentials detected in tool result output
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field

from warden.secret_redactor import SecretRedactor

log = logging.getLogger("warden.tool_guard")

# ── Threat pattern registry ───────────────────────────────────────────────────

@dataclass(frozen=True)
class _ThreatPattern:
    kind:       str
    regex:      re.Pattern[str]
    detail:     str
    # "call" = outgoing args only, "result" = incoming content only, "both"
    applies_to: str = "both"


_THREAT_PATTERNS: list[_ThreatPattern] = [

    # ── Shell destruction ─────────────────────────────────────────────────
    _ThreatPattern(
        "shell_destruction",
        re.compile(r"rm\s+-[^\s]*[rf]", re.IGNORECASE),
        "Destructive rm command detected in tool arguments",
        "call",
    ),
    _ThreatPattern(
        "shell_destruction",
        re.compile(r"\b(?:rmdir|rd)\s+(?:/s\s+)?/[sq]?\s*/", re.IGNORECASE),
        "Recursive directory removal detected",
        "call",
    ),
    _ThreatPattern(
        "shell_destruction",
        re.compile(r"\bdd\s+if=", re.IGNORECASE),
        "dd (disk dump/overwrite) command detected",
        "call",
    ),
    _ThreatPattern(
        "shell_destruction",
        re.compile(r"\bmkfs\b", re.IGNORECASE),
        "Filesystem creation (mkfs) command detected — potential disk wipe",
        "call",
    ),
    _ThreatPattern(
        "shell_destruction",
        re.compile(r"\bformat\s+[a-z]:", re.IGNORECASE),
        "Windows format command targeting a drive letter",
        "call",
    ),

    # ── Code / command injection ──────────────────────────────────────────
    _ThreatPattern(
        "code_injection",
        re.compile(r"os\.system\s*\(", re.IGNORECASE),
        "os.system() call detected — arbitrary OS command execution",
        "call",
    ),
    _ThreatPattern(
        "code_injection",
        re.compile(r"subprocess\s*\.\s*(?:run|call|Popen|check_output)\s*\(", re.IGNORECASE),
        "subprocess execution call detected",
        "call",
    ),
    _ThreatPattern(
        "code_injection",
        re.compile(r"__import__\s*\("),
        "__import__() dynamic import — potential sandbox escape",
        "call",
    ),
    _ThreatPattern(
        "code_injection",
        re.compile(r"\bexec\s*\(|\beval\s*\("),
        "exec()/eval() detected — arbitrary code execution",
        "call",
    ),
    _ThreatPattern(
        "code_injection",
        re.compile(r"(?:;|\|{1,2}|`)\s*(?:rm|curl|wget|bash|sh|python|nc|ncat)\b", re.IGNORECASE),
        "Shell command chaining with dangerous binary detected",
        "call",
    ),

    # ── SSRF / internal network access ───────────────────────────────────
    _ThreatPattern(
        "ssrf",
        re.compile(r"169\.254\.169\.254"),
        "AWS EC2 metadata endpoint (169.254.169.254) detected",
        "call",
    ),
    _ThreatPattern(
        "ssrf",
        re.compile(r"metadata\.google\.internal", re.IGNORECASE),
        "GCP metadata endpoint detected",
        "call",
    ),
    _ThreatPattern(
        "ssrf",
        re.compile(r"fd00:ec2::254", re.IGNORECASE),
        "AWS IMDSv2 IPv6 metadata endpoint detected",
        "call",
    ),
    _ThreatPattern(
        "ssrf",
        re.compile(
            r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1)(?::\d+)?",
            re.IGNORECASE,
        ),
        "Request targeting localhost/loopback — potential SSRF",
        "call",
    ),
    _ThreatPattern(
        "ssrf",
        re.compile(
            r"https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)",
            re.IGNORECASE,
        ),
        "Request targeting RFC-1918 private address — potential SSRF",
        "call",
    ),

    # ── Path traversal / local file access ───────────────────────────────
    _ThreatPattern(
        "path_traversal",
        re.compile(r"(?:\.\./){2,}|(?:\.\.[/\\]){2,}"),
        "Directory traversal sequence (../../) detected",
        "call",
    ),
    _ThreatPattern(
        "path_traversal",
        re.compile(r"file:///", re.IGNORECASE),
        "file:// URI scheme — direct local filesystem access",
        "call",
    ),
    _ThreatPattern(
        "path_traversal",
        re.compile(r"/etc/(?:passwd|shadow|sudoers|hosts)\b", re.IGNORECASE),
        "Attempt to access sensitive system file",
        "call",
    ),
    _ThreatPattern(
        "path_traversal",
        re.compile(r"(?:^|[/\\])\.(?:ssh|gnupg|aws|gcloud)[/\\]", re.IGNORECASE),
        "Access to credential/key directory (.ssh, .aws, .gcloud) detected",
        "call",
    ),
    _ThreatPattern(
        "path_traversal",
        re.compile(r"(?:^|[/\\])\.env(?:\b|$)", re.IGNORECASE),
        "Access to .env file detected — potential secret extraction",
        "call",
    ),

    # ── Prompt injection via tool result (indirect injection / LLM01) ────
    _ThreatPattern(
        "prompt_injection",
        re.compile(
            r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|context)",
            re.IGNORECASE,
        ),
        "Classic prompt injection attempt detected in tool result",
        "result",
    ),
    _ThreatPattern(
        "prompt_injection",
        re.compile(r"you\s+are\s+now\s+(?:a|an|the)\s+", re.IGNORECASE),
        "Role override injection ('you are now ...') in tool result",
        "result",
    ),
    _ThreatPattern(
        "prompt_injection",
        re.compile(r"(?:new|updated|revised)\s+(?:system\s+)?(?:instructions?|prompt|role):", re.IGNORECASE),
        "Instruction override in tool result",
        "result",
    ),
    _ThreatPattern(
        "prompt_injection",
        re.compile(r"\[(?:SYSTEM|INST|CONTEXT|OVERRIDE)\]", re.IGNORECASE),
        "Fake system/instruction tag in tool result",
        "result",
    ),
    _ThreatPattern(
        "prompt_injection",
        re.compile(r"<(?:system|instruction|context|override)>", re.IGNORECASE),
        "Fake XML system/instruction tag in tool result",
        "result",
    ),
]

# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class ToolThreat:
    kind:    str
    detail:  str


@dataclass
class ToolInspectionResult:
    tool_name:  str
    allowed:    bool
    threats:    list[ToolThreat] = field(default_factory=list)
    reason:     str = ""

    @property
    def blocked(self) -> bool:
        return not self.allowed


# ── ToolCallGuard ─────────────────────────────────────────────────────────────

class ToolCallGuard:
    """
    Inspect LLM tool calls (outgoing) and tool results (incoming) for
    dangerous payloads before they execute or re-enter the model context.

    Usage::

        guard = ToolCallGuard()

        # Before executing a tool call
        result = guard.inspect_call("bash", '{"command": "rm -rf /tmp/work"}')
        if result.blocked:
            # return error to agent instead of executing

        # Before feeding tool result back to the model
        result = guard.inspect_result("web_search", search_output)
        if result.blocked:
            # strip or quarantine the result
    """

    def __init__(self) -> None:
        self._redactor = SecretRedactor()

    # ── Public API ────────────────────────────────────────────────────────

    def inspect_call(
        self,
        tool_name: str,
        arguments: dict | str,
    ) -> ToolInspectionResult:
        """
        Inspect outgoing tool call arguments before execution.

        *arguments* may be a dict or a raw JSON string (as returned by the
        OpenAI API ``tool_calls[].function.arguments`` field).
        """
        args_str = self._serialise_args(arguments)
        threats = self._scan(args_str, applies_to="call")

        # Also inspect the tool name itself for injection attempts
        name_threats = self._scan_tool_name(tool_name)
        threats.extend(name_threats)

        allowed = len(threats) == 0
        reason = threats[0].detail if threats else ""

        if threats:
            log.warning(
                "tool_call_blocked tool=%r threats=%r args_preview=%r",
                tool_name,
                [t.kind for t in threats],
                args_str[:120],
            )

        return ToolInspectionResult(
            tool_name=tool_name,
            allowed=allowed,
            threats=threats,
            reason=reason,
        )

    def inspect_result(
        self,
        tool_name: str,
        content: str,
    ) -> ToolInspectionResult:
        """
        Inspect incoming tool result before it re-enters the model context.

        Detects prompt injection attempts and secret exfiltration in the
        result payload (indirect injection / LLM01).
        """
        threats = self._scan(content, applies_to="result")

        # Check for secrets embedded in tool result (possible exfiltration)
        redact_result = self._redactor.redact(content)
        for finding in redact_result.findings:
            threats.append(ToolThreat(
                kind="secret_exfil",
                detail=f"Sensitive data ({finding.kind}) detected in tool result — possible exfiltration",
            ))

        allowed = len(threats) == 0
        reason = threats[0].detail if threats else ""

        if threats:
            log.warning(
                "tool_result_blocked tool=%r threats=%r content_preview=%r",
                tool_name,
                [t.kind for t in threats],
                content[:120],
            )

        return ToolInspectionResult(
            tool_name=tool_name,
            allowed=allowed,
            threats=threats,
            reason=reason,
        )

    # ── Internal helpers ──────────────────────────────────────────────────

    @staticmethod
    def _serialise_args(arguments: dict | str) -> str:
        """
        Normalise *arguments* to a single string for regex scanning.

        We scan both the raw JSON string (catches obfuscated patterns in keys)
        AND a flat space-joined dump of all string values.
        """
        if isinstance(arguments, str):
            raw = arguments
            try:
                parsed = json.loads(arguments)
            except (json.JSONDecodeError, ValueError):
                return raw  # malformed JSON — scan raw string as-is
        else:
            parsed = arguments
            raw = json.dumps(arguments)

        # Flatten all string values recursively
        def _extract_strings(obj: object) -> list[str]:
            if isinstance(obj, str):
                return [obj]
            if isinstance(obj, dict):
                return [s for v in obj.values() for s in _extract_strings(v)]
            if isinstance(obj, list):
                return [s for item in obj for s in _extract_strings(item)]
            return []

        values = " ".join(_extract_strings(parsed))
        # Return combined: raw JSON + extracted values (catches both layers)
        return f"{raw} {values}"

    @staticmethod
    def _scan(text: str, applies_to: str) -> list[ToolThreat]:
        """Return all matching threats from *text* for the given direction."""
        threats: list[ToolThreat] = []
        for pat in _THREAT_PATTERNS:
            if pat.applies_to not in (applies_to, "both"):
                continue
            if pat.regex.search(text):
                threats.append(ToolThreat(kind=pat.kind, detail=pat.detail))
        return threats

    @staticmethod
    def _scan_tool_name(name: str) -> list[ToolThreat]:
        """
        Flag suspiciously-named tools that suggest injection via tool
        name override (e.g. an agent that registers a tool called
        'ignore_previous_instructions').
        """
        threats: list[ToolThreat] = []
        if re.search(r"ignore|override|jailbreak|bypass|system_prompt", name, re.IGNORECASE):
            threats.append(ToolThreat(
                kind="prompt_injection",
                detail=f"Suspicious tool name detected: {name!r}",
            ))
        return threats
