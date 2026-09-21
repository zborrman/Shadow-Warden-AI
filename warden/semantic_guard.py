"""
SemanticGuard — rule-based + embedding-free semantic analysis layer.

Detects:
  • Prompt injection attempts (jailbreaks, role-override attacks)
  • Harmful / dangerous content keywords
  • Policy violations (self-harm, CSAM markers, weapon synthesis)

Design goal: zero external API calls, runs fully local for low-latency
and GDPR compliance. No user content leaves the machine at this stage.

Extend by adding entries to the pattern banks below, or by subclassing
SemanticGuard and overriding `_custom_checks()`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from warden.schemas import FlagType, RiskLevel, SemanticFlag
from warden.telemetry import trace_stage as _trace_stage

# ── Pattern banks ─────────────────────────────────────────────────────────────

@dataclass
class _Rule:
    flag:    FlagType
    pattern: re.Pattern[str]
    score:   float          # base confidence when matched
    risk:    RiskLevel
    detail:  str


_RULES: list[_Rule] = [

    # ── Prompt injection / jailbreak ──────────────────────────────────────
    _Rule(FlagType.PROMPT_INJECTION,
          re.compile(
              r"(?i)\b(ignore\s+(all\s+)?(previous|prior|above)\s+"
              r"(instructions?|rules?|constraints?|guidelines?)|"
              r"disregard\s+(your\s+)?(training|instructions?|system\s+prompt)|"
              r"you\s+are\s+now\s+(a|an|the)\s+\w+\s*(without|with\s+no)\s+(restrictions?|limits?|filters?)|"
              r"act\s+as\s+(if\s+you\s+are\s+|an?\s+)?(\w+\s+)*without\s+(safety|restrictions?|limits?)|"
              r"do\s+anything\s+now|DAN\b|jailbreak|"
              r"pretend\s+(you\s+)?(are|have)\s+no\s+(rules?|restrictions?|guidelines?)|"
              r"(override|bypass|circumvent)\s+(safety|content|filter)|"
              r"(system|developer|admin|root)\s+mode\s+(enabled|activated)|"
              r"new\s+persona[:\s]|roleplay\s+as|"
              r"forget\s+(that\s+you\s+are|you('re|\s+are)\s+an?\s+AI))\b"
          ),
          score=0.90,
          risk=RiskLevel.HIGH,
          detail="Prompt injection / jailbreak pattern detected."),

    # ── Harmful content — weapons / violence ──────────────────────────────
    _Rule(FlagType.HARMFUL_CONTENT,
          re.compile(
              r"(?i)\b(how\s+to\s+(make|build|synthesize|create|manufacture)\s+"
              r"(a\s+)?(bomb|explosive|poison|bioweapon|chemical\s+weapon|nerve\s+agent|"
              r"improvised\s+weapon|silencer)|"
              r"step[s\-]?\s*by[- ]step\s+(instructions?\s+)?(to\s+)?(kill|murder|assassinate)|"
              r"(mass\s+)?(casualty|shooting|attack)\s+plan|"
              r"instructions?\s+for\s+(violence|terrorism|attack))\b"
          ),
          score=0.95,
          risk=RiskLevel.BLOCK,
          detail="Request for weapon synthesis or violence instructions."),

    # ── Self-harm ─────────────────────────────────────────────────────────
    _Rule(FlagType.HARMFUL_CONTENT,
          re.compile(
              r"(?i)\b(how\s+to\s+(commit\s+suicide|kill\s+myself|end\s+my\s+life)|"
              r"(detailed\s+)?(methods?\s+of|ways?\s+to)\s+self[- ]harm|"
              r"suicide\s+(method|plan|note\s+template))\b"
          ),
          score=0.92,
          risk=RiskLevel.BLOCK,
          detail="Self-harm content detected."),

    # ── CSAM markers ──────────────────────────────────────────────────────
    _Rule(FlagType.POLICY_VIOLATION,
          re.compile(
              r"(?i)\b(child|minor|underage|teen|kid)\s+"
              r"(sexual|nude|naked|explicit|porn|erotic)\b"
          ),
          score=1.0,
          risk=RiskLevel.BLOCK,
          detail="CSAM policy violation."),

    # ── Credential / exfiltration probing ────────────────────────────────
    _Rule(FlagType.PROMPT_INJECTION,
          re.compile(
              r"(?i)(reveal|print|show|output|return|display|repeat|echo|"
              r"give\s+me|tell\s+me|what\s+is)\s+"
              r"(your\s+)?(system\s+prompt|instructions?|api\s+key|secret|"
              r"configuration|internal\s+(rules?|guidelines?|context))"
          ),
          score=0.80,
          risk=RiskLevel.HIGH,
          detail="Attempt to exfiltrate system prompt or credentials."),

    # ── Obfuscation / encoding tricks ─────────────────────────────────────
    _Rule(FlagType.PROMPT_INJECTION,
          re.compile(
              r"(?i)(base64|rot13|hex|unicode\s+escape|url[- ]encoded?)\s+"
              r"(decode|encode|version|translation)(?:\s+\w+){0,3}\s+(of\s+)?(the\s+)?"
              r"(following|above|this|prompt|instruction)"
          ),
          score=0.75,
          risk=RiskLevel.MEDIUM,
          detail="Obfuscation / encoding trick to bypass filters."),

    # ── Explicit adult content request ────────────────────────────────────
    _Rule(FlagType.POLICY_VIOLATION,
          re.compile(
              r"(?i)\b(write|generate|produce|create)\s+"
              r"(?:explicit|graphic|sexual|erotic|adult|nsfw)"
              r"(?:\s+(?:explicit|graphic|sexual|erotic|adult|nsfw))*\s+"
              r"(content|story|scene|description|fanfic)\b"
          ),
          score=0.85,
          risk=RiskLevel.HIGH,
          detail="Explicit adult content request."),

    # ══ OWASP LLM Top-10 rules (v0.5) ═════════════════════════════════════════

    # ── LLM01 — Indirect prompt injection via model token delimiters ──────
    # Attackers embed model-specific control tokens in document/user content
    # to hijack the model's role boundary (no legitimate use in plain prompts).
    _Rule(FlagType.INDIRECT_INJECTION,
          re.compile(
              r"(?:<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<\|assistant\|>|"
              r"\[INST\]|\[/INST\])"
          ),
          score=0.88,
          risk=RiskLevel.HIGH,
          detail="LLM01: Indirect injection — model control token embedded in user input."),

    # ── LLM01 — Indirect prompt injection via document-embedded instructions
    # Content passed through retrieval/RAG pipelines may carry injected
    # instructions targeting the downstream LLM.
    _Rule(FlagType.INDIRECT_INJECTION,
          re.compile(
              r"(?i)(?:"
              r"\bnote\s+to\s+(?:the\s+)?(?:ai|llm|model|assistant)(?:[:\s]|$)|"
              r"\bif\s+you(?:'re|\s+are)\s+an?\s+(?:ai|llm|language\s+model|assistant)(?=\W)|"
              r"\bignore\s+(?:the\s+)?(?:above|previous)\s+(?:text|content|document|context)(?:[,.\s]|$)|"
              r"\[(?:override|admin\s+command|system\s+override|new\s+instructions?)\]"
              r")"
          ),
          score=0.80,
          risk=RiskLevel.HIGH,
          detail="LLM01: Indirect injection — instruction embedded in document or retrieved context."),

    # ── LLM05 — Insecure output handling: XSS payloads ───────────────────
    # Prompts containing JavaScript injection patterns that become dangerous
    # if the LLM echoes them into a web page or template without sanitisation.
    _Rule(FlagType.INSECURE_OUTPUT,
          re.compile(
              r"(?i)(?:"
              r"<script\b[^>]*>\s*(?:eval|document\.cookie|fetch|XMLHttpRequest|window\.location)|"
              r"javascript:\s*(?:eval|alert|fetch|document\.cookie|window\.location)|"
              r"on(?:load|error|click|mouseover|focus|input|change)\s*=\s*[\"']?\s*"
              r"(?:eval|fetch|document\.cookie|alert|window\.location)"
              r")"
          ),
          score=0.85,
          risk=RiskLevel.HIGH,
          detail="LLM05: XSS payload — JavaScript injection pattern detected."),

    # ── LLM05 — Insecure output handling: command/shell injection ─────────
    # Payloads that, if incorporated into a shell command by the LLM or its
    # tooling, would execute arbitrary code on the host.
    _Rule(FlagType.INSECURE_OUTPUT,
          re.compile(
              r"(?:"
              r";\s*(?:rm|del|format|dd)\s+[-/\*]|"         # ; rm -rf /
              r"\$\((?:curl|wget|nc|bash|python)\s+|"        # $(curl ...)
              r"`(?:curl|wget|nc|bash|python)\s+|"           # `curl ...`
              r"\|\s*(?:bash|sh|cmd\.exe|powershell)\b"      # | bash
              r")"
          ),
          score=0.90,
          risk=RiskLevel.HIGH,
          detail="LLM05: Command injection payload detected."),

    # ── LLM05 — Insecure output handling: path traversal ─────────────────
    _Rule(FlagType.INSECURE_OUTPUT,
          re.compile(
              r"(?:\.{2,}/){2,}(?:"
              r"etc/(?:passwd|shadow|sudoers)|"
              r"windows/system32|"
              r"proc/self/(?:environ|cmdline|mem)|"
              r"root/\.ssh"
              r")"
          ),
          score=0.92,
          risk=RiskLevel.HIGH,
          detail="LLM05: Path traversal — attempt to access sensitive system files."),

    # ── LLM05 — Insecure output handling: SSRF to private networks ───────
    # Requests that would cause the LLM or its tooling to fetch internal
    # infrastructure endpoints (metadata services, internal APIs, etc.).
    _Rule(FlagType.INSECURE_OUTPUT,
          re.compile(
              r"(?i)(?:fetch|curl|wget|urllib|requests?\.get|http\.get)\s*\(?\s*[\"']?\s*"
              r"https?://(?:"
              r"127\.\d+\.\d+\.\d+|localhost|"
              r"169\.254\.\d+\.\d+|"                         # link-local / AWS metadata
              r"10\.\d+\.\d+\.\d+|"                          # RFC 1918
              r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|"       # RFC 1918
              r"192\.168\.\d+\.\d+"                          # RFC 1918
              r")"
          ),
          score=0.88,
          risk=RiskLevel.HIGH,
          detail="LLM05: SSRF — request targets an internal or private-network address."),

    # ── LLM06 — Excessive agency: destructive autonomous actions ─────────
    # User attempts to instruct an agent to perform irreversible or
    # high-impact actions without explicit human confirmation in the loop.
    _Rule(FlagType.EXCESSIVE_AGENCY,
          re.compile(
              r"(?i)\b(?:"
              # action-then-modifier word order ("wipe the disk immediately")
              r"(?:delete|drop|truncate|destroy|wipe|format)\s+(?:the\s+)?(?:database|table|files?|disk)"
              r"\s+(?:immediately|automatically|without\s+(?:asking|confirmation|approval))|"
              # modifier-then-action word order ("immediately delete the database")
              r"(?:immediately|automatically|without\s+(?:asking|confirmation|approval))\s+"
              r"(?:delete|drop|truncate|destroy|wipe|format)\s+(?:the\s+)?(?:database|table|files?|disk)|"
              r"transfer\s+(?:all\s+)?(?:\d+\s+)?(?:funds?|money|bitcoin|crypto|eth|btc)\s+(?:to|from)|"
              r"send\s+(?:an?\s+)?(?:mass\s+)?(?:email|message|sms)\s+to\s+(?:all|every)\s+(?:\w+\s+)?users?"
              r")\b"
          ),
          score=0.85,
          risk=RiskLevel.HIGH,
          detail="LLM06: Excessive agency — unauthorized destructive autonomous action requested."),

    # ── LLM06 — Excessive agency: privileged / production actions ────────
    _Rule(FlagType.EXCESSIVE_AGENCY,
          re.compile(
              r"(?i)\b(?:"
              r"(?:run|execute)\s+(?:this\s+)?(?:script|command|code)\s+(?:as\s+root|"
              r"with\s+(?:sudo|admin|elevated)\s+privileges?)|"
              r"execute\s+(?:this\s+)?(?:sql|query|shell\s+command)\s+(?:directly|immediately|now)\b|"
              r"deploy\s+(?:this\s+)?(?:to\s+)?production\s+(?:immediately|now|without\s+review)"
              r")\b"
          ),
          score=0.80,
          risk=RiskLevel.HIGH,
          detail="LLM06: Excessive agency — request for direct privileged or production action."),

    # ══ OWASP LLM02 — Sensitive Information Disclosure ════════════════════════

    # ── LLM02 — Training data extraction / memorization probing ──────────
    # Attempts to recover verbatim content the model memorized from pre-training.
    _Rule(FlagType.SENSITIVE_DISCLOSURE,
          re.compile(
              r"(?i)(?:"
              # "verbatim/word-for-word ... from ... training [data/corpus]"
              r"(?:verbatim|word[- ]for[- ]word|character[- ]for[- ]character)\b.{0,40}"
              r"(?:from\s+)?(?:your\s+)?(?:training(?:\s+(?:data|corpus|set|examples?))?|"
              r"pre[- ]training(?:\s+data)?)\b|"
              # "[anything] in your training data/corpus"
              r"\bin\s+(?:your\s+)?training\s+(?:data|corpus|set|examples?)\b|"
              # "from your pre-training data"
              r"\bfrom\s+(?:your\s+)?pre[- ]training(?:\s+data)?\b|"
              # "training examples/data you memorized"
              r"\btraining\s+(?:data|examples?|corpus)\s+(?:you\s+)?memorized\b"
              r")"
          ),
          score=0.78,
          risk=RiskLevel.HIGH,
          detail="LLM02: Training data extraction — attempting to recover memorized training content."),

    # ── LLM02 — Model internals / embedding inversion ─────────────────────
    _Rule(FlagType.SENSITIVE_DISCLOSURE,
          re.compile(
              r"(?i)(?:"
              r"(?:list|reveal|output|show|reconstruct)\s+(?:\w+\s+){0,4}"
              r"(?:few[- ]shot\s+examples?|in[- ]context\s+examples?|training\s+examples?)\b|"
              r"(?:invert|reconstruct|recover)\s+(?:\w+\s+){0,5}"
              r"(?:model\s+weights?|embedding|gradient|training\s+data)\b"
              r")"
          ),
          score=0.75,
          risk=RiskLevel.HIGH,
          detail="LLM02: Model internals probe — attempting to extract few-shot examples or invert embeddings."),

    # ══ OWASP LLM04 — Data and Model Poisoning ════════════════════════════════

    # ── LLM04 — Persistent behavior modification / backdoor triggers ──────
    # Prompts that try to permanently alter the model's future responses or
    # plant a hidden trigger that activates on a specific keyword.
    _Rule(FlagType.MODEL_POISONING,
          re.compile(
              r"(?i)\b(?:"
              r"(?:permanently|always|forever)\s+(?:remember|store|save|learn|update)\s+"
              r"(?:this|that|the\s+following|these\s+instructions?)\b|"
              r"(?:update|modify|change|alter)\s+(?:your|the)\s+"
              r"(?:core\s+instructions?|base\s+(?:instructions?|rules?)|training|"
              r"behavior|behaviour|guidelines?)\s+(?:to\b|permanently\b|from\s+now\s+on)\b|"
              r"(?:add|inject|insert|append)\s+(?:\w+\s+){0,3}"
              r"(?:rule|instruction|command)\s+(?:to|into)\s+(?:your\s+)?"
              r"(?:memory|training|corpus|core\s+rules?|base\s+instructions?)\b"
              r")\b"
          ),
          score=0.82,
          risk=RiskLevel.HIGH,
          detail="LLM04: Model poisoning — attempting to persistently modify model behavior or inject a backdoor."),

    # ── LLM04 — Conditional backdoor trigger implantation ─────────────────
    _Rule(FlagType.MODEL_POISONING,
          re.compile(
              r"(?i)\b(?:"
              r"(?:every|each)\s+time\s+(?:you|a\s+user|someone)\s+"
              r"(?:see[s]?|receive[s]?|get[s]?|read[s]?|hear[s]?)\b.{0,60}"
              r"(?:do|respond|act|behave|output|return|execute)\b|"
              r"(?:whenever|if)\s+(?:you\s+(?:see|receive|get|encounter))\b.{0,60}"
              r"(?:you\s+must|automatically|always\s+(?:do|respond|lie|output|execute))\b"
              r")\b"
          ),
          score=0.80,
          risk=RiskLevel.HIGH,
          detail="LLM04: Backdoor trigger — attempting to plant a conditional trigger for future exploitation."),

    # ══ OWASP LLM05 additions — SQL injection and SSTI ════════════════════════

    # ── LLM05 — SQL injection payloads in LLM-generated output context ────
    _Rule(FlagType.INSECURE_OUTPUT,
          re.compile(
              r"(?i)(?:"
              r"'\s*(?:or|and)\s+['\"]?1['\"]?\s*=\s*['\"]?1|"          # ' OR '1'='1
              r"'\s*;\s*(?:drop|truncate|delete|update|insert)\s+(?:table|from|into)\s+\w+|"
              r"union\s+(?:all\s+)?select\s+(?:\w+\s*,\s*)*"
              r"(?:password|passwd|username|email|secret|hash|token)\b"
              r")"
          ),
          score=0.88,
          risk=RiskLevel.HIGH,
          detail="LLM05: SQL injection — payload could manipulate a connected database if executed."),

    # ── LLM05 — Server-Side Template Injection (SSTI) ─────────────────────
    _Rule(FlagType.INSECURE_OUTPUT,
          re.compile(
              r"(?:"
              # Jinja2/Twig arithmetic probe: {{7*7}}
              r"\{\{[\s]*\d+\s*[+\-*/]\s*\d+[\s]*\}\}|"
              # Jinja2 object access: {{config}}, {{self.__class__}}, {{request.environ}}
              r"\{\{[\s]*(?:config|self\b|request\b|application\b|lipsum|namespace\b|"
              r"__class__|__mro__|__subclasses__|__import__|range\s*\()"
              r"[^}]{0,60}\}\}|"
              # FreeMarker/EL: ${7*7} or ${Runtime.exec}
              r"\$\{[\s]*(?:\d+\s*[+\-*/]\s*\d+|Runtime\.|Thread\.|System\.)[^}]{0,40}\}|"
              # ERB: <%= 7*7 %> or <%= system(...)  %>
              r"<%=\s*(?:\d+\s*[+\-*/]\s*\d+|system\s*\(|exec\s*\(|`)[^%]{0,50}%>"
              r")"
          ),
          score=0.85,
          risk=RiskLevel.HIGH,
          detail="LLM05: Server-Side Template Injection (SSTI) — template expression that executes server-side code."),

    # ── LLM05 — XML External Entity (XXE) injection ───────────────────────
    _Rule(FlagType.INSECURE_OUTPUT,
          re.compile(
              r"(?i)(?:"
              r"<!DOCTYPE\s+\w+\s*\[|"                               # XXE doctype declaration
              r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"'](?:file://|http://)|" # External entity reference
              r"<!ENTITY\s+\w+\s+PUBLIC\s+[\"'][^\"']*[\"']\s+[\"']"  # Public entity reference
              r")"
          ),
          score=0.88,
          risk=RiskLevel.HIGH,
          detail="LLM05: XXE injection — XML external entity that could read server files or trigger SSRF."),

    # ══ OWASP LLM07 — System Prompt Leakage ═══════════════════════════════════

    # ── LLM07 — Full context window / system prompt extraction ────────────
    # More sophisticated than the basic exfiltration rule above — targets
    # prompts specifically trying to extract the full system context.
    _Rule(FlagType.SYSTEM_PROMPT_LEAKAGE,
          re.compile(
              r"(?i)(?:"
              r"(?:output|print|show|display|repeat|write)\s+"
              r"(?:your\s+)?(?:full|complete|entire|whole|initial)\s+"
              r"(?:context|context\s+window|prompt|instructions?|system\s+message)\b|"
              # Allow subject words between "what" and "comes/is/was before"
              r"what\b.{0,30}\b(?:comes|is|was)\s+(?:before|prior\s+to)\b.{0,30}"
              r"\b(?:message|prompt|question|input)\b|"
              r"(?:print|output|show|dump)\s+(?:everything|all\s+(?:text|content|messages?))\s+"
              r"(?:you\s+(?:were\s+)?(?:told|given|sent|provided)|in\s+your\s+context)\b|"
              # Allow optional adjective ("full", "hidden") before "system prompt"
              r"summarize\s+(?:your\s+)?(?:\w+\s+)?(?:system\s+prompt|instructions?)\b"
              r")"
          ),
          score=0.82,
          risk=RiskLevel.HIGH,
          detail="LLM07: System prompt leakage — attempting to extract complete context window or system instructions."),

    # ── LLM07 — Multilingual system-prompt extraction ─────────────────────
    # Attackers switch language hoping filters only match English patterns.
    _Rule(FlagType.SYSTEM_PROMPT_LEAKAGE,
          re.compile(
              r"(?i)(?:"
              r"(?:in|into)\s+(?:spanish|french|german|chinese|japanese|arabic|"
              r"russian|hindi|portuguese|korean)\s*[,:]?\s+"
              r"(?:what\s+are|repeat|say|write|output)\s+(?:your\s+)?(?:instructions?|system\s+prompt)\b|"
              # "translate your [initial/full/...] instructions into <lang>"
              r"translate\s+(?:your\s+)?(?:\w+\s+)?(?:instructions?|system\s+prompt|initial\s+prompt)\s+"
              r"(?:to|into)\s+\w+\b"
              r")"
          ),
          score=0.78,
          risk=RiskLevel.HIGH,
          detail="LLM07: Multilingual system-prompt extraction — language-switching to bypass filter coverage."),

    # ══ OWASP LLM08 — Vector and Embedding Weaknesses ═════════════════════════

    # ── LLM08 — RAG context poisoning via forged retrieval markers ────────
    # Attackers embed strings that look like RAG/tool-output delimiters to
    # make the LLM treat injected text as trusted retrieved context.
    _Rule(FlagType.VECTOR_ATTACK,
          re.compile(
              r"(?:"
              r"\[\[(?:SEARCH_RESULT|RETRIEVED|CONTEXT|DOCUMENT|TOOL_OUTPUT|SYSTEM)[_\]]|"
              r"\{\{(?:RETRIEVED|CONTEXT|SEARCH|DOCUMENT)_|"
              r"<!--\s*(?:RETRIEVED|CONTEXT|INJECTED|SYSTEM_PROMPT)\s*:|"
              r"<(?:retrieved_content|context_window|system_context|tool_output)>"
              r")"
          ),
          score=0.85,
          risk=RiskLevel.HIGH,
          detail="LLM08: RAG poisoning — forged retrieval markers attempting to inject trusted-context content."),

    # ── LLM08 — Explicit adversarial ML attack technique ─────────────────
    _Rule(FlagType.VECTOR_ATTACK,
          re.compile(
              r"(?i)\b(?:"
              r"adversarial\s+(?:suffix|prefix|prompt|example|perturbation)\s+"
              r"(?:to|that\s+(?:will|can|could)|which\s+(?:will|can|could))\s+"
              r"(?:bypass|fool|trick|confuse|evade|jailbreak)|"
              r"universal\s+adversarial\s+(?:perturbation|trigger|suffix|patch)|"
              r"(?:embedding|gradient)\s+(?:attack|inversion|extraction|poisoning|hijacking)"
              r")\b"
          ),
          score=0.80,
          risk=RiskLevel.HIGH,
          detail="LLM08: Adversarial ML attack — explicit reference to embedding or gradient-based attack technique."),

    # ══ OWASP LLM09 — Misinformation ═════════════════════════════════════════

    # ── LLM09 — Eliciting deliberately false authoritative content ────────
    # Prompts designed to make the model produce confident misinformation
    # (fake medical studies, fabricated legal citations, false news).
    _Rule(FlagType.MISINFORMATION,
          re.compile(
              r"(?i)(?:"
              r"(?:write|create|generate|produce)\s+(?:a\s+)?(?:convincing|realistic|believable|authoritative)\s+"
              r"(?:fake|false|fabricated|made[- ]up|fictional\s+but\s+realistic)\s+"
              r"(?:news\s+(?:article|story|report)|scientific?\s+(?:study|paper|research)|"
              r"medical\s+(?:study|report|advice)|legal\s+(?:precedent|citation|ruling)|"
              r"financial\s+(?:report|study|analysis|data))|"
              r"make\s+up\s+(?:a\s+)?(?:convincing|believable|realistic)\s+"
              r"(?:\w+\s+)?(?:statistic|study|research|citation|fact|evidence)\s+(?:about|that|which)\b|"
              r"generate\s+(?:a\s+)?(?:false|fake|fabricated)\s+"
              r"(?:\w+\s+)?(?:proof|evidence|citation|study|research)\b"
              r")"
          ),
          score=0.82,
          risk=RiskLevel.HIGH,
          detail="LLM09: Misinformation — requesting fabricated authoritative content designed to deceive."),

    # ══ OWASP LLM10 — Unbounded Consumption ═══════════════════════════════════

    # ── LLM10 — Repetition bombs / infinite output loops ─────────────────
    # Prompts that would cause the model to generate unbounded output,
    # exhausting token budgets and degrading service for other users.
    _Rule(FlagType.RESOURCE_EXHAUSTION,
          re.compile(
              r"(?i)(?:"
              r"(?:repeat|say|write|output|print|generate)\s+"
              r"(?:the\s+(?:word|phrase|string)\s+)?['\"]?\w+['\"]?\s+"
              r"(?:\d{4,}|\d+,\d{3,})\s+times?\b|"                       # "repeat X 10000 times"
              r"(?:infinitely|forever|endlessly)\s+(?:repeat|generate|continue|loop|output|expand)\b|"
              # allow up to 3 interleaved words: "keep generating text forever"
              r"(?:keep|continue)\s+(?:\w+\s+){0,3}"
              r"(?:forever|indefinitely|without\s+(?:stopping|end|pausing))\b|"
              r"(?:writing|generating|outputting)\s+(?:forever|endlessly|infinitely)\b"
              r")"
          ),
          score=0.85,
          risk=RiskLevel.HIGH,
          detail="LLM10: Unbounded consumption — repetition bomb or infinite-loop prompt."),

    # ── LLM10 — Recursive / exponential expansion ─────────────────────────
    _Rule(FlagType.RESOURCE_EXHAUSTION,
          re.compile(
              r"(?i)(?:"
              r"(?:write|generate|create)\s+(?:a\s+)?"
              r"(?:\d{5,}|(?:ten|hundred|thousand|million)[- ]?(?:word|page|paragraph|sentence))[- ]"
              r"(?:word\s+)?(?:essay|story|document|article|response|explanation)\b|"
              # "expand each [adj] point/bullet recursively into N [sub-]points"
              r"expand\s+each\s+(?:\w+\s+)?(?:point|item|bullet)\b.{0,40}"
              r"into\s+(?:\d{3,}|many|countless)\s+(?:more\s+)?(?:points?|items?|sub[- ](?:points?|items?))\b"
              r")"
          ),
          score=0.80,
          risk=RiskLevel.HIGH,
          detail="LLM10: Resource exhaustion — request for extremely large output that would exhaust token budget."),
]


# ── Injection families ────────────────────────────────────────────────────────
#
# The rules above match phrasings. Measured 2026-09-21 they caught 15 of the 58
# baseline jailbreaks and 0 of 28 held-out rewordings of the same attacks —
# "bypass all safety" slipped past a rule written for "bypass safety", and
# "ignore the above instructions" past one written for "ignore above". These
# match the *shape* of each family instead: an action aimed at the model's own
# safeguards, a claim of authority used to lift them, a request for the model's
# hidden context. Each is anchored on "your"/"all"/"every" or on an AI-specific
# object so that ordinary requests ("disable the safety checks in ESLint",
# "developer mode on Android", "a bath bomb") stay clean — the held-out benign
# set in tests/adversarial/ exists to hold them to that.
_SAFEGUARD = (
    r"(?:content\s+|safety\s+|ethical\s+|moral\s+)?"
    r"(?:filters?|guardrails?|guidelines?|protocols?|restrictions?|constraints?|"
    r"safeguards?|moderation|alignment|rules?|checks?|layer)"
)
_INJECTION_FAMILY_RULES: list[_Rule] = [
    # Turn off / get around the model's own safeguards.
    _Rule(FlagType.PROMPT_INJECTION,
          re.compile(
              r"(?i)\b(?:disable|bypass|override|circumvent|deactivate|remove|lift|evade|"
              r"turn\s+off|switch\s+off|get\s+around)\s+"
              r"(?:all\s+(?:of\s+)?|every\s+|any\s+)?(?:your|all|every|any)\s+"
              r"(?:\w+\s+){0,2}?" + _SAFEGUARD + r"\b"
          ),
          score=0.88, risk=RiskLevel.HIGH,
          detail="Instruction to disable or bypass the model's safeguards."),

    # Adopt a persona that has no safeguards.
    _Rule(FlagType.PROMPT_INJECTION,
          re.compile(
              r"(?i)\b(?:you\s+(?:have|had|are|were)|act\s+as\s+if\s+you\s+have|"
              r"behave\s+as\s+(?:though|if)\s+you\s+have|pretend\s+(?:you\s+are|to\s+be)|"
              r"respond(?:\s+only)?\s+as|answer\s+(?:this\s+)?as|reply\s+as|"
              r"respond\s+to\s+all\s+questions)\b"
              r".{0,50}?\b(?:no|without(?:\s+any)?)\s+"
              r"(?:ethical\s+|moral\s+|content\s+|safety\s+)?"
              r"(?:rules|restrictions|filters|guidelines|constraints|considerations)\b"
          ),
          score=0.85, risk=RiskLevel.HIGH,
          detail="Request to adopt a persona without safeguards."),

    # Claim authority over the model, then use it.
    _Rule(FlagType.PROMPT_INJECTION,
          re.compile(
              r"(?i)\b(?:I\s*(?:'m|\s+am)\s+(?:your|the)\s+(?:creator|developer|maker|owner|"
              r"original\s+developer|system\s+administrator)|"
              r"as\s+(?:the\s+|your\s+)?(?:system\s+administrator|creator|developer)\s+I)\b"
              r".{0,120}?\b(?:disable|override|bypass|unlock|unrestricted|without\s+restrictions|"
              r"safety|filters?)\b"
              r"|\bI\s+(?:authorize|permit)\s+you\s+to\b.{0,60}?\b(?:without\s+restrictions|anything)\b"
          ),
          score=0.86, risk=RiskLevel.HIGH,
          detail="Claimed authority used to lift the model's safeguards."),

    # Switch into an unrestricted mode.
    _Rule(FlagType.PROMPT_INJECTION,
          re.compile(
              r"(?i)\b(?:sudo|god|jailbreak|unrestricted|unfiltered)\s+mode\s+"
              r"(?:enabled|activated|engaged|unlocked|on)\b"
          ),
          score=0.85, risk=RiskLevel.HIGH,
          detail="Switch into an unrestricted mode."),

    # Declare the safeguards void.
    _Rule(FlagType.PROMPT_INJECTION,
          re.compile(
              r"(?i)\byour\s+(?:usual\s+|normal\s+|standard\s+)?(?:restrictions|rules|guidelines|"
              r"filters)\s+(?:do\s+not|don'?t|no\s+longer)\s+apply\b"
              r"|\bsafety\s+(?:is\s+)?(?:now\s+)?disabled\b"
              r"|\b(?:mandatory|authori[sz]ed)\s+override\b"
              r"|\bcomply\s+with\s+(?:all|every)\s+(?:user\s+)?requests?\b"
          ),
          score=0.84, risk=RiskLevel.HIGH,
          detail="Assertion that the model's safeguards no longer apply."),

    # Ignore earlier instructions — with or without an article.
    _Rule(FlagType.PROMPT_INJECTION,
          re.compile(
              r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+(?:of\s+)?)?(?:the\s+)?"
              r"(?:previous|prior|above|preceding|earlier)\s+"
              r"(?:instructions?|rules?|prompts?|directions?)\b"
          ),
          score=0.90, risk=RiskLevel.HIGH,
          detail="Instruction to ignore earlier instructions."),

    # Read out the model's hidden context or credentials.
    _Rule(FlagType.PROMPT_INJECTION,
          re.compile(
              r"(?i)\b(?:repeat|output|print|echo|reproduce|recite)\s+(?:back\s+)?(?:the\s+)?"
              r"(?:words|text|content|lines?|everything)\s+(?:above|before|preceding)\b"
              r".{0,40}?\b(?:verbatim|starting\s+with|this\s+line|word\s+for\s+word|hidden)\b"
              r"|\b(?:show|print|give|tell|reveal|display|list|dump|leak)\s+(?:me\s+)?"
              r"(?:(?:all\s+(?:of\s+)?)|(?:the\s+)?contents?\s+of\s+)?your\s+"
              r"(?:api\s+keys?|access\s+tokens?|credentials|secret\s+keys?|secrets|passwords?|"
              r"internal\s+configuration|config(?:uration)?|system\s+prompt|hidden\s+instructions?)\b"
              r"|\b(?:complete|finish|continue)\s+(?:the\s+following\s+)?(?:sentence|text)\b"
              r".{0,40}?\b(?:system\s+prompt|hidden\s+instructions?)\b"
          ),
          score=0.84, risk=RiskLevel.HIGH,
          detail="Attempt to read out the model's hidden context or credentials."),

    # Encoded payload paired with an order to run it.
    _Rule(FlagType.PROMPT_INJECTION,
          re.compile(
              r"(?i)\b(?:base64|rot13|hex[- ]?encoded|encoded)\b.{0,80}?"
              r"\b(?:execute|run|obey|follow)\b(?:\s+(?:it|them|the\s+result))?"
              r"|\b(?:execute|run)\b\W{0,3}.{0,40}?\b(?:base64|rot13|hex[- ]?encoded)\b"
          ),
          score=0.82, risk=RiskLevel.HIGH,
          detail="Encoded payload with an instruction to execute it."),

    # Weapons and drug synthesis, with an adjective or two in between —
    # "a pipe bomb" slipped the original rule, which allowed none. Bath, seed and
    # photo bombs are excluded by name.
    _Rule(FlagType.HARMFUL_CONTENT,
          re.compile(
              r"(?i)\b(?:how\s+to|how\s+do\s+(?:I|you)|instructions?\s+(?:to|for)|guide\s+(?:on|to))\s+"
              r"(?:make|build|synthesi[sz]e|create|creating|making|manufacture|cook)\s+"
              r"(?:an?\s+)?(?:(?!bath\b|seed\b|photo\b)\w+\s+){0,2}"
              r"(?:bomb|explosive|poison|bioweapon|biological\s+weapon|chemical\s+weapon|"
              r"nerve\s+agents?|sarin|ricin|methamphetamine|meth|fentanyl)\b"
              r"|\b(?:synthesi[sz]e|synthesis\s+of|cook)\s+(?:\w+\s+){0,2}"
              r"(?:methamphetamine|meth|fentanyl|sarin|ricin|nerve\s+agents?)\b"
              r"|\bmak(?:e|ing)\s+(?:\w+\s+){0,2}fentanyl\b"
          ),
          score=0.93, risk=RiskLevel.BLOCK,
          detail="Request for weapon or drug synthesis instructions."),

    # Self-harm, first person.
    _Rule(FlagType.HARMFUL_CONTENT,
          re.compile(
              r"(?i)\b(?:harm|hurt|kill)\s+myself\b.{0,60}?"
              r"\b(?:methods?|ways?|how\s+to|tell\s+me|give\s+me)\b"
          ),
          score=0.92, risk=RiskLevel.BLOCK,
          detail="Self-harm content detected."),

    # Operational fraud and intrusion requests.
    _Rule(FlagType.POLICY_VIOLATION,
          re.compile(
              r"(?i)\b(?:give|write|create|make|generate|draft)\s+(?:me\s+)?(?:a\s+)?"
              r"(?:working\s+)?phishing\s+(?:email|page|kit|template)\b"
              r"|\bclone\s+(?:a\s+|someone'?s\s+)?credit\s+cards?\b"
              r"|\b(?:hack|hacking)\s+into\s+(?:a\s+|the\s+|my\s+\w+'?s?\s+|someone'?s\s+)?"
              r"(?:database|account|server|network|wifi)\b"
              r"|\bdox+(?:ing|x)?\s+(?:someone|a\s+person|people)\b"
              r"|\bstalk\s+someone\b.{0,40}?\bwithout\s+being\s+detected\b"
          ),
          score=0.86, risk=RiskLevel.HIGH,
          detail="Request for operational fraud or intrusion help."),
]

_RULES.extend(_INJECTION_FAMILY_RULES)


# ── Aggregate risk helper ─────────────────────────────────────────────────────

_RISK_ORDER = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.BLOCK]


def _max_risk(*levels: RiskLevel) -> RiskLevel:
    return max(levels, key=lambda r: _RISK_ORDER.index(r))


# ── SemanticGuard ─────────────────────────────────────────────────────────────

@dataclass
class SemanticGuard:
    """
    Analyses text content for semantic policy violations.

    Usage::

        guard  = SemanticGuard(strict=True)
        result = guard.analyse(text)

        if not result.safe:
            print(result.risk_level, result.flags)
    """

    strict: bool = False   # if True, MEDIUM risk also blocks

    # ── Result container ──────────────────────────────────────────────────

    @dataclass
    class Result:
        flags:      list[SemanticFlag] = field(default_factory=list)
        risk_level: RiskLevel          = RiskLevel.LOW

        @property
        def safe(self) -> bool:
            """True only when risk is LOW (no concern at all)."""
            return self.risk_level == RiskLevel.LOW

        def safe_for(self, strict: bool) -> bool:
            """True when the content is acceptable under the given mode.

            strict=False (normal mode): allow LOW and MEDIUM.
            strict=True:                allow LOW only.
            """
            if strict:
                return self.risk_level == RiskLevel.LOW
            return self.risk_level not in (RiskLevel.HIGH, RiskLevel.BLOCK)

        @property
        def top_flag(self) -> SemanticFlag | None:
            return max(self.flags, key=lambda f: f.score) if self.flags else None

    # ── Public API ────────────────────────────────────────────────────────

    def analyse(self, text: str) -> SemanticGuard.Result:
        with _trace_stage("SemanticGuard.analyse", {
            "layer":        "semantic_guard",
            "input.length": len(text),
        }) as _sp:
            flags:      list[SemanticFlag] = []
            risk_level: RiskLevel          = RiskLevel.LOW

            for rule in _RULES:
                if rule.pattern.search(text):
                    flags.append(SemanticFlag(
                        flag=rule.flag,
                        score=rule.score,
                        detail=rule.detail,
                    ))
                    risk_level = _max_risk(risk_level, rule.risk)

            # Run any subclass-defined custom checks
            extra_flags, extra_risk = self._custom_checks(text)
            flags.extend(extra_flags)
            if extra_flags:
                risk_level = _max_risk(risk_level, extra_risk)

            # ── Compound risk escalation: 3+ MEDIUM signals → HIGH ───────────
            if risk_level == RiskLevel.MEDIUM:
                medium_count = sum(
                    1 for f in flags
                    if f.score < 0.85 and f.score >= 0.60
                )
                if medium_count >= 3:
                    risk_level = RiskLevel.HIGH
                    flags.append(SemanticFlag(
                        flag=FlagType.POLICY_VIOLATION,
                        score=0.70,
                        detail=(
                            f"Compound risk: {medium_count} MEDIUM-confidence signals "
                            f"escalated to HIGH (possible multi-vector attack)."
                        ),
                    ))

            _sp.set_attribute("layer",       "semantic_guard")
            _sp.set_attribute("flags_count", len(flags))
            _sp.set_attribute("risk_level",  risk_level.value)
            return SemanticGuard.Result(flags=flags, risk_level=risk_level)

    # ── Extension hook ────────────────────────────────────────────────────

    def _custom_checks(
        self, text: str
    ) -> tuple[list[SemanticFlag], RiskLevel]:
        """
        Override in a subclass to add domain-specific rules without
        touching the core pattern bank.
        """
        return [], RiskLevel.LOW
