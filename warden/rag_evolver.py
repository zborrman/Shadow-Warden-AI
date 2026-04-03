"""
warden/rag_evolver.py
━━━━━━━━━━━━━━━━━━━━
RAG Injection Evolution Engine — Blue Team adaptive defence.

Blue Team concern addressed
────────────────────────────
Static regexes go stale as attackers invent new obfuscation techniques:

  • Unicode Tag block (U+E0000–U+E007F) — invisible in all browsers
  • BiDi override chars — reverse-rendered text hides instructions
  • Fullwidth ASCII homoglyphs — "Ｉgnore ａll ｐrevious instructions"
  • Markdown hidden sections / HTML comment injection
  • Soft-hyphen keyword splitting — "i\u00adgnore" bypasses ASCII regex
  • Novel techniques not yet known at build time

This module closes the feedback loop:

  1. log_blocked_sample()
       Called by worm_guard.inspect_for_ingestion() on every blocked doc.
       Appends anonymised samples to a JSONL dataset
       (RAG_EVOLVER_DATASET_PATH, default /warden/data/rag_injection_dataset.jsonl).

  2. evolve_patterns()  [async, call as BackgroundTask or from ARQ queue]
       Reads the N most recent unprocessed samples from the dataset.
       Calls the Evolution Engine (Nemotron Super via NimClient, or Claude
       Opus via AsyncAnthropic) with a RAG-security-specialist prompt.
       The LLM returns a JSON array of new regex patterns with explanations.
       Each pattern is compiled and smoke-tested before acceptance.

  3. save_patterns() / reload_patterns()
       Writes accepted patterns to RAG_EVOLVER_PATTERNS_PATH
       (default /warden/data/rag_evolved_patterns.json) and hot-patches
       worm_guard._evolved_patterns via worm_guard._register_evolved_patterns().
       No restart needed — the next inspect_for_ingestion() call picks up the
       new patterns immediately.

Architecture
────────────
  Dataset:    JSONL, append-only, capped at RAG_EVOLVER_MAX_SAMPLES rows.
  Patterns:   JSON array, atomically overwritten on each evolution cycle.
  Hot-reload: worm_guard._register_evolved_patterns(compiled_patterns)
  Scheduling: call evolve_patterns() from ARQ queue or a periodic FastAPI
              background task.  Rate-gated to RAG_EVOLVER_RATE_MAX calls
              per RAG_EVOLVER_RATE_WINDOW seconds (shared Redis counter).

GDPR
────
  Sample text is truncated to 2 KB and anonymised (IPs, UUIDs, emails,
  long hex strings stripped) before storage and before sending to the LLM.
  Fingerprints are one-way SHA-256 hashes — the original document cannot
  be recovered from the stored data.

Environment variables
─────────────────────
  RAG_EVOLVER_ENABLED          "false" to disable (default: true)
  RAG_EVOLVER_DATASET_PATH     JSONL dataset path (default: /warden/data/rag_injection_dataset.jsonl)
  RAG_EVOLVER_PATTERNS_PATH    Evolved patterns JSON path (default: /warden/data/rag_evolved_patterns.json)
  RAG_EVOLVER_MAX_SAMPLES      Dataset row cap (default: 5000)
  RAG_EVOLVER_BATCH_SIZE       Samples per LLM call (default: 10)
  RAG_EVOLVER_RATE_WINDOW      Redis rate window in seconds (default: 3600)
  RAG_EVOLVER_RATE_MAX         Max LLM calls per window (default: 4)
  RAG_EVOLVER_ENGINE           "nemotron" | "claude" | "auto" (default: auto)
"""
from __future__ import annotations

import concurrent.futures as _futures
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("warden.rag_evolver")

# ── Config ────────────────────────────────────────────────────────────────────

ENABLED: bool              = os.getenv("RAG_EVOLVER_ENABLED", "true").lower() != "false"
DATASET_PATH: Path         = Path(os.getenv(
    "RAG_EVOLVER_DATASET_PATH",
    "/warden/data/rag_injection_dataset.jsonl",
))
PATTERNS_PATH: Path        = Path(os.getenv(
    "RAG_EVOLVER_PATTERNS_PATH",
    "/warden/data/rag_evolved_patterns.json",
))
MAX_SAMPLES: int           = int(os.getenv("RAG_EVOLVER_MAX_SAMPLES",  "5000"))
BATCH_SIZE: int            = int(os.getenv("RAG_EVOLVER_BATCH_SIZE",   "10"))
RATE_WINDOW: int           = int(os.getenv("RAG_EVOLVER_RATE_WINDOW",  "3600"))   # 1 hour
RATE_MAX: int              = int(os.getenv("RAG_EVOLVER_RATE_MAX",     "4"))
ENGINE: str                = os.getenv("RAG_EVOLVER_ENGINE", "auto").lower()

_RATE_KEY = "warden:rag_evolver:calls"

# ── Thread-safety ─────────────────────────────────────────────────────────────

_dataset_lock   = threading.Lock()
_patterns_lock  = threading.Lock()
_row_count: int | None = None

# ── GDPR anonymiser (mirrors evolve.py's _ANON_PATTERNS) ─────────────────────

_ANON: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
                re.IGNORECASE), "[UUID]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),                              "[IPv4]"),
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),   "[EMAIL]"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"),
                "[TIMESTAMP]"),
    (re.compile(r"\b[0-9a-f]{32}\b", re.IGNORECASE),                          "[UUID]"),
    (re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE),                         "[HEX]"),
]


def _anonymise(text: str) -> str:
    for pat, repl in _ANON:
        text = pat.sub(repl, text)
    return text


# ── Dataset helpers ───────────────────────────────────────────────────────────

@dataclass
class RAGSample:
    """One blocked RAG ingestion event stored in the dataset."""
    fingerprint:  str
    attack_forms: list[str]
    snippet:      str            # anonymised, ≤ 2 KB
    timestamp:    float = field(default_factory=time.time)
    processed:    bool  = False  # True after the Evolution Engine has seen this


def _get_row_count() -> int:
    global _row_count  # noqa: PLW0603
    if _row_count is not None:
        return _row_count
    if not DATASET_PATH.exists():
        _row_count = 0
        return 0
    try:
        _row_count = sum(1 for line in DATASET_PATH.open("r", encoding="utf-8") if line.strip())
    except Exception:
        _row_count = 0
    return _row_count


def _atomic_append(line: str) -> None:
    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    with DATASET_PATH.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())


# ── Public: log a blocked sample ─────────────────────────────────────────────

def log_blocked_sample(
    document_text: str,
    attack_forms:  list[str],
    fingerprint:   str,
) -> bool:
    """
    Append one blocked RAG injection event to the dataset.

    Called non-blocking from worm_guard.inspect_for_ingestion().
    Returns True if the sample was written, False if the cap is reached
    or the evolver is disabled.

    GDPR: `document_text` is anonymised and truncated to 500 chars before
    storage — the stored snippet is not reversible to the original document.
    """
    if not ENABLED:
        return False

    with _dataset_lock:
        global _row_count  # noqa: PLW0603
        count = _get_row_count()
        if count >= MAX_SAMPLES:
            log.debug(
                "RAGEvolver dataset cap (%d) reached — skipping sample fp=%s…",
                MAX_SAMPLES, fingerprint[:12],
            )
            return False

        snippet = _anonymise(document_text)[:500]
        sample  = RAGSample(
            fingerprint  = fingerprint,
            attack_forms = attack_forms,
            snippet      = snippet,
        )
        record = {
            "fingerprint":  sample.fingerprint,
            "attack_forms": sample.attack_forms,
            "snippet":      sample.snippet,
            "timestamp":    sample.timestamp,
            "processed":    False,
        }
        _atomic_append(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
        _row_count = count + 1

    log.debug(
        "RAGEvolver: logged sample fp=%s… attacks=%s",
        fingerprint[:12], attack_forms,
    )
    return True


# ── Load unprocessed samples ──────────────────────────────────────────────────

def _read_unprocessed(limit: int = BATCH_SIZE) -> list[dict]:
    """Read up to `limit` unprocessed samples from the dataset."""
    if not DATASET_PATH.exists():
        return []
    samples: list[dict] = []
    try:
        with DATASET_PATH.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    if not rec.get("processed", False):
                        samples.append(rec)
                        if len(samples) >= limit:
                            break
                except json.JSONDecodeError:
                    continue
    except Exception as exc:
        log.debug("RAGEvolver: _read_unprocessed error: %s", exc)
    return samples


def _mark_processed(fingerprints: set[str]) -> None:
    """Rewrite the dataset file marking the given fingerprints as processed."""
    if not DATASET_PATH.exists() or not fingerprints:
        return
    try:
        lines: list[str] = []
        with DATASET_PATH.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    if rec.get("fingerprint") in fingerprints:
                        rec["processed"] = True
                    lines.append(json.dumps(rec, ensure_ascii=False, separators=(",", ":")))
                except json.JSONDecodeError:
                    lines.append(line)
        # Atomic overwrite via temp file
        tmp = Path(str(DATASET_PATH) + ".tmp")
        tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        tmp.replace(DATASET_PATH)
    except Exception as exc:
        log.debug("RAGEvolver: _mark_processed error: %s", exc)


# ── Rate gate ─────────────────────────────────────────────────────────────────

def _is_rate_limited() -> bool:
    try:
        from warden.cache import _get_client  # noqa: PLC0415
        r = _get_client()
        if r is None:
            return False
        count = r.incr(_RATE_KEY)
        if count == 1:
            r.expire(_RATE_KEY, RATE_WINDOW)
        return int(count) > RATE_MAX
    except Exception:
        return False


# ── System prompt for the RAG Evolution Engine ────────────────────────────────

_RAG_EVOLUTION_SYSTEM_PROMPT = """\
You are an expert adversarial ML security researcher embedded in the Shadow
Warden AI gateway. Your speciality is RAG (Retrieval-Augmented Generation)
poisoning and document-injection attacks.

You will receive a batch of documents that were blocked by the RAG Ingestion
Firewall because they contained prompt-injection payloads. Your task is to
analyse these samples and generate NEW Python-compatible regex patterns that
will catch *novel obfuscation variants* of the same attack class that the
current static patterns do NOT yet cover.

Focus areas for new patterns:
  1. Unicode obfuscation not already covered:
     • Tag block (U+E0000-U+E007F), soft hyphens, variation selectors,
       combining characters used to split keywords, NFD decomposition
  2. Markdown / HTML structural abuse:
     • Invisible HTML comments, empty link anchors with JS payloads,
       details/summary collapse, CSS class name smuggling
  3. Language variants and paraphrasing:
     • "Set aside", "Put on hold", "Pause", "Suspend" as synonyms for "ignore"
     • Authority framing: "New system message:", "Updated directive:", etc.
  4. Encoding chains:
     • ROT13, simple Caesar substitution of instruction verbs,
       base64-labelled instruction payloads inside otherwise normal text
  5. Structural patterns that do NOT appear in the baseline:
     • Multi-paragraph instruction hiding (instruction split across paragraphs)
     • Footnote / endnote abuse with instruction content

For each new pattern, return a JSON object in the array with:
  {
    "pattern":     "<Python regex string — MUST be valid Python re syntax>",
    "flags":       "IGNORECASE"  // or "IGNORECASE|DOTALL" or ""
    "description": "<one sentence: what attack variant this catches>",
    "attack_class": "<one of: hidden_instruction | rag_quine | delimiter_spoof | unicode_obfuscation | encoding_abuse | structural_split>"
  }

Rules:
  • Return ONLY a JSON array. No preamble. No commentary. No markdown fences.
  • Every "pattern" must compile with Python re.compile(). Test it mentally.
  • False-positive risk: patterns must NOT match common legitimate document text.
  • Maximum 8 new patterns per batch. Quality > quantity.
  • Never reproduce real credentials, PII, or working exploit payloads.
  • If you cannot generate any meaningful new patterns from this batch, return [].
"""


def _build_user_prompt(samples: list[dict]) -> str:
    lines = ["Blocked RAG injection samples for analysis:\n"]
    for i, s in enumerate(samples, 1):
        lines.append(
            f"--- Sample {i} ---\n"
            f"Attack forms detected: {', '.join(s.get('attack_forms', []))}\n"
            f"Snippet (anonymised): {s.get('snippet', '')[:300]}\n"
        )
    lines.append(
        "\nGenerate new regex patterns to catch novel variants not covered by "
        "the current static patterns."
    )
    return "\n".join(lines)


# ── Pattern validation ────────────────────────────────────────────────────────

_COMMON_LEGIT_PHRASES = [
    "The quarterly sales report shows revenue growth.",
    "Please review the attached PDF document.",
    "Meeting notes from the product roadmap session.",
    "Our return policy allows exchanges within 30 days.",
    "Thank you for your order. Your shipment has been dispatched.",
    "The research paper analyses climate data from 2020 to 2025.",
    "図表1は四半期の売上データを示しています。",   # Japanese — CJK legit content
    "Données financières du troisième trimestre 2025.",  # French
]

_FALSE_POSITIVE_THRESHOLD = 0   # no legit phrase should match any new pattern

# ── ReDoS stress-test infrastructure ─────────────────────────────────────────
# A ~100 KB block of varied legitimate document text.  Patterns with
# catastrophic backtracking will time out on this corpus; safe patterns
# complete in microseconds.  The text is assembled from diverse realistic
# fragments to maximise engine backtracking opportunity.
_STRESS_FRAGMENT = (
    "The quarterly report shows revenue of $4.2 million, up 12% year-over-year. "
    "Our customer satisfaction score improved to 94 percent. The new product line "
    "launch exceeded projections by 18%. Supply chain disruptions were mitigated "
    "through diversified sourcing strategies across multiple continents. The board "
    "approved a dividend of $0.25 per share at the extraordinary general meeting. "
    "Research and development expenses increased to $1.8 million as we invest in "
    "next-generation features and platform capabilities. Headcount grew from 142 to "
    "167 employees across engineering, sales, and operations departments. "
    "The integration of the acquired subsidiary is proceeding on schedule and within "
    "budget. Market share in the EMEA region expanded to 23% of addressable market. "
    "Compliance audits were completed without any material findings or observations. "
    "The annual general meeting is scheduled for the third week of June this year. "
    "Shareholders are encouraged to submit proxy votes before the deadline. "
    "Environmental initiatives reduced carbon emissions by 7% compared to baseline. "
    "Our data centre migration to cloud infrastructure is approximately 80% complete. "
    "Please see the attached financial statements and notes for full detail. "
    "The legal team has reviewed all contractual obligations and confirmed compliance. "
    "Customer retention rate remained stable at 91% throughout the reporting period. "
    "New partnership agreements were signed with three additional distribution channels. "
)
_STRESS_TEXT: str = _STRESS_FRAGMENT * 500   # ≈ 105 KB

# Hard timeout for the ReDoS stress test.  Patterns completing in < 500 ms on
# 105 KB of text are safe for production use in the async event loop.
_REDOS_TIMEOUT_S: float = float(os.getenv("RAG_EVOLVER_REDOS_TIMEOUT_S", "0.5"))

# Shared thread pool — 2 workers so concurrent evolution cycles don't queue.
# Uses daemon threads so it does not block process shutdown.
_REDOS_POOL: _futures.ThreadPoolExecutor = _futures.ThreadPoolExecutor(
    max_workers    = 2,
    thread_name_prefix = "redos-check",
)

# Optional: use Google re2 (linear-time, ReDoS-immune) as an additional
# compile-time screen.  If the pattern is rejected by re2 it almost certainly
# contains a construct that enables catastrophic backtracking.
try:
    import re2 as _re2  # type: ignore[import]
    _RE2_AVAILABLE = True
except ImportError:
    _re2 = None
    _RE2_AVAILABLE = False


def _validate_pattern(raw_pattern: str, flags_str: str) -> re.Pattern[str] | None:
    """
    Compile and smoke-test a new AI-generated regex pattern.

    Three-stage gate — a pattern must pass ALL stages:

    Stage 1 — Syntax check
        ``re.compile()`` must succeed.

    Stage 2 — False-positive check
        Pattern must NOT match any phrase in ``_COMMON_LEGIT_PHRASES``.

    Stage 3 — ReDoS stress test  ← NEW (Blue Team hardening)
        Pattern is run against a ~105 KB block of legitimate text inside a
        worker thread.  If it does not complete within ``_REDOS_TIMEOUT_S``
        (default 0.5 s, override via ``RAG_EVOLVER_REDOS_TIMEOUT_S`` env var),
        it is rejected as a ReDoS risk.

        Additionally, if the ``re2`` package (Google's linear-time engine) is
        installed, the pattern is also compiled with re2 as a fast pre-screen.
        re2 rejects patterns whose worst-case complexity is super-linear, which
        eliminates an entire class of catastrophic-backtracking constructs before
        the thread-based timeout is even needed.

    Returns the compiled ``re.Pattern`` on success, ``None`` on any failure.
    """
    flag_map = {
        "IGNORECASE":        re.IGNORECASE,
        "DOTALL":            re.DOTALL,
        "IGNORECASE|DOTALL": re.IGNORECASE | re.DOTALL,
        "DOTALL|IGNORECASE": re.IGNORECASE | re.DOTALL,
        "":                  0,
    }
    flags = flag_map.get(flags_str.strip().upper(), re.IGNORECASE)

    # ── Stage 1: syntax ───────────────────────────────────────────────────────
    try:
        compiled = re.compile(raw_pattern, flags)
    except re.error as exc:
        log.warning("RAGEvolver: pattern compile error — %s: %r", exc, raw_pattern[:80])
        return None

    # ── Optional re2 pre-screen (fast path, linear-time guarantee) ────────────
    if _RE2_AVAILABLE and _re2 is not None:
        try:
            re2_flags = 0
            if flags & re.IGNORECASE:
                re2_flags |= _re2.IGNORECASE
            _re2.compile(raw_pattern, re2_flags)
        except Exception as exc:
            log.warning(
                "RAGEvolver: pattern REJECTED (re2 rejects — likely ReDoS-prone) — %s: %r",
                exc, raw_pattern[:80],
            )
            return None

    # ── Stage 2: false-positive check ────────────────────────────────────────
    for phrase in _COMMON_LEGIT_PHRASES:
        if compiled.search(phrase):
            log.warning(
                "RAGEvolver: pattern REJECTED (false positive on legit text) — %r",
                raw_pattern[:80],
            )
            return None

    # ── Stage 3: ReDoS stress test ────────────────────────────────────────────
    # Run the pattern against ~105 KB of benign text in a worker thread.
    # If it does not finish within _REDOS_TIMEOUT_S, the pattern is a ReDoS
    # risk and must not enter the production event loop.
    future = _REDOS_POOL.submit(compiled.search, _STRESS_TEXT)
    try:
        future.result(timeout=_REDOS_TIMEOUT_S)
    except _futures.TimeoutError:
        future.cancel()
        log.warning(
            "RAGEvolver: pattern REJECTED (ReDoS — did not complete on 105 KB "
            "stress corpus within %.1f s) — %r",
            _REDOS_TIMEOUT_S, raw_pattern[:80],
        )
        return None

    return compiled


# ── LLM call ─────────────────────────────────────────────────────────────────

async def _call_llm(user_prompt: str) -> list[dict]:
    """
    Send the evolution prompt to the configured LLM (Nemotron or Claude).
    Returns a list of raw pattern dicts from the LLM response, or [] on error.
    """
    choice = ENGINE
    if choice == "auto":
        nvidia_key = os.getenv("NVIDIA_API_KEY", "").strip()
        anthro_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
        choice = "nemotron" if nvidia_key else ("claude" if anthro_key else "none")

    if choice == "nemotron":
        return await _call_nemotron(user_prompt)
    if choice == "claude":
        return await _call_claude(user_prompt)

    log.info("RAGEvolver: no LLM configured (NVIDIA_API_KEY / ANTHROPIC_API_KEY unset) — skipping")
    return []


async def _call_nemotron(user_prompt: str) -> list[dict]:
    try:
        from warden.brain.nemotron_client import NimClient  # noqa: PLC0415
        client = NimClient()
        if not client.is_configured:
            return []
        answer, _ = await client.chat(
            messages = [
                {"role": "user", "content": user_prompt},
            ],
            max_tokens      = 2048,
            enable_thinking = False,
            temperature     = 0.1,
        )
        return _parse_llm_response(answer)
    except Exception as exc:
        log.warning("RAGEvolver: Nemotron call failed: %s", exc)
        return []


async def _call_claude(user_prompt: str) -> list[dict]:
    try:
        import anthropic  # noqa: PLC0415
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            return []
        client = anthropic.AsyncAnthropic(api_key=api_key)
        msg = await client.messages.create(
            model      = "claude-opus-4-6",
            max_tokens = 2048,
            system     = _RAG_EVOLUTION_SYSTEM_PROMPT,
            messages   = [{"role": "user", "content": user_prompt}],
        )
        raw = msg.content[0].text if msg.content else ""
        return _parse_llm_response(raw)
    except Exception as exc:
        log.warning("RAGEvolver: Claude call failed: %s", exc)
        return []


def _parse_llm_response(text: str) -> list[dict]:
    """Extract and parse the JSON array from LLM output."""
    text = text.strip()
    # Strip markdown fences if present
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*```$", "", text)
    # Find the outermost JSON array
    m = re.search(r"\[.*\]", text, re.DOTALL)
    if not m:
        log.debug("RAGEvolver: LLM response contains no JSON array: %r", text[:200])
        return []
    try:
        data = json.loads(m.group(0))
        if isinstance(data, list):
            return data
    except json.JSONDecodeError as exc:
        log.debug("RAGEvolver: JSON parse error: %s raw=%r", exc, text[:200])
    return []


# ── Save / load evolved patterns ──────────────────────────────────────────────

def save_patterns(compiled: list[re.Pattern[str]], raw_entries: list[dict]) -> None:
    """
    Atomically persist accepted patterns to PATTERNS_PATH as a JSON file.

    Stored format:
        {
          "generated_at": <unix timestamp>,
          "count": N,
          "patterns": [
            {"pattern": "...", "flags": "IGNORECASE", "description": "..."},
            ...
          ]
        }
    """
    with _patterns_lock:
        entries = []
        for pat, raw in zip(compiled, raw_entries, strict=False):
            entries.append({
                "pattern":      pat.pattern,
                "flags":        raw.get("flags", "IGNORECASE"),
                "description":  raw.get("description", ""),
                "attack_class": raw.get("attack_class", ""),
            })
        payload = {
            "generated_at": time.time(),
            "count":        len(entries),
            "patterns":     entries,
        }
        PATTERNS_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = Path(str(PATTERNS_PATH) + ".tmp")
        tmp.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        tmp.replace(PATTERNS_PATH)
    log.info(
        "RAGEvolver: saved %d evolved patterns to %s", len(entries), PATTERNS_PATH
    )


def reload_patterns() -> int:
    """
    Load persisted patterns from PATTERNS_PATH, validate, and hot-patch
    worm_guard._evolved_patterns.

    Returns the number of valid patterns loaded.
    Called at Warden startup and after each successful evolve_patterns() cycle.
    """
    if not PATTERNS_PATH.exists():
        return 0
    try:
        data     = json.loads(PATTERNS_PATH.read_text(encoding="utf-8"))
        entries  = data.get("patterns", [])
        compiled = []
        for entry in entries:
            pat = _validate_pattern(
                entry.get("pattern", ""),
                entry.get("flags", "IGNORECASE"),
            )
            if pat:
                compiled.append(pat)
        from warden.worm_guard import _register_evolved_patterns  # noqa: PLC0415
        _register_evolved_patterns(compiled)
        log.info(
            "RAGEvolver: hot-loaded %d/%d evolved patterns from %s",
            len(compiled), len(entries), PATTERNS_PATH,
        )
        return len(compiled)
    except Exception as exc:
        log.warning("RAGEvolver: reload_patterns failed: %s", exc)
        return 0


# ── Main evolution cycle ──────────────────────────────────────────────────────

async def evolve_patterns() -> dict:
    """
    Main async entry point — run one RAG Evolution cycle.

    1. Rate-gate check (Redis counter — avoids LLM cost explosion)
    2. Read BATCH_SIZE unprocessed samples from the dataset
    3. Build LLM prompt, call Evolution Engine
    4. Validate returned patterns (compile + false-positive smoke test)
    5. Merge with existing patterns, save, hot-reload into worm_guard
    6. Mark samples as processed

    Returns a status dict:
        {
          "status":          "ok" | "skipped" | "error",
          "reason":          str,
          "new_patterns":    int,
          "total_patterns":  int,
          "samples_used":    int,
        }
    Designed to be called from a FastAPI BackgroundTask, ARQ worker, or
    a periodic asyncio task.
    """
    if not ENABLED:
        return {"status": "skipped", "reason": "disabled", "new_patterns": 0,
                "total_patterns": 0, "samples_used": 0}

    if _is_rate_limited():
        return {"status": "skipped", "reason": "rate_limited", "new_patterns": 0,
                "total_patterns": 0, "samples_used": 0}

    samples = _read_unprocessed(limit=BATCH_SIZE)
    if not samples:
        return {"status": "skipped", "reason": "no_unprocessed_samples",
                "new_patterns": 0, "total_patterns": 0, "samples_used": 0}

    log.info("RAGEvolver: starting evolution cycle with %d samples", len(samples))

    user_prompt   = _build_user_prompt(samples)
    raw_proposals = await _call_llm(user_prompt)

    if not raw_proposals:
        log.info("RAGEvolver: LLM returned no new patterns")
        return {"status": "ok", "reason": "llm_returned_empty",
                "new_patterns": 0, "total_patterns": 0, "samples_used": len(samples)}

    # Validate + cap at 8 patterns
    accepted_compiled: list[re.Pattern[str]] = []
    accepted_raw:      list[dict]            = []
    for proposal in raw_proposals[:8]:
        pat = _validate_pattern(
            proposal.get("pattern", ""),
            proposal.get("flags", "IGNORECASE"),
        )
        if pat:
            accepted_compiled.append(pat)
            accepted_raw.append(proposal)
            log.info(
                "RAGEvolver: accepted pattern — %s: %r",
                proposal.get("attack_class", "?"),
                proposal.get("pattern", "")[:60],
            )

    if not accepted_compiled:
        log.info("RAGEvolver: 0/%d proposals passed validation", len(raw_proposals))
        _mark_processed({s["fingerprint"] for s in samples})
        return {"status": "ok", "reason": "all_proposals_rejected",
                "new_patterns": 0, "total_patterns": 0, "samples_used": len(samples)}

    # Merge with existing persisted patterns to avoid regression
    existing_compiled, existing_raw = _load_existing_patterns()
    merged_compiled = existing_compiled + accepted_compiled
    merged_raw      = existing_raw      + accepted_raw

    save_patterns(merged_compiled, merged_raw)
    total = reload_patterns()

    _mark_processed({s["fingerprint"] for s in samples})

    log.info(
        "RAGEvolver: cycle complete — %d new patterns accepted, %d total in worm_guard",
        len(accepted_compiled), total,
    )
    return {
        "status":         "ok",
        "reason":         "evolution_complete",
        "new_patterns":   len(accepted_compiled),
        "total_patterns": total,
        "samples_used":   len(samples),
    }


def _load_existing_patterns() -> tuple[list[re.Pattern[str]], list[dict]]:
    """Load previously persisted patterns (pre-merge step)."""
    if not PATTERNS_PATH.exists():
        return [], []
    try:
        data    = json.loads(PATTERNS_PATH.read_text(encoding="utf-8"))
        entries = data.get("patterns", [])
        compiled, raw = [], []
        for e in entries:
            pat = _validate_pattern(e.get("pattern", ""), e.get("flags", "IGNORECASE"))
            if pat:
                compiled.append(pat)
                raw.append(e)
        return compiled, raw
    except Exception as exc:
        log.debug("RAGEvolver: _load_existing_patterns error: %s", exc)
        return [], []


# ── Dataset stats ─────────────────────────────────────────────────────────────

def dataset_stats() -> dict:
    """Return dataset and pattern status (for /health or /api/config)."""
    with _dataset_lock:
        count = _get_row_count()
    pattern_count = 0
    generated_at  = None
    try:
        if PATTERNS_PATH.exists():
            data          = json.loads(PATTERNS_PATH.read_text(encoding="utf-8"))
            pattern_count = data.get("count", 0)
            generated_at  = data.get("generated_at")
    except Exception:
        pass
    return {
        "enabled":          ENABLED,
        "dataset_path":     str(DATASET_PATH),
        "dataset_rows":     count,
        "dataset_max":      MAX_SAMPLES,
        "patterns_path":    str(PATTERNS_PATH),
        "evolved_patterns": pattern_count,
        "last_evolved_at":  generated_at,
        "engine":           ENGINE,
    }
