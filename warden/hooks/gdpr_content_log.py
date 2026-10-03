"""
Pre-commit hook: request content must never reach a log call (H-7).

``CLAUDE.md`` names "Content is NEVER logged — only metadata (type, length,
timing)" a hard requirement and a protected invariant the autonomous loop may
not touch, and the old Hook.md advertised a ``check-gdpr-content-log`` guard
for it. That guard existed nowhere; ``test_gdpr_endpoints.py`` and
``test_gdpr_idor.py`` cover the export/purge routes and IDOR, not logging
statements. This is the guard.

It matters more than the usual style check because a log line is the one place
the project cannot take content back from: logs ship to Loki, to MinIO and to a
SIEM, and the paths that log content are the ones that fire when input looks
suspicious — so the payload most worth not keeping is the one most likely to be
written down.

What counts as a violation: a call to ``log.info`` / ``logger.warning`` / … in
which a *content-named* value is passed. Three distinctions do the real work,
and each exists because the naive rule was wrong on this codebase:

* **A measurement of content is not content.** ``log.warning("len=%d", len(text))``
  is exactly what the invariant asks for, so a name used only inside ``len()``
  (or ``type``/``bool``/``isinstance``/…) is pruned. The first draft of this
  scanner flagged ``topology_guard.py`` and ``backup/service.py`` for logging a
  length.
* **An object that is dereferenced is not what is logged.** ``body.ttl_hours``
  logs a TTL, not the request body; the scanner reads the *final attribute*, not
  the object it came through. Without this, twenty-one ``body.<field>`` lines in
  the routers read as leaks.
* **A string literal is not a value.** Matching happens on identifiers, never on
  message text, so ``log.info("content blocked")`` is silent — the same reason
  the Worker source ratchets strip comments before matching. Prose about content
  is not content.

The merge gate is ``warden/tests/test_gdpr_content_never_logged.py``, which
carries the may-only-shrink baseline — CI runs pytest, not pre-commit, so this
entry is for fast local feedback, not the wall.
"""
from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path

# Logger methods. ``log`` is included for ``logger.log(level, msg)``.
LOG_METHODS = frozenset({
    "debug", "info", "warning", "warn", "error", "exception", "critical", "log",
})

# The receiver has to look like a logger: ``log.info`` yes, ``result.info`` no.
LOGGERISH = frozenset({"logger", "log", "logging", "_logger", "_log", "LOGGER", "LOG"})

# Identifiers that name request/response content rather than metadata about it.
# Matching is exact, never substring: ``prompt_tokens``, ``content_length`` and
# ``text_len`` are measurements and must stay legal.
CONTENT_NAMES = frozenset({
    "content", "text", "prompt", "body", "payload", "decoded", "decoded_text",
    "plaintext", "raw", "raw_text", "user_input", "unmasked", "masked",
    "snippet", "message_text", "answer", "completion", "response_text",
})

# Wrapping content in one of these yields a measurement, which is permitted.
# Deliberately short, and it must stay that way: `sorted`, `min` and `max` were
# in this set and are not measurements of a string — `sorted(text)` logs every
# character of it and `min(text)` logs one, so each was an exemption that
# published content. A name belongs here only if its result cannot vary with the
# *characters* of the input, which is why `hash` qualifies and `sorted` does not.
METADATA_FNS = frozenset({"len", "type", "bool", "isinstance", "id", "hash"})

# Calls that hand back an object's contents. These are the exception to the
# "an object that is dereferenced is not what is logged" rule below: `body.label`
# selects a field, but `body.model_dump()` serialises the whole request — so the
# receiver's name must be judged, not pruned.
SERIALIZING_ATTRS = frozenset({
    "model_dump", "model_dump_json", "dict", "json", "to_dict", "as_dict",
    "_asdict", "__dict__",
})

# Names that carry content only once serialised. `request.url.path` is routine
# and must stay legal; `request.model_dump()` is the whole request body.
SERIALIZED_SUBJECTS = frozenset({"request", "req", "form", "message", "msg"})


@dataclass(frozen=True)
class Finding:
    path: str
    lineno: int
    names: tuple[str, ...]

    def __str__(self) -> str:
        # ASCII only: this prints to a pre-commit console, which is cp1252 on
        # the maintainer's Windows box and raises UnicodeEncodeError on a dash.
        return (
            f"{self.path}:{self.lineno}: content reaches a log call "
            f"({', '.join(self.names)}) - log length/type/timing instead"
        )


def _is_logger_call(func: ast.Attribute) -> bool:
    receiver = func.value
    if isinstance(receiver, ast.Name):
        return receiver.id in LOGGERISH
    if isinstance(receiver, ast.Attribute):
        return receiver.attr in LOGGERISH
    # `logging.getLogger(__name__).warning(content)` — the receiver is a *call*,
    # which the first version did not consider a logger at all, so the most
    # idiomatic way to obtain a logger was also the way to bypass this guard.
    if isinstance(receiver, ast.Call):
        fn = receiver.func
        if isinstance(fn, ast.Attribute) and fn.attr == "getLogger":
            return True
        if isinstance(fn, ast.Name) and fn.id == "getLogger":
            return True
    return False


def _serialized_subject(node: ast.Call) -> set[str]:
    """Names whose *contents* this serializing call hands to the logger."""
    fn = node.func
    if not isinstance(fn, ast.Attribute) or fn.attr not in SERIALIZING_ATTRS:
        return set()
    found: set[str] = set()
    cur: ast.AST = fn.value
    while True:  # walk the receiver chain: a.b.c.model_dump()
        if isinstance(cur, ast.Name):
            if cur.id in CONTENT_NAMES or cur.id in SERIALIZED_SUBJECTS:
                found.add(cur.id)
            break
        if isinstance(cur, ast.Attribute):
            if cur.attr in CONTENT_NAMES or cur.attr in SERIALIZED_SUBJECTS:
                found.add(cur.attr)
            cur = cur.value
            continue
        break
    return found


def _content_names(node: ast.AST) -> set[str]:
    """Content-naming identifiers actually *logged* by this expression."""
    found: set[str] = set()
    stack: list[ast.AST] = [node]
    while stack:
        cur = stack.pop()
        if isinstance(cur, ast.Call):
            fn = cur.func
            # len(content) is a length; do not descend into it.
            if isinstance(fn, ast.Name) and fn.id in METADATA_FNS:
                continue
            # payload.get("content") logs the content under that key.
            if isinstance(fn, ast.Attribute) and fn.attr == "get":
                for arg in cur.args:
                    if isinstance(arg, ast.Constant) and arg.value in CONTENT_NAMES:
                        found.add(str(arg.value))
            # body.model_dump() serialises the request rather than selecting a
            # field from it, so the receiver is the thing being logged.
            found |= _serialized_subject(cur)
        if isinstance(cur, ast.Name):
            if cur.id in CONTENT_NAMES:
                found.add(cur.id)
        elif isinstance(cur, ast.Attribute):
            if cur.attr in CONTENT_NAMES:
                found.add(cur.attr)
            # ``body.label`` logs the label. The object it came through is a
            # path to the value, not the value — do not walk into it.
            if isinstance(cur.value, (ast.Name, ast.Attribute)):
                continue
        elif isinstance(cur, ast.Subscript):
            index = cur.slice
            if isinstance(index, ast.Constant) and index.value in CONTENT_NAMES:
                found.add(str(index.value))
        stack.extend(ast.iter_child_nodes(cur))
    return found


def scan_source(src: str, rel_path: str) -> list[Finding]:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in LOG_METHODS or not _is_logger_call(node.func):
            continue
        names: set[str] = set()
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            names |= _content_names(arg)
        if names:
            findings.append(Finding(rel_path, node.lineno, tuple(sorted(names))))
    return findings


def scan_file(path: Path, rel_path: str | None = None) -> list[Finding]:
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return scan_source(src, rel_path or str(path).replace("\\", "/"))


def main() -> int:
    paths = [
        Path(f) for f in sys.argv[1:]
        if f.endswith(".py") and "/tests/" not in f.replace("\\", "/")
    ]
    findings: list[Finding] = []
    for p in paths:
        findings.extend(scan_file(p))
    for f in sorted(findings, key=lambda f: (f.path, f.lineno)):
        print(str(f))
    if findings:
        print(
            f"\n{len(findings)} log call(s) carry content. GDPR: content is never "
            f"logged - only metadata (type, length, timing). If the site is a "
            f"third-party error body rather than request content, record it in "
            f"warden/tests/gdpr_content_log_baseline.json with a reason in the "
            f"test's _BASELINE_REASONS table."
        )
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
