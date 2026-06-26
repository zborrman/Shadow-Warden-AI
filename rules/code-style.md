# Code Style

Load this file when writing Python code or reviewing a diff.

## Python version

Python 3.11+ features are allowed: `match/case`, `X | Y` union types, `tomllib`, `TaskGroup`.

## Ruff configuration

```
line-length = 100
select = E, F, W, I, N, UP, B, C4, SIM
ignore = E501, B008
```

Run: `ruff check warden/ --ignore E501`
Auto-fix: `ruff check warden/ --ignore E501 --fix`

`# noqa: <code>` is acceptable only when the suppression is documented (e.g., `# noqa: PLC0415` for deferred imports inside functions).

## Mypy

```
--ignore-missing-imports
--no-strict-optional
```

Run: `mypy warden/ --ignore-missing-imports --no-strict-optional`

No type annotations required on code you didn't change. Add annotations only to new functions or when fixing a mypy error in existing code.

## Comments

Default: **no comments.** Only add one when the WHY is non-obvious:
- A hidden constraint or invariant
- A workaround for a specific known bug
- Behavior that would surprise a reader

Never write comments that explain WHAT the code does (identifiers do that). Never reference the ticket/issue number or caller name in comments (those belong in the PR description).

## Docstrings

Not required. One-line module docstring is acceptable for context (see `vector_search.py`). No multi-paragraph docstrings.

## Imports

- Standard library first, then third-party, then local — Ruff enforces this (I001).
- Deferred imports inside functions use `# noqa: PLC0415` to suppress the lint warning.
- `from __future__ import annotations` at the top of every new module.

## Naming

- Snake case for all Python identifiers (Ruff N-rules enforce this).
- Constants: `_UPPER_SNAKE` (module-private) or `UPPER_SNAKE` (public).
- Private helpers: `_single_leading_underscore`.
- No abbreviations unless they are standard (e.g., `neg` for negotiation, `dec` for Decimal).

## Error handling

- Catch specific exceptions, not bare `except Exception` unless it's a fail-open guard.
- Fail-open guards: `except Exception as exc: log.warning("...: %s", exc)` — always log.
- Never silence exceptions without logging: `except Exception: pass` is forbidden.
- `contextlib.suppress(Exception)` is acceptable for additive SQLite migrations only.

## Dataclasses

Use `@dataclass` for plain data containers. Add `__slots__` only when memory is a concern (rarely). Default field values use `field(default_factory=...)` for mutable defaults.

## Async

- Use `asyncio.get_running_loop()` (not deprecated `get_event_loop()`).
- Background tasks via FastAPI `BackgroundTasks` — never `asyncio.create_task()` from a request handler.
- `asyncio.to_thread()` for CPU-bound work inside async context.

## Billing

`float` arithmetic is prohibited for any calculation involving money. Use `Decimal`:
```python
from decimal import Decimal, ROUND_HALF_UP
fee = (Decimal(str(price)) * rate).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
```
