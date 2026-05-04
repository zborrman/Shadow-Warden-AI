"""
Pre-commit hook: ensure except blocks never silently swallow errors.
Blocks: `except ...: pass` or bare return without a logger call.
"""
from __future__ import annotations
import ast
import sys
from pathlib import Path

_LOGGER_CALLS = {"warning", "error", "critical", "exception", "warn"}


def _has_log_call(body: list[ast.stmt]) -> bool:
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in _LOGGER_CALLS:
                return True
    return False


def check_file(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return errors

    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        body = node.body
        # bare pass
        if len(body) == 1 and isinstance(body[0], ast.Pass):
            errors.append(
                f"{path}:{node.lineno}: bare `except: pass` — add logger.warning()"
            )
            continue
        # bare return without logging
        if len(body) == 1 and isinstance(body[0], ast.Return) and not _has_log_call(body):
            errors.append(
                f"{path}:{node.lineno}: `except: return` without logging — add logger.warning()"
            )
    return errors


def main() -> int:
    files = [Path(f) for f in sys.argv[1:] if f.endswith(".py")]
    all_errors: list[str] = []
    for f in files:
        # skip tests and migrations — they have intentional bare excepts
        if "test" in f.parts or "migration" in f.parts:
            continue
        all_errors.extend(check_file(f))
    for err in all_errors:
        print(err)
    return 1 if all_errors else 0


if __name__ == "__main__":
    sys.exit(main())
