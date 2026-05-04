"""
Pre-commit hook: verify every charge/refund/subscription call
carries an idempotency_key argument.
"""
from __future__ import annotations
import ast
import sys
from pathlib import Path

PAYMENT_CALLS = {"charge", "refund", "subscribe", "subscription_change"}


def check_file(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return errors

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name not in PAYMENT_CALLS:
            continue

        kw_names = {kw.arg for kw in node.keywords}
        if "idempotency_key" not in kw_names:
            errors.append(
                f"{path}:{node.lineno}: {func_name}() called without idempotency_key"
            )
    return errors


def main() -> int:
    files = [Path(f) for f in sys.argv[1:] if f.endswith(".py")]
    all_errors: list[str] = []
    for f in files:
        all_errors.extend(check_file(f))
    for err in all_errors:
        print(err)
    return 1 if all_errors else 0


if __name__ == "__main__":
    sys.exit(main())
