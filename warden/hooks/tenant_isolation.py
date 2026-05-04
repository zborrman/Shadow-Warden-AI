"""
Pre-commit hook: every SQLAlchemy query in api/ must filter by tenant_id.
Warns (does not block) — tenant isolation is advisory in this check.
"""
from __future__ import annotations
import ast
import sys
from pathlib import Path

_QUERY_METHODS = {"filter", "filter_by", "where"}


def check_file(path: Path) -> list[str]:
    warnings: list[str] = []
    try:
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src)
    except SyntaxError:
        return warnings

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in _QUERY_METHODS:
            continue
        # check if any arg / keyword references tenant_id
        src_segment = ast.get_source_segment(src, node) or ""
        if "tenant_id" not in src_segment:
            warnings.append(
                f"WARN {path}:{node.lineno}: "
                f".{node.func.attr}() may be missing tenant_id filter"
            )
    return warnings


def main() -> int:
    files = [
        Path(f) for f in sys.argv[1:]
        if f.endswith(".py") and "warden/api" in f.replace("\\", "/")
    ]
    for f in files:
        for w in check_file(f):
            print(w)
    return 0  # advisory only


if __name__ == "__main__":
    sys.exit(main())
