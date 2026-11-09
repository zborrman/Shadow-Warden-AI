"""
Tenant isolation guard (H-5): a route must not take the tenant it acts on from
the caller.

The first version of this hook looked for SQLAlchemy ``.filter()`` / ``.where()``
calls in ``warden/api/`` missing the string ``tenant_id``. ``warden/api/`` uses
raw SQLite and has no such calls, so it reported **zero** on every run — and it
returned 0 regardless, so it could not have blocked anything if it had. A
control that is present and permits everyone (Rule.md §29.1).

The defect that actually shipped (SW-11..16, #444) had a different shape: a
route took ``tenant_id`` as a query parameter, so any caller could read any
tenant's data by naming it. That is what this guard looks for — a route-handler
parameter whose name contains ``tenant`` and whose value comes from the request
(path, query, header, form, or a literal default) rather than from a dependency.

A claimed tenant is *bound* — and not reported — when any of these hold:

* the parameter itself is resolved by ``Depends(...)`` / ``Security(...)``;
* the route, or the ``APIRouter`` it hangs off, depends on an ownership or
  admin check (``_BINDING_DEPENDENCIES``) — an admin acting on a named tenant
  is the legitimate case, and ``require_tenant_owner_or_admin`` compares the
  path tenant against the authenticated one;
* the handler body compares the claimed name against some ``*.tenant_id``
  attribute in an ``if`` that raises, e.g.
  ``if auth.tenant_id != tenant_id: raise HTTPException(403)``. A comparison
  with no rejection behind it binds nothing.

Each route registration is judged on its own: a handler stacked under two
decorators is two routes, and an admin dependency on one does not cover the
other. A finding's key names the route (method and path), so adding a second
URL to an already baselined handler is a new finding, not a free pass.

Detection lives here; the merge gate is
``warden/tests/test_tenant_isolation.py`` (CI runs pytest, not pre-commit),
which holds a may-only-shrink baseline. As a pre-commit hook this exits 1 on any
finding the baseline does not already record.
"""
from __future__ import annotations

import ast
import json
import sys
from dataclasses import dataclass
from pathlib import Path

_ROUTE_VERBS = frozenset({"get", "post", "put", "patch", "delete", "api_route", "websocket"})

# Dependencies that make a request-supplied tenant safe to act on: either the
# caller is an operator, or the dependency itself checks ownership.
_BINDING_DEPENDENCIES = frozenset({
    "require_tenant_owner_or_admin",
    "require_admin_only",
    "require_admin",
    "_require_admin",
    "require_admin_key",
    "_require_admin_key",
    "verify_admin_key",
})

BASELINE = Path(__file__).resolve().parent.parent / "tests" / "tenant_isolation_baseline.json"


@dataclass(frozen=True)
class Finding:
    path: str
    lineno: int
    func: str
    param: str
    source: str  # how the value arrives: path/query, Query, Header, Form, literal-default
    route: str = ""  # "GET /x/{tenant_id}" — the registration this finding is about

    @property
    def key(self) -> str:
        # Line-free, so moving a route does not churn the baseline. The route is
        # part of it: keyed on the function alone, a second URL added to a
        # baselined handler matched the existing entry and was never reported.
        return f"{self.path}::{self.func}::{self.param}::{self.route}"

    def __str__(self) -> str:
        return (
            f"{self.path}:{self.lineno}: {self.func}() [{self.route}] takes {self.param!r} "
            f"from the request ({self.source}) and never binds it to the authenticated tenant"
        )


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _depends_target(node: ast.AST) -> str:
    """``Depends(x)`` / ``Security(x)`` → ``"x"``; anything else → ``""``."""
    if isinstance(node, ast.Call) and _call_name(node) in {"Depends", "Security"} and node.args:
        return _call_name(node.args[0])
    return ""


def _dependency_names(deps: ast.AST | None, aliases: dict[str, str]) -> set[str]:
    names: set[str] = set()
    if isinstance(deps, (ast.List, ast.Tuple)):
        for elt in deps.elts:
            target = _depends_target(elt)
            if not target and isinstance(elt, ast.Name):
                # `_Gate = Depends(require_admin)` then `dependencies=[_Gate]`
                target = aliases.get(elt.id, "")
            if target:
                names.add(target)
    return names


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _module_context(tree: ast.Module) -> tuple[dict[str, str], dict[str, set[str]]]:
    """Module-level ``X = Depends(f)`` aliases and each ``APIRouter``'s dependencies."""
    aliases: dict[str, str] = {}
    routers: dict[str, set[str]] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        dep = _depends_target(node.value)
        if dep:
            aliases[target.id] = dep
        if isinstance(node.value, ast.Call) and _call_name(node.value) == "APIRouter":
            routers[target.id] = _dependency_names(_kw(node.value, "dependencies"), aliases)
    return aliases, routers


def _route_decorators(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Call]:
    """Every route registration on *fn* — not just the first."""
    return [
        dec for dec in fn.decorator_list
        if isinstance(dec, ast.Call)
        and isinstance(dec.func, ast.Attribute)
        and dec.func.attr in _ROUTE_VERBS
    ]


def _route_label(dec: ast.Call) -> str:
    verb = dec.func.attr.upper() if isinstance(dec.func, ast.Attribute) else "?"
    first = dec.args[0] if dec.args else _kw(dec, "path")
    path = first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else "?"
    return f"{verb} {path}"


def _is_tenant_compare(node: ast.AST, name: str) -> bool:
    if not isinstance(node, ast.Compare):
        return False
    operands = [node.left, *node.comparators]
    has_name = any(isinstance(o, ast.Name) and o.id == name for o in operands)
    has_attr = any(isinstance(o, ast.Attribute) and o.attr == "tenant_id" for o in operands)
    return has_name and has_attr


def _rejecters(tree: ast.Module) -> set[str]:
    """Module-level helpers that always raise, e.g. ``def _403(msg): raise HTTPException(403)``.

    A top-level ``raise`` statement in the body is the test, so a helper that
    raises only on some branch does not count.
    """
    return {
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(isinstance(stmt, ast.Raise) for stmt in node.body)
    }


def _raises(stmts: list[ast.stmt], rejecters: frozenset[str] = frozenset()) -> bool:
    """A ``raise`` in *stmts* — or a call to a helper that always raises — not
    counting nested function or class bodies."""
    stack: list[ast.AST] = list(stmts)
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Raise):
            return True
        if isinstance(node, ast.Call) and _call_name(node) in rejecters:
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        stack.extend(ast.iter_child_nodes(node))
    return False


def _compared_to_tenant_attr(
    fn: ast.AST, name: str, rejecters: frozenset[str] = frozenset()
) -> bool:
    """True when the body rejects on a comparison of *name* with some ``<x>.tenant_id``.

    The comparison must sit in an ``if`` test with a ``raise`` in one of its
    branches. Any comparison used to count — ``if auth.tenant_id != tenant_id:
    pass`` silenced the finding while the handler still loaded the claimed
    tenant.
    """
    for node in ast.walk(fn):
        if not isinstance(node, ast.If):
            continue
        if not any(_is_tenant_compare(n, name) for n in ast.walk(node.test)):
            continue
        if _raises(node.body, rejecters) or _raises(node.orelse, rejecters):
            return True
    return False


def _source_of(default: ast.AST | None) -> str:
    if default is None:
        return "path/query"
    name = _call_name(default) if isinstance(default, ast.Call) else ""
    return name or "literal-default"


def scan_source(src: str, path: str) -> list[Finding]:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    aliases, routers = _module_context(tree)
    rejecters = frozenset(_rejecters(tree))
    findings: list[Finding] = []

    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorators = _route_decorators(fn)
        if not decorators:
            continue

        args = fn.args
        positional = args.posonlyargs + args.args
        defaults: list[ast.AST | None] = [None] * (len(positional) - len(args.defaults))
        defaults += list(args.defaults)
        pairs = list(zip(positional, defaults, strict=True))
        pairs += list(zip(args.kwonlyargs, args.kw_defaults, strict=True))

        # A parameter that is itself resolved by a dependency is not a claim —
        # but a dependency on an ownership/admin check binds every claim.
        param_deps = {
            _depends_target(default) for _arg, default in pairs if default is not None
        } - {""}

        # Each registration is its own route with its own dependencies.
        for dec in decorators:
            bound_by = _dependency_names(_kw(dec, "dependencies"), aliases) | param_deps
            if isinstance(dec.func, ast.Attribute) and isinstance(dec.func.value, ast.Name):
                bound_by |= routers.get(dec.func.value.id, set())
            if bound_by & _BINDING_DEPENDENCIES:
                continue
            route = _route_label(dec)
            for arg, default in pairs:
                if "tenant" not in arg.arg.lower():
                    continue
                if default is not None and _depends_target(default):
                    continue
                if _compared_to_tenant_attr(fn, arg.arg, rejecters):
                    continue
                findings.append(Finding(path, fn.lineno, fn.name, arg.arg,
                                        _source_of(default), route))
    return findings


def scan_file(file: Path, rel: str) -> list[Finding]:
    return scan_source(file.read_text(encoding="utf-8"), rel)


def load_baseline() -> set[str]:
    try:
        return set(json.loads(BASELINE.read_text(encoding="utf-8"))["routes"])
    except (OSError, ValueError, KeyError):
        return set()


def main() -> int:
    baseline = load_baseline()
    new: list[Finding] = []
    for arg in sys.argv[1:]:
        rel = arg.replace("\\", "/")
        if not rel.endswith(".py") or "/tests/" in rel or not rel.startswith("warden/"):
            continue
        new.extend(f for f in scan_file(Path(arg), rel) if f.key not in baseline)
    for f in new:
        print(f"BLOCK {f}")
    if new:
        print(
            "\nResolve the tenant from auth (`auth.tenant_id` via Depends(require_api_key)), "
            "or depend on require_tenant_owner_or_admin when the path names a tenant."
        )
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main())
