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

Two more shapes (re-audit 2026-11-16). The first version saw parameters only,
and the re-audit found the same claim arriving two other ways:

* **a body field** - a handler takes a Pydantic model with a ``tenant*`` field
  and reads ``body.tenant_id``. The model index is built from every module
  under ``warden/``, so a model imported from ``schemas.py`` is still seen. It
  is bound when the handler rebinds the field before use
  (``body.tenant_id = caller.bind(body.tenant_id)``, or any call to
  ``bind_tenant``/``bind`` with it), or rejects on a comparison with some
  ``*.tenant_id``.
* **a header read in code** - ``request.headers.get("X-Tenant-ID")`` anywhere
  in a module, not only in a route signature. Bound when the value goes into
  ``bind_tenant``/``bind``, or the read sits under ``if tier_header_trusted()``
  (dev/test, where no key exists to derive a tenant from).

A model passed whole to a helper that reads the tenant inside is not seen.

Detection lives here; the merge gate is
``warden/tests/test_tenant_isolation.py`` (CI runs pytest, not pre-commit),
which holds a may-only-shrink baseline. As a pre-commit hook this exits 1 on any
finding the baseline does not already record.
"""
from __future__ import annotations

import ast
import json
import sys
from collections.abc import Callable
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

#: Headers that name a tenant. A client writes them; only a key proves one.
_TENANT_HEADERS = frozenset({"x-tenant-id", "x-warden-tenant-id"})
#: Calls that turn a claimed tenant into the authenticated one (or refuse it).
_BINDERS = frozenset({"bind_tenant", "bind"})
#: Calls in a handler body that admit only the operator. An operator acting on
#: a named tenant is the legitimate case, as with `_BINDING_DEPENDENCIES`.
_OPERATOR_CHECKS = frozenset({
    "_require_admin", "require_admin", "_require_admin_key", "require_admin_key",
    "verify_admin_key", "_require_super_admin",
})
#: Claims a route must take from the caller, because proving them is the route's
#: job. Keyed like a finding without the route; each carries its reason, and
#: test_tenant_isolation.py fails on an entry that no longer matches anything.
PROVEN_CLAIMS: dict[str, str] = {
    "warden/api/fido_auth.py::authenticate_begin::body.tenant_id":
        "Passkey sign-in: the tenant is the account being signed into, and the "
        "ceremony issues a challenge only that tenant's registered credential can answer.",
    "warden/api/fido_auth.py::authenticate_complete::body.tenant_id":
        "Passkey sign-in: the assertion is verified against the named tenant's "
        "credential; a wrong name fails the signature check.",
}

#: Dependencies whose result is the caller's own, already-bound tenant.
_BOUND_TENANT_DEPENDENCIES = frozenset({
    "caller_tenant", "caller_tenant_path", "caller_tenant_header", "caller_tenant_form",
    "_caller_tenant", "_own_tenant",
})


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


# ── body fields ──────────────────────────────────────────────────────────────


def _model_tenant_fields(tree: ast.Module) -> dict[str, set[str]]:
    """``class X(BaseModel)`` -> the names of its fields that contain ``tenant``.

    Inherits within the index: ``class B(A)`` gets A's tenant fields when A is a
    model, in this module or (after merging) another one.
    """
    out: dict[str, set[str]] = {}
    bases: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        base_names = [_call_name(b) for b in node.bases]
        fields = {
            stmt.target.id
            for stmt in node.body
            if isinstance(stmt, ast.AnnAssign)
            and isinstance(stmt.target, ast.Name)
            and "tenant" in stmt.target.id.lower()
        }
        bases[node.name] = base_names
        if "BaseModel" in base_names or fields:
            out.setdefault(node.name, set()).update(fields)
    for name, parents in bases.items():
        for parent in parents:
            if parent in out and name in out:
                out[name] |= out[parent]
    return {k: v for k, v in out.items() if v}


_REPO_MODELS: dict[str, set[str]] | None = None


def _repo_models() -> dict[str, set[str]]:
    global _REPO_MODELS
    if _REPO_MODELS is None:
        root = Path(__file__).resolve().parents[1]
        merged: dict[str, set[str]] = {}
        for file in root.rglob("*.py"):
            if "tests" in file.parts:
                continue
            try:
                tree = ast.parse(file.read_text(encoding="utf-8"))
            except (SyntaxError, UnicodeDecodeError, OSError):
                continue
            for name, fields in _model_tenant_fields(tree).items():
                merged.setdefault(name, set()).update(fields)
        _REPO_MODELS = merged
    return _REPO_MODELS


def _annotation_names(node: ast.AST | None) -> set[str]:
    """``Model``, ``Model | None``, ``Optional[Model]``, ``list[Model]`` -> {"Model"}."""
    names: set[str] = set()
    if node is None:
        return names
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            names.add(sub.id)
        elif isinstance(sub, ast.Attribute):
            names.add(sub.attr)
        elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            names.add(sub.value.split("[")[0].split(".")[-1].strip())
    return names


def _is_field(node: ast.AST, obj: str, field: str) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == field
        and isinstance(node.value, ast.Name)
        and node.value.id == obj
    )


def _reads_field(fn: ast.AST, obj: str, field: str) -> bool:
    return any(
        isinstance(n, ast.Attribute) and _is_field(n, obj, field) and isinstance(n.ctx, ast.Load)
        for n in ast.walk(fn)
    )


def _binder_takes(call: ast.AST, pred: Callable[[ast.AST], bool]) -> bool:
    return (
        isinstance(call, ast.Call)
        and _call_name(call) in _BINDERS
        and any(pred(a) for a in [*call.args, *(k.value for k in call.keywords)])
    )


def _calls_operator_check(fn: ast.AST) -> bool:
    return any(
        isinstance(n, ast.Call) and _call_name(n) in _OPERATOR_CHECKS for n in ast.walk(fn)
    )


def _bound_tenant_params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    args = fn.args
    positional = args.posonlyargs + args.args
    defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
    pairs = list(zip(positional, defaults, strict=True)) + list(
        zip(args.kwonlyargs, args.kw_defaults, strict=True)
    )
    return {
        a.arg for a, d in pairs
        if d is not None and _depends_target(d) in _BOUND_TENANT_DEPENDENCIES
    }


def _field_is_bound(fn: ast.AST, obj: str, field: str, rejecters: frozenset[str]) -> bool:
    if _calls_operator_check(fn):
        return True
    bound_names = (
        _bound_tenant_params(fn) if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
        else set()
    )
    for node in ast.walk(fn):
        # body.tenant_id = caller.bind(body.tenant_id)  /  bind_tenant(auth, body.tenant_id)
        if _binder_takes(node, lambda a: _is_field(a, obj, field)):
            return True
        if isinstance(node, ast.If) and _raises(node.body, rejecters) | _raises(node.orelse, rejecters):
            for cmp in ast.walk(node.test):
                if not isinstance(cmp, ast.Compare):
                    continue
                ops = [cmp.left, *cmp.comparators]
                if any(_is_field(o, obj, field) for o in ops) and any(
                    (isinstance(o, ast.Attribute) and o.attr == "tenant_id"
                     and not _is_field(o, obj, field))
                    or (isinstance(o, ast.Name) and o.id in bound_names)
                    for o in ops
                ):
                    return True
    return False


# ── header reads ─────────────────────────────────────────────────────────────


def _header_name(call: ast.AST) -> str:
    """``x.headers.get("X-Tenant-ID", ...)`` / ``x.headers["X-Tenant-ID"]`` -> lower name."""
    target: ast.AST | None = None
    if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == "get":
        holder = call.func.value
        if isinstance(holder, ast.Attribute) and holder.attr == "headers" and call.args:
            target = call.args[0]
    elif isinstance(call, ast.Subscript) and isinstance(call.value, ast.Attribute) and call.value.attr == "headers":
        target = call.slice
    if isinstance(target, ast.Constant) and isinstance(target.value, str):
        return target.value.lower()
    return ""


def _under_trusted_dev_check(fn: ast.AST, read: ast.AST) -> bool:
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.If)
            and any(
                isinstance(c, ast.Call) and _call_name(c) == "tier_header_trusted"
                for c in ast.walk(node.test)
            )
            and any(n is read for stmt in node.body for n in ast.walk(stmt))
        ):
            return True
    return False


def _header_is_bound(fn: ast.AST, read: ast.AST) -> bool:
    if _under_trusted_dev_check(fn, read) or _calls_operator_check(fn):
        return True
    # bind_tenant(auth, request.headers.get("X-Tenant-ID")) - directly, or
    # through a local it was assigned to.
    names = {
        t.id
        for node in ast.walk(fn)
        if isinstance(node, ast.Assign) and any(n is read for n in ast.walk(node.value))
        for t in node.targets
        if isinstance(t, ast.Name)
    }
    for node in ast.walk(fn):
        if _binder_takes(
            node,
            lambda a: any(n is read for n in ast.walk(a))
            or (isinstance(a, ast.Name) and a.id in names),
        ):
            return True
    return False


def _source_of(default: ast.AST | None) -> str:
    if default is None:
        return "path/query"
    name = _call_name(default) if isinstance(default, ast.Call) else ""
    return name or "literal-default"


def scan_source(
    src: str, path: str, models: dict[str, set[str]] | None = None
) -> list[Finding]:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    aliases, routers = _module_context(tree)
    rejecters = frozenset(_rejecters(tree))
    findings: list[Finding] = []
    if models is None:
        models = {**_repo_models()}
    for name, fields in _model_tenant_fields(tree).items():
        models.setdefault(name, set()).update(fields)

    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorators = _route_decorators(fn)

        # Header reads count in any function: a helper the route calls is
        # where most of them live.
        for node in ast.walk(fn):
            header = _header_name(node)
            if header in _TENANT_HEADERS and not _header_is_bound(fn, node):
                route = ", ".join(_route_label(d) for d in decorators) or "helper"
                findings.append(Finding(path, getattr(node, "lineno", fn.lineno), fn.name,
                                        f"header:{header}", "header read", route))

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
                # A request body is a parameter with no default, or `Body(...)`.
                # Anything else (`auth: AuthResult = AuthDep`, `me = Depends(...)`)
                # is resolved server-side - its tenant_id is the answer, not a claim.
                if default is not None and _call_name(default) != "Body":
                    continue
                annotation = arg.annotation
                for model in _annotation_names(annotation) & models.keys():
                    for field in sorted(models[model]):
                        if not _reads_field(fn, arg.arg, field):
                            continue
                        if _field_is_bound(fn, arg.arg, field, rejecters):
                            continue
                        if f"{path}::{fn.name}::{arg.arg}.{field}" in PROVEN_CLAIMS:
                            continue
                        findings.append(Finding(path, fn.lineno, fn.name,
                                                f"{arg.arg}.{field}", "body", route))
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


def _is_lab(rel: str) -> bool:
    """A lab router is not mounted, so its routes are not reachable to isolate.

    The debt is not forgiven: leaving ``warden/surfaces.py`` puts the module
    back under this hook with no baseline entry to hide behind.
    """
    try:
        root = str(Path(__file__).resolve().parents[2])
        if root not in sys.path:
            sys.path.insert(0, root)
        from warden.surfaces import is_lab
    except Exception:  # noqa: BLE001 - if the list cannot be read, count everything
        return False
    return is_lab(rel.removesuffix(".py").replace("/", "."))


def scan_file(file: Path, rel: str) -> list[Finding]:
    if _is_lab(rel):
        return []
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
