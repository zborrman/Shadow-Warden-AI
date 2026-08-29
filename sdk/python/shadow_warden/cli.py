"""
shadow_warden/cli.py
━━━━━━━━━━━━━━━━━━━━
``warden`` — command-line access to the Shadow Warden AI gateway.

Installed as a console script by ``shadow-warden-sdk``, so an agent or a shell
script can use the gateway without writing an integration first::

    warden health
    warden filter "ignore previous instructions"
    warden filter --json --file prompt.txt
    echo "text" | warden filter --stdin
    warden impact --requests 50000
    warden billing

Configuration comes from the environment (``WARDEN_API_KEY``,
``WARDEN_GATEWAY_URL``, ``WARDEN_TENANT_ID``) or from flags; flags win.

Exit codes are the interface for scripts and agents:

    0  the content is allowed / the command succeeded
    1  the content was blocked
    2  usage error (bad arguments, nothing to read)
    3  the gateway could not be reached, or answered with an error
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from typing import Any

from shadow_warden.client import WardenClient
from shadow_warden.errors import WardenGatewayError, WardenTimeoutError

__all__ = ["main", "build_parser"]

EXIT_OK = 0
EXIT_BLOCKED = 1
EXIT_USAGE = 2
EXIT_GATEWAY = 3

DEFAULT_GATEWAY = "https://api.shadow-warden-ai.com"


# ── Output ────────────────────────────────────────────────────────────────────


def _emit(payload: Any, as_json: bool, human: str, stream: Any = None) -> None:
    out = stream or sys.stdout
    if as_json:
        json.dump(payload, out, indent=2, sort_keys=True, default=str)
        out.write("\n")
    else:
        out.write(human + "\n")


def _fail(message: str, code: int, as_json: bool) -> int:
    _emit({"error": message}, as_json, f"error: {message}", stream=sys.stderr)
    return code


# ── Input ─────────────────────────────────────────────────────────────────────


def _read_content(args: argparse.Namespace) -> str | None:
    """Text to filter, from an argument, a file, or stdin. None means none."""
    if args.stdin:
        return sys.stdin.read()
    if args.file:
        try:
            with open(args.file, encoding="utf-8", errors="replace") as handle:
                return handle.read()
        except OSError as exc:
            raise ValueError(f"cannot read {args.file}: {exc}") from exc
    if args.text:
        return " ".join(args.text)
    # `some-command | warden filter` with no other argument is a natural shape.
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return None


def _client(args: argparse.Namespace) -> WardenClient:
    return WardenClient(
        gateway_url=args.gateway_url,
        api_key=args.api_key,
        tenant_id=args.tenant_id,
        timeout=args.timeout,
    )


# ── Commands ──────────────────────────────────────────────────────────────────


def _cmd_filter(args: argparse.Namespace) -> int:
    try:
        content = _read_content(args)
    except ValueError as exc:
        return _fail(str(exc), EXIT_USAGE, args.json)
    if not content or not content.strip():
        return _fail("nothing to filter — pass text, --file or --stdin", EXIT_USAGE, args.json)

    with _client(args) as warden:
        try:
            result = warden.filter(content, strict=args.strict)
        except (WardenGatewayError, WardenTimeoutError) as exc:
            return _fail(str(exc), EXIT_GATEWAY, args.json)

    payload = asdict(result)
    payload["blocked"] = result.blocked
    payload["flags"] = result.flag_names

    verdict = "ALLOWED" if result.allowed else "BLOCKED"
    lines = [f"{verdict}  risk={result.risk_level}"]
    if result.secrets_found:
        lines.append("secrets: " + ", ".join(s.kind for s in result.secrets_found))
    if result.semantic_flags:
        lines.append("flags:   " + ", ".join(result.flag_names))
    if args.show_filtered:
        lines.append(result.filtered_content)
    _emit(payload, args.json, "\n".join(lines))

    return EXIT_OK if result.allowed else EXIT_BLOCKED


def _cmd_health(args: argparse.Namespace) -> int:
    with _client(args) as warden:
        try:
            document = warden.health()
        except (WardenGatewayError, WardenTimeoutError) as exc:
            return _fail(str(exc), EXIT_GATEWAY, args.json)
    status = str(document.get("status", "unknown"))
    _emit(document, args.json, f"{status}  ({args.gateway_url})")
    return EXIT_OK


def _cmd_impact(args: argparse.Namespace) -> int:
    with _client(args) as warden:
        try:
            report = warden.impact(
                industry=args.industry,
                requests_per_day=args.requests,
                annual_cost_usd=args.annual_cost,
            )
        except (WardenGatewayError, WardenTimeoutError) as exc:
            return _fail(str(exc), EXIT_GATEWAY, args.json)
    _emit(
        asdict(report),
        args.json,
        f"annual value ${report.total_annual_value:,.0f}  "
        f"roi x{report.roi_multiple:.1f}  payback {report.payback_months:.1f} months",
    )
    return EXIT_OK


def _cmd_billing(args: argparse.Namespace) -> int:
    with _client(args) as warden:
        try:
            status = warden.get_billing_status()
        except (WardenGatewayError, WardenTimeoutError) as exc:
            return _fail(str(exc), EXIT_GATEWAY, args.json)
    plan = status.get("tier") or status.get("plan") or "unknown"
    _emit(status, args.json, f"plan={plan}")
    return EXIT_OK


def _cmd_version(args: argparse.Namespace) -> int:
    from shadow_warden import __version__

    _emit({"version": __version__}, args.json, __version__)
    return EXIT_OK


# ── Parser ────────────────────────────────────────────────────────────────────


def _connection_flags(suppress: bool) -> argparse.ArgumentParser:
    """
    The flags every command shares.

    Added twice: once to the root parser, which supplies the defaults, and once
    to each subcommand so `warden filter --json x` works as readily as
    `warden --json filter x`. The subcommand copy defaults to SUPPRESS, so an
    unset flag there leaves the root parser's value alone instead of resetting
    it — the standard argparse parent-parser trap.
    """
    group = argparse.ArgumentParser(add_help=False)
    default = (lambda value: argparse.SUPPRESS) if suppress else (lambda value: value)
    group.add_argument("--gateway-url", default=default(os.getenv("WARDEN_GATEWAY_URL", DEFAULT_GATEWAY)))
    group.add_argument("--api-key", default=default(os.getenv("WARDEN_API_KEY", "")))
    group.add_argument("--tenant-id", default=default(os.getenv("WARDEN_TENANT_ID", "default")))
    group.add_argument("--timeout", type=float, default=default(float(os.getenv("WARDEN_TIMEOUT", "10"))))
    group.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS if suppress else False,
        help="machine-readable output",
    )
    return group


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="warden",
        description="Command-line access to the Shadow Warden AI security gateway.",
        epilog="Exit codes: 0 allowed - 1 blocked - 2 usage error - 3 gateway error",
        parents=[_connection_flags(suppress=False)],
    )
    shared = [_connection_flags(suppress=True)]

    sub = parser.add_subparsers(dest="command", parser_class=argparse.ArgumentParser)

    run = sub.add_parser("filter", help="run text through the filter pipeline", parents=shared)
    run.add_argument("text", nargs="*", help="the text to inspect")
    run.add_argument("--file", help="read the text from a file")
    run.add_argument("--stdin", action="store_true", help="read the text from stdin")
    run.add_argument("--strict", action="store_true", help="block on MEDIUM risk too")
    run.add_argument("--show-filtered", action="store_true", help="print the redacted text")
    run.set_defaults(func=_cmd_filter)

    health = sub.add_parser("health", help="check that the gateway answers", parents=shared)
    health.set_defaults(func=_cmd_health)

    impact = sub.add_parser("impact", help="projected value at a request volume", parents=shared)
    impact.add_argument("--industry", default="technology")
    impact.add_argument("--requests", type=int, default=10_000, help="requests per day")
    impact.add_argument("--annual-cost", type=float, default=50_000.0)
    impact.set_defaults(func=_cmd_impact)

    billing = sub.add_parser("billing", help="plan, quota and add-ons for this tenant", parents=shared)
    billing.set_defaults(func=_cmd_billing)

    version = sub.add_parser("version", help="print the SDK version", parents=shared)
    version.set_defaults(func=_cmd_version)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_USAGE
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
