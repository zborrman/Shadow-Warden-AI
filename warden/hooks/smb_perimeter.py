"""warden/hooks/smb_perimeter.py — the SMB profile's perimeter, checked.

`CONTRIBUTING.md:201` and `Hook.md:263` have described a `check-smb-compose`
guard for months: "verifies the SMB stack before pushing". It never existed.
Not in `hooks/`, not among the fourteen ids in `.pre-commit-config.yaml`, not in
any workflow. The least-protected deployment profile in the repo was the one
with zero automated checks, while two documents said otherwise.

That matters because of what was behind the missing guard. `docker-compose.smb.yml`
publishes the Streamlit analytics dashboard on `8501:8501` — every interface, no
loopback prefix — and the dashboard reads the live `/filter` event stream, so it
shows a customer's real security telemetry. Its auth is real (bcrypt, lockout,
optional SAML) but `warden/analytics/auth.py` treats an unset password hash as
dev mode and lets everyone in, and `DASHBOARD_PASSWORD_HASH` appears in neither
the compose file nor `.env.smb.example`. An MSP following the example env file
gets an open panel and no hint that a variable was missing.

Verified 2026-09-04: our own production is NOT exposed this way — it runs the
enterprise `docker-compose.yml`, where the same app sits behind `expose:` on
8502, and `curl` to the origin on 8501/8502 times out. This is a latent defect
shipped to whoever deploys the SMB profile, not a live hole in our host. The
distinction changes the words, not the priority.

Run directly (pre-commit) or via warden/tests/test_smb_perimeter.py, which is
what actually gates a merge — CI does not run pre-commit.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE = _ROOT / "docker-compose.smb.yml"
_ENV_EXAMPLE = _ROOT / ".env.smb.example"

#: Ports the SMB profile is *meant* to publish. 8001 is the gateway API — the
#: product itself; a customer's application has to reach it. Everything else is
#: an operator surface and belongs behind loopback or a tunnel, which is the
#: same rule OB-7 applied to Grafana: a request straight to the origin IP
#: bypasses Cloudflare's WAF and rate limits entirely.
PUBLIC_PORTS: frozenset[str] = frozenset({"8001"})

#: Env vars whose absence silently disables a security control. Listing one here
#: means: it must appear in .env.smb.example, so an operator reading the example
#: learns the variable exists. A control you are never told to configure is not
#: a control.
REQUIRED_ENV_KEYS: tuple[str, ...] = ("DASHBOARD_PASSWORD_HASH",)

#: Services the SMB tier must not carry. This is the check the documentation
#: already credited the missing hook with performing.
ENTERPRISE_ONLY: tuple[str, ...] = ("minio", "prometheus", "grafana")

_PORT_LINE = re.compile(r'^\s*-\s*"(?P<mapping>[^"]+)"\s*$')
_SERVICE = re.compile(r"^  (?P<name>[a-z0-9][a-z0-9_-]*):\s*$")


def _published_ports(text: str) -> list[tuple[int, str]]:
    """(line number, mapping) for every `- "…"` entry under a `ports:` key."""
    out: list[tuple[int, str]] = []
    in_ports = False
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("ports:"):
            in_ports = True
            continue
        if in_ports:
            m = _PORT_LINE.match(line)
            if m:
                out.append((lineno, m.group("mapping")))
                continue
            # Any other non-blank line ends the block.
            if stripped and not stripped.startswith("#"):
                in_ports = False
    return out


def _host_port(mapping: str) -> str:
    """`127.0.0.1:8501:8501` -> `8501`; `8501:8501` -> `8501`."""
    parts = mapping.split(":")
    return parts[-2] if len(parts) >= 2 else parts[0]


def _is_loopback_bound(mapping: str) -> bool:
    return mapping.startswith(("127.0.0.1:", "localhost:", "::1:"))


def check_ports(text: str) -> list[str]:
    """Every published port is either allow-listed or bound to loopback."""
    problems: list[str] = []
    for lineno, mapping in _published_ports(text):
        if _is_loopback_bound(mapping):
            continue
        if _host_port(mapping) in PUBLIC_PORTS:
            continue
        problems.append(
            f"docker-compose.smb.yml:{lineno}: {mapping!r} is published on every "
            f"interface. Bind it to loopback (127.0.0.1:{mapping}) or add the "
            f"port to PUBLIC_PORTS with a reason."
        )
    return problems


def check_required_env(env_text: str) -> list[str]:
    return [
        f".env.smb.example does not mention {key} — an operator copying it will "
        f"never learn the variable exists, and the control it guards stays off."
        for key in REQUIRED_ENV_KEYS
        if key not in env_text
    ]


def check_no_enterprise_services(text: str) -> list[str]:
    names = {m.group("name") for m in (_SERVICE.match(ln) for ln in text.splitlines()) if m}
    return [
        f"docker-compose.smb.yml declares {svc!r}, which is enterprise-tier only."
        for svc in ENTERPRISE_ONLY
        if svc in names
    ]


def run() -> list[str]:
    if not _COMPOSE.exists():
        return ["docker-compose.smb.yml is missing — this guard has nothing to check."]
    text = _COMPOSE.read_text(encoding="utf-8")
    env_text = _ENV_EXAMPLE.read_text(encoding="utf-8") if _ENV_EXAMPLE.exists() else ""
    if not _ENV_EXAMPLE.exists():
        return [".env.smb.example is missing — operators have no reference config."]
    return check_ports(text) + check_required_env(env_text) + check_no_enterprise_services(text)


def main() -> int:
    problems = run()
    if not problems:
        return 0
    print("SMB profile perimeter check failed:\n", file=sys.stderr)
    for p in problems:
        print(f"  • {p}", file=sys.stderr)
    print(
        "\nThe SMB profile ships to MSPs. A port published here is published on "
        "their host, and a variable absent from the example env file is a "
        "control they are never told to turn on.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
