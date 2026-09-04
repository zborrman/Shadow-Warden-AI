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

import sys
from pathlib import Path

import yaml

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

def _services(doc: dict) -> dict:
    svc = doc.get("services")
    return svc if isinstance(svc, dict) else {}


def _port_mappings(doc: dict) -> list[tuple[str, str]]:
    """(service name, mapping) for every published port, in any Compose form.

    Reading the YAML rather than matching lines is not pedantry here. The first
    version of this guard matched `- "8501:8501"` with a regex that required
    double quotes, so `- 8501:8501` and `- '8501:8501'` walked straight past it
    — and the long form, `{target: 8501, published: 8501}`, was invisible
    entirely. A perimeter check with three spellings it cannot see is the kind
    of guard this repo keeps finding: green, and blind.

    It also scoped `services` by indentation, which counted `volumes:` entries
    as services. Compose already knows what a service is; ask it.
    """
    out: list[tuple[str, str]] = []
    for name, body in _services(doc).items():
        if not isinstance(body, dict):
            continue
        for entry in body.get("ports") or []:
            if isinstance(entry, str):
                out.append((name, entry))
            elif isinstance(entry, int):
                # `- 8501` publishes a container port on an ephemeral host port,
                # still on every interface.
                out.append((name, str(entry)))
            elif isinstance(entry, dict):
                published = entry.get("published")
                host_ip = entry.get("host_ip") or entry.get("host-ip")
                target = entry.get("target")
                if published is None:
                    continue
                mapping = f"{published}:{target}" if target is not None else str(published)
                out.append((name, f"{host_ip}:{mapping}" if host_ip else mapping))
    return out


def _host_port(mapping: str) -> str:
    """`127.0.0.1:8501:8501` -> `8501`; `8501:8501` -> `8501`; `8501` -> `8501`."""
    parts = mapping.split(":")
    return parts[-2] if len(parts) >= 2 else parts[0]


def _is_loopback_bound(mapping: str) -> bool:
    return mapping.startswith(("127.0.0.1:", "localhost:", "::1:", "[::1]:"))


def check_ports(doc: dict) -> list[str]:
    """Every published port is either allow-listed or bound to loopback."""
    problems: list[str] = []
    for service, mapping in _port_mappings(doc):
        if _is_loopback_bound(mapping):
            continue
        if _host_port(mapping) in PUBLIC_PORTS:
            continue
        problems.append(
            f"service {service!r} publishes {mapping!r} on every interface. "
            f"Bind it to loopback (127.0.0.1:...) or add the host port to "
            f"PUBLIC_PORTS with a reason."
        )
    return problems


def check_required_env(env_text: str) -> list[str]:
    """`KEY=` must be an active assignment, not a mention.

    Matching the bare name meant a variable named only in a comment satisfied
    the check — including the explanatory comment this guard's own fix added to
    .env.smb.example. The guard would then have passed on a file that still
    told the operator nothing actionable.
    """
    problems: list[str] = []
    for key in REQUIRED_ENV_KEYS:
        assigned = any(
            line.lstrip().startswith(f"{key}=")
            for line in env_text.splitlines()
            if not line.lstrip().startswith("#")
        )
        if not assigned:
            problems.append(
                f".env.smb.example has no active `{key}=` line — an operator "
                f"copying it will never learn the variable exists, and the "
                f"control it guards stays off. A mention in a comment does not "
                f"count; the line has to be there to be filled in."
            )
    return problems


def check_no_enterprise_services(doc: dict) -> list[str]:
    """Scoped to the services mapping — `volumes:` is not a service."""
    names = set(_services(doc))
    return [
        f"docker-compose.smb.yml declares service {svc!r}, which is enterprise-tier only."
        for svc in ENTERPRISE_ONLY
        if svc in names
    ]


def run() -> list[str]:
    if not _COMPOSE.exists():
        return ["docker-compose.smb.yml is missing — this guard has nothing to check."]
    if not _ENV_EXAMPLE.exists():
        return [".env.smb.example is missing — operators have no reference config."]
    doc = yaml.safe_load(_COMPOSE.read_text(encoding="utf-8")) or {}
    env_text = _ENV_EXAMPLE.read_text(encoding="utf-8")
    return (
        check_ports(doc)
        + check_required_env(env_text)
        + check_no_enterprise_services(doc)
    )


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
