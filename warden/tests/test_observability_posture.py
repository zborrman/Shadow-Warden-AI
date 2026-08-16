"""
warden/tests/test_observability_posture.py — OB-7 exposure guard.

Grafana is a credential store. It holds the connection details for every
datasource, the whole alerting configuration, and a login page in front of both.
Until OB-7 it was published on **all interfaces** as `"3001:3000"` with the
admin password defaulted in `docker-compose.yml` to `warden-grafana` — while
MinIO (9000/9091) and Jaeger (16686) in the same file were deliberately bound to
127.0.0.1 with comments explaining why.

That gap matters because of the project's own edge rule: every Cloudflare WAF
rule, rate limit and Bot-Fight check is bypassed by a request sent straight to
the origin IP. An internal surface published there is outside the entire edge
posture, protected by one shared password that was written in a public file.

`.env.example` compounded it by suggesting the value `admin`.

These checks are cheap and they fail loudly, because the natural direction of
drift is back: someone debugging reaches for `"3001:3000"` to get a browser on
it, and nothing would notice it stayed that way.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE = _ROOT / "docker-compose.yml"
_ENV_EXAMPLE = _ROOT / ".env.example"

#: Services that must never be reachable on the public origin IP. Each holds
#: credentials, object data, or an unauthenticated debugging surface.
_LOOPBACK_ONLY = ("grafana", "minio", "jaeger")

#: Images this track owns. A floating tag here means a `docker compose up` —
#: which CI autodeploy runs on every merge to main — can move a major version
#: under the alert provisioning schema or the scrape config.
_MUST_BE_PINNED = ("grafana", "prometheus")


def _compose() -> dict:
    assert _COMPOSE.exists(), f"missing {_COMPOSE}"
    return yaml.safe_load(_COMPOSE.read_text(encoding="utf-8")) or {}


def _published_ports(service: str) -> list[str]:
    svc = (_compose().get("services") or {}).get(service) or {}
    return [str(p) for p in svc.get("ports") or []]


def test_observability_surfaces_are_loopback_only() -> None:
    offenders: dict[str, list[str]] = {}
    services = _compose().get("services") or {}
    for name in _LOOPBACK_ONLY:
        if name not in services:
            continue
        bad = [
            p
            for p in _published_ports(name)
            if not p.startswith("127.0.0.1:") and not p.startswith("localhost:")
        ]
        if bad:
            offenders[name] = bad
    assert not offenders, (
        "Services publishing on all interfaces that must stay on loopback:\n"
        + "\n".join(f"  {svc}: {ports}" for svc, ports in sorted(offenders.items()))
        + "\n\nCloudflare's WAF and rate limits are bypassed by any request sent to "
        "the origin IP directly, so a published port here sits outside the edge "
        "posture entirely. Bind as \"127.0.0.1:<host>:<container>\" and reach it "
        "with `ssh -L <host>:127.0.0.1:<host> root@<server>`, or put it behind a "
        "Caddy vhost + Cloudflare Access (see docker/Caddyfile)."
    )


def test_grafana_admin_password_has_no_default() -> None:
    raw = _COMPOSE.read_text(encoding="utf-8")
    match = re.search(r"GF_SECURITY_ADMIN_PASSWORD=\$\{GRAFANA_PASSWORD([^}]*)\}", raw)
    assert match, "GF_SECURITY_ADMIN_PASSWORD is not sourced from ${GRAFANA_PASSWORD...}"
    modifier = match.group(1)
    assert modifier.startswith(":?"), (
        f"GRAFANA_PASSWORD is declared as ${{GRAFANA_PASSWORD{modifier}}} — a default "
        "means a fresh deploy boots with a password committed to this repository. "
        "Use ${GRAFANA_PASSWORD:?<message>} so compose refuses to start instead, "
        "mirroring the fail-closed WARDEN_API_KEY rule in warden/main.py."
    )


def test_env_example_does_not_ship_a_usable_default_password() -> None:
    assert _ENV_EXAMPLE.exists(), f"missing {_ENV_EXAMPLE}"
    for line in _ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("GRAFANA_PASSWORD="):
            continue
        value = stripped.split("=", 1)[1].strip()
        assert not value, (
            f".env.example ships GRAFANA_PASSWORD={value!r}. A copied example is a "
            "real deployment's starting point — this file previously suggested "
            "'admin'. Leave it empty so the ${GRAFANA_PASSWORD:?} guard in "
            "docker-compose.yml is what the operator meets."
        )


def _is_floating(image: str) -> bool:
    """True when the reference does not name a specific version.

    Note `image.endswith((":latest", ""))` is NOT this check — `endswith("")` is
    always True, so that form marks every image floating. Compare the tag.
    """
    if not image:
        return True
    tag = image.rsplit("/", 1)[-1]
    tag = tag.split(":", 1)[1] if ":" in tag else ""
    return tag in {"", "latest"}


def test_observability_images_are_pinned() -> None:
    services = _compose().get("services") or {}
    floating = {
        name: services[name]["image"]
        for name in _MUST_BE_PINNED
        if name in services and _is_floating(str(services[name].get("image", "")))
    }
    assert not floating, (
        "Observability images are on a floating tag:\n"
        + "\n".join(f"  {svc}: {img}" for svc, img in sorted(floating.items()))
        + "\n\n`:latest` had already carried Grafana to 12.4.1 — two majors past the "
        "\"version\": \"10.0.0\" the dashboards' own __requires blocks claimed. CI "
        "autodeploy runs `docker compose up` on every merge to main, so a floating "
        "tag lets a Grafana major rewrite the alert-provisioning schema during a "
        "deploy nobody reviewed. Pin to a version verified against what is running."
    )
