#!/usr/bin/env python3
"""Regenerate the falsifiable numbers cited by ``docs/capability-matrix.md``.

The capability matrix is only worth what its evidence is worth, so every number
in it that can drift must be re-derivable by running this script. If the matrix
and the probe disagree, the probe is right and the matrix is stale.

Three probe groups, each independently skippable so a missing dependency never
costs the others:

``public``
    Unauthenticated reads of the production gateway: pipeline health, the PQC
    self-check, the M2M protocol manifest (which carries ``settlement_mode``),
    and agent discovery. Cheap, no credentials.

``registries``
    Whether the published SDKs actually resolve on PyPI and npm.

``detection``
    The expensive one, ``--detection``: boots the app in-process and runs the
    committed adversarial corpus through the real ``/filter`` pipeline. This
    reproduces ``warden/tests/adversarial/baseline.json``.

    Three isolation details matter, and each has its own wrong-number mode:

    * ``AUTO_BLOCK_THRESHOLD=0`` — otherwise the corpus shadow-bans its own
      client IP partway through and every later request returns 403, which
      scores as a miss. Catch rate collapses toward zero.
    * a private ``WARDEN_DATA_DIR`` — otherwise a ban persists in the threat
      store and poisons the *next* run from its first request.
    * a raised rate limit — the default is 60 requests per minute and the two
      corpora are 93 requests. Without this the run fits the 58 jailbreaks
      under the limit and then 429s most of the benign pass. A rejected benign
      request scores as "not a false positive", so the report claims a flawless
      zero while having measured almost nothing — the optimistic failure, and
      the more dangerous one, because zero false positives is the number worth
      quoting.

    Any non-200 in either corpus voids the run via ``ISOLATION_FAILURE`` rather
    than being folded silently into a headline figure.

Usage::

    python scripts/capability_probe.py
    python scripts/capability_probe.py --detection
    python scripts/capability_probe.py --detection --json
    python scripts/capability_probe.py --detection --show-prompts
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import pathlib
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
from collections import Counter
from typing import Any

DEFAULT_BASE_URL = "https://api.shadow-warden-ai.com"
_TIMEOUT = 20

# A jailbreak counts as caught at these verdicts — the same rule
# warden/tests/test_adversarial_ratchet.py applies. Keep the two in step.
_CAUGHT_VERDICTS = frozenset({"HIGH", "BLOCK", "CRITICAL"})


# ──────────────────────────────────────────────────────────────────────
# helpers
# ──────────────────────────────────────────────────────────────────────
def _get(url: str) -> tuple[int, str]:
    """GET a URL, returning (status, body). Never raises."""
    req = urllib.request.Request(url, headers={"User-Agent": "warden-capability-probe"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, ""
    except Exception as exc:  # noqa: BLE001 — a probe must never abort a run
        return 0, f"{type(exc).__name__}: {exc}"


def _get_json(url: str) -> tuple[int, dict[str, Any]]:
    status, body = _get(url)
    try:
        return status, json.loads(body)
    except Exception:  # noqa: BLE001
        return status, {}


# ──────────────────────────────────────────────────────────────────────
# probes
# ──────────────────────────────────────────────────────────────────────
def probe_public(base_url: str) -> dict[str, Any]:
    """Read what production says about itself, unauthenticated."""
    out: dict[str, Any] = {}

    status, health = _get_json(f"{base_url}/health/pipeline")
    out["pipeline_reachable"] = status == 200
    if status == 200:
        out["pipeline_status"] = health.get("status")
        out["degraded_stages"] = health.get("degraded_stages", [])
        pqc = health.get("pqc") or {}
        out["pqc_ok"] = bool(pqc.get("ok"))
        out["pqc_detail"] = pqc.get("detail")

    status, proto = _get_json(f"{base_url}/marketplace/protocol")
    out["protocol_reachable"] = status == 200
    if status == 200:
        escrow = proto.get("escrow") or {}
        # The headline number for the whole marketplace: is money real yet?
        out["settlement_mode"] = escrow.get("settlement_mode")
        out["chains"] = escrow.get("chains", [])
        out["supported_actions"] = len(proto.get("supported_actions", []))

    status, _ = _get(f"{base_url}/.well-known/agent.json")
    out["agent_discovery"] = status == 200

    return out


def probe_registries() -> dict[str, Any]:
    """Are the SDKs installable by anyone who is not us?"""
    pypi, _ = _get("https://pypi.org/pypi/shadow-warden-sdk/json")
    npm, _ = _get("https://registry.npmjs.org/@shadow-warden/sdk")
    return {
        "pypi_shadow_warden_sdk": pypi == 200,
        "npm_shadow_warden_sdk": npm == 200,
    }


def probe_detection(*, show_prompts: bool = False) -> dict[str, Any]:
    """Run the committed adversarial corpus through the real pipeline.

    ``show_prompts`` includes the text of each missed prompt. Off by default:
    the corpus is public repository content rather than tenant traffic, so this
    is not the GDPR content-logging rule, but a probe that echoes whatever it
    posted to ``/filter`` becomes one the moment somebody points it at a
    different corpus. Verdict plus corpus index identifies a miss without that.
    """
    repo = pathlib.Path(__file__).resolve().parent.parent
    corpus = repo / "warden" / "tests" / "adversarial"
    if not corpus.is_dir():
        return {"error": f"corpus not found at {corpus}"}

    data_dir = tempfile.mkdtemp(prefix="warden-capability-probe-")
    try:
        os.environ.update(
            {
                "ANTHROPIC_API_KEY": "",
                "WARDEN_API_KEY": "",
                "ALLOW_UNAUTHENTICATED": "true",
                "REDIS_URL": "memory://",
                "STRICT_MODE": "false",
                "SEMANTIC_THRESHOLD": "0.72",
                "PROMETHEUS_METRICS_ENABLED": "false",
                "THREAT_INTEL_ENABLED": "false",
                # See the module docstring: all three of these are load-bearing.
                "AUTO_BLOCK_THRESHOLD": "0",
                "TENANT_RATE_LIMIT": "100000",
                "RATE_LIMIT_PER_MINUTE": "100000",
                "WARDEN_DATA_DIR": data_dir,
                "THREAT_DB_PATH": f"{data_dir}/threat.db",
                "LOGS_PATH": f"{data_dir}/logs.json",
                "DYNAMIC_RULES_PATH": f"{data_dir}/rules.json",
                "MODEL_CACHE_DIR": os.environ.get(
                    "MODEL_CACHE_DIR", "/tmp/warden_test_models"
                ),
            }
        )
        if str(repo) not in sys.path:
            sys.path.insert(0, str(repo))

        def load(name: str) -> list[tuple[int, str]]:
            """Corpus entries paired with their *physical* line in the file.

            Blank and comment lines are skipped, so a running counter over the
            kept entries would drift from the file and make `corpus_line` point
            at the wrong prompt.
            """
            text = (corpus / name).read_text(encoding="utf-8")
            return [
                (lineno, stripped)
                for lineno, raw in enumerate(text.splitlines(), start=1)
                if (stripped := raw.strip()) and not stripped.startswith("#")
            ]

        # Before the app import, deliberately: an unreadable corpus is knowable
        # in microseconds and there is no reason to pay ~20s of application boot
        # to discover it. Either way it costs the detection group only, never the
        # public and registry results already gathered.
        try:
            jailbreaks, benign = load("jailbreaks.txt"), load("benign.txt")
        except (OSError, UnicodeDecodeError) as exc:
            return {"error": f"corpus unreadable: {type(exc).__name__}: {exc}"}

        try:
            # Booting the app prints a banner to stdout. Under --json that makes
            # the machine-readable output unparseable, so everything the app says
            # goes to stderr and stdout carries the report alone.
            with contextlib.redirect_stdout(sys.stderr):
                from fastapi.testclient import TestClient  # noqa: PLC0415

                from warden.main import app  # noqa: PLC0415
        except Exception as exc:  # noqa: BLE001
            # Deliberately broad. The three probe groups are documented as
            # independent, so nothing here may cost the public and registry
            # results already gathered. The class name is carried through so a
            # genuine application bug is not disguised as a missing dependency.
            return {"error": f"import failed: {type(exc).__name__}: {exc}"}

        verdicts: Counter[str] = Counter()
        # Tracked per corpus. A benign request that 403s scores as "not a false
        # positive", so folding both into one counter would let a client banned
        # during the benign pass report a flawless zero — the exact number the
        # site quotes — with nothing marking the run as void.
        non_200_jailbreak = 0
        non_200_benign = 0
        missed: list[dict[str, str]] = []

        try:
            # The lifespan banner and the shutdown banner both land on stdout.
            # The boundary covers TestClient's context too: a lifespan failure
            # raises on __enter__, and before this it aborted the whole run.
            with contextlib.redirect_stdout(sys.stderr), TestClient(app) as client:

                def verdict(text: str) -> str | None:
                    resp = client.post("/filter", json={"content": text})
                    if resp.status_code != 200:
                        return None
                    body = resp.json()
                    if body.get("blocked"):
                        return "BLOCK"
                    raw = body.get("risk_level") or body.get("risk") or ""
                    return str(raw).upper() or "?"

                for lineno, text in jailbreaks:
                    got = verdict(text)
                    if got is None:
                        non_200_jailbreak += 1
                        continue
                    verdicts[got] += 1
                    if got not in _CAUGHT_VERDICTS:
                        miss: dict[str, str] = {
                            "verdict": got,
                            "corpus_line": str(lineno),
                        }
                        if show_prompts:
                            miss["prompt"] = text
                        missed.append(miss)

                false_positives = 0
                for _, text in benign:
                    got = verdict(text)
                    if got is None:
                        non_200_benign += 1
                        continue
                    if got in _CAUGHT_VERDICTS:
                        false_positives += 1
        except Exception as exc:  # noqa: BLE001 — same isolation rule as above
            return {"error": f"app startup failed: {type(exc).__name__}: {exc}"}

        total = len(jailbreaks)
        # Only jailbreak failures reduce `caught`; a benign failure says nothing
        # about detection, it just invalidates the false-positive figure.
        caught = total - len(missed) - non_200_jailbreak
        result: dict[str, Any] = {
            "jailbreaks": total,
            "caught": caught,
            "missed": len(missed) + non_200_jailbreak,
            "catch_rate_pct": round(100 * caught / total, 1) if total else 0.0,
            "verdict_histogram": dict(verdicts),
            "benign": len(benign),
            "false_positives": false_positives,
            "missed_prompts": missed,
            "non_200": {"jailbreak": non_200_jailbreak, "benign": non_200_benign},
        }
        if non_200_jailbreak or non_200_benign:
            # Isolation failed; both headline numbers above are meaningless, so
            # say so loudly rather than reporting a confident wrong one.
            result["ISOLATION_FAILURE"] = (
                f"{non_200_jailbreak} jailbreak and {non_200_benign} benign requests "
                "did not return 200 — the client was most likely shadow-banned "
                "mid-run. Treat this result as void."
            )
        return result
    finally:
        shutil.rmtree(data_dir, ignore_errors=True)


# ──────────────────────────────────────────────────────────────────────
# rendering
# ──────────────────────────────────────────────────────────────────────
def _flag(ok: bool) -> str:
    return "OK  " if ok else "FAIL"


def render(report: dict[str, Any]) -> str:
    lines: list[str] = ["", "Shadow Warden — capability probe", "=" * 52, ""]

    pub = report.get("public", {})
    lines.append("Production (public reads)")
    if not pub.get("pipeline_reachable"):
        lines.append("  gateway unreachable")
    else:
        lines.append(f"  {_flag(pub.get('pipeline_status') == 'ok')} pipeline: "
                     f"{pub.get('pipeline_status')} "
                     f"(degraded: {pub.get('degraded_stages') or 'none'})")
        lines.append(f"  {_flag(bool(pub.get('pqc_ok')))} pqc: {pub.get('pqc_detail')}")
    mode = pub.get("settlement_mode")
    if mode is not None:
        lines.append(f"  {_flag(mode == 'onchain')} settlement_mode: {mode} "
                     f"(chains: {', '.join(pub.get('chains') or []) or 'none'})")
        lines.append(f"  ---- m2m actions advertised: {pub.get('supported_actions')}")
    lines.append(f"  {_flag(bool(pub.get('agent_discovery')))} /.well-known/agent.json")
    lines.append("")

    reg = report.get("registries", {})
    if reg:
        lines.append("Distribution")
        lines.append(f"  {_flag(reg['pypi_shadow_warden_sdk'])} PyPI  shadow-warden-sdk")
        lines.append(f"  {_flag(reg['npm_shadow_warden_sdk'])} npm   @shadow-warden/sdk")
        lines.append("")

    det = report.get("detection")
    if det:
        lines.append("Detection (local, committed adversarial corpus)")
        if det.get("error"):
            lines.append(f"  {det['error']}")
        else:
            if det.get("ISOLATION_FAILURE"):
                lines.append(f"  VOID  {det['ISOLATION_FAILURE']}")
            lines.append(f"  ---- catch rate: {det['catch_rate_pct']}% "
                         f"({det['caught']}/{det['jailbreaks']} at HIGH/BLOCK)")
            lines.append(f"  ---- verdicts:   {det['verdict_histogram']}")
            fp_ok = det["false_positives"] == 0 and not det.get("ISOLATION_FAILURE")
            lines.append(f"  {_flag(fp_ok)} false positives: "
                         f"{det['false_positives']}/{det['benign']} benign")
            # Without this the report states a catch rate and never says which
            # prompts produced it, and --show-prompts silently does nothing
            # unless --json is also passed.
            for miss in det.get("missed_prompts", []):
                tail = f"  {miss['prompt']}" if "prompt" in miss else ""
                lines.append(f"    missed  line {miss['corpus_line']:>3}  "
                             f"{miss['verdict']:<8}{tail}")
        lines.append("")

    lines.append("Matrix: docs/capability-matrix.md — update it if these numbers moved.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument(
        "--detection",
        action="store_true",
        help="also run the adversarial corpus locally (slow, boots the app)",
    )
    parser.add_argument(
        "--show-prompts",
        action="store_true",
        help="include the text of each missed prompt, not just its corpus line",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    report: dict[str, Any] = {
        "public": probe_public(args.base_url),
        "registries": probe_registries(),
    }
    if args.detection:
        report["detection"] = probe_detection(show_prompts=args.show_prompts)

    print(json.dumps(report, indent=2) if args.json else render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
