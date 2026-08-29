"""
warden/tests/test_site_agent_readiness.py — the site stays legible to agents.

An external readiness audit (2026-08-28) found four things wrong with what
www.shadow-warden-ai.com hands a non-browser client:

  * `Accept: text/markdown` returned `text/html`, and no response carried
    `Vary: Accept` — so a CDN could serve either variant to either client;
  * the 404 body was an HTML shell with one link home, nothing an agent could
    use to recover;
  * the homepage carried no JSON-LD, so identity had to be inferred from
    marketing copy;
  * `llms.txt` said what the product is, never when an agent should reach for it.

The fixes live in four places that can drift apart: `edge/negotiate.mjs` (the
Vercel edge middleware's decision), `docker/Caddyfile` (the apex, served from
`landing/`), `vercel.json`, and the markdown corpus under `site/public`. These
tests hold them together. What they cannot do is prove the deployed edge
behaves — `edge/negotiate.e2e.test.mjs` does that against the built site, and
`node --test edge/` runs in CI.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_SITE = _ROOT / "site"
_PUBLIC = _SITE / "public"
_PAGES = _SITE / "src" / "pages"
_LAYOUTS = _SITE / "src" / "layouts"
_NEGOTIATE = _ROOT / "edge" / "negotiate.mjs"
_MIDDLEWARE = _ROOT / "middleware.ts"
_CADDYFILE = _ROOT / "docker" / "Caddyfile"
_VERCEL = _ROOT / "vercel.json"
_LANDING = _ROOT / "landing"

pytestmark = pytest.mark.skipif(not _SITE.is_dir(), reason="site/ not present in this checkout")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _markdown_routes() -> dict[str, str]:
    """Parse MARKDOWN_ROUTES out of the edge module — the one source of truth."""
    src = _read(_NEGOTIATE)
    block = re.search(r"MARKDOWN_ROUTES = Object\.freeze\(\{(.*?)\}\)", src, re.S)
    assert block, "MARKDOWN_ROUTES is gone or reshaped — re-check this guard"
    return dict(re.findall(r'"([^"]+)":\s*"([^"]+)"', block.group(1)))


# ── The markdown corpus ───────────────────────────────────────────────────────


class TestMarkdownRepresentations:
    def test_every_negotiated_route_has_a_markdown_file(self):
        for route, target in _markdown_routes().items():
            path = _PUBLIC / target.lstrip("/")
            assert path.is_file(), f"{route} negotiates to {target}, which does not exist"

    def test_every_markdown_file_is_reachable(self):
        """A markdown file nothing routes to is a file nobody will ever read."""
        targets = set(_markdown_routes().values())
        # 404.md is served on any unknown path rather than from a fixed route.
        targets.add("/404.md")
        for path in _PUBLIC.glob("*.md"):
            assert f"/{path.name}" in targets, f"{path.name} is served by no route"

    def test_markdown_files_open_with_a_heading(self):
        for path in _PUBLIC.rglob("*.md"):
            assert _read(path).lstrip().startswith("#"), f"{path.name} has no title"

    def test_every_negotiated_route_is_a_real_page(self):
        """A route with a markdown twin but no page would 404 for browsers."""
        for route in _markdown_routes():
            if route == "/":
                assert (_PAGES / "index.astro").is_file()
                continue
            name = route.strip("/")
            assert (_PAGES / f"{name}.astro").is_file() or (_PAGES / name / "index.astro").is_file(), (
                f"{route} negotiates markdown but has no Astro page"
            )

    def test_pages_declare_their_markdown_twin(self):
        """
        The `markdown` prop renders the `rel="alternate"` link. If a page stops
        declaring it, agents lose the discovery path even though negotiation
        still works — a silent half-regression.
        """
        for route, target in _markdown_routes().items():
            name = "index" if route == "/" else route.strip("/")
            page = _PAGES / f"{name}.astro"
            if not page.is_file():
                page = _PAGES / name / "index.astro"
            assert f'markdown="{target}"' in _read(page), (
                f"{page.name} does not declare markdown={target}"
            )

    def test_the_404_page_declares_its_markdown_twin(self):
        assert 'markdown="/404.md"' in _read(_PAGES / "404.astro")


# ── The 404 ───────────────────────────────────────────────────────────────────


class TestNotFound:
    _RECOVERY = ("llms.txt", "sitemap-index.xml", "agent-instructions.md", "/doc", "openapi.json")

    def test_the_markdown_404_points_somewhere_useful(self):
        body = _read(_PUBLIC / "404.md")
        for marker in self._RECOVERY:
            assert marker in body, f"404.md does not mention {marker}"

    def test_the_html_404_points_somewhere_useful(self):
        body = _read(_PAGES / "404.astro")
        for marker in self._RECOVERY:
            assert marker in body, f"404.astro does not mention {marker}"

    def test_the_apex_no_longer_answers_every_path_with_the_homepage(self):
        """
        `try_files … /index.html` made every unknown URL a 200 of the homepage,
        which tells a crawler that every path it invents exists.
        """
        caddy = _read(_CADDYFILE)
        assert "try_files {path} {path}/index.html {path}.html /index.html" not in caddy, (
            "the landing vhost still falls back to /index.html — every 404 would be a 200"
        )
        assert "handle_errors" in caddy, "the landing vhost serves no error page"
        assert "status {err.status_code}" in caddy, (
            "the error page would be served with 200 — the status is the whole point"
        )

    def test_the_apex_serves_the_markdown_404_to_a_markdown_client(self):
        """
        Both surfaces must answer a missing path the same way. The apex served
        the HTML shell to every client until review of #409 caught it.
        """
        caddy = _read(_CADDYFILE)
        assert "@md_notfound" in caddy, "the apex has no markdown branch for 404s"
        assert "rewrite * /404.md" in caddy


# ── Content negotiation ───────────────────────────────────────────────────────


class TestContentNegotiation:
    def test_the_middleware_uses_the_shared_planner(self):
        """
        The e2e test and the preview harness drive `planRequest`. If the
        middleware stops doing the same, CI would be testing a second
        implementation of the rules rather than the deployed one.
        """
        src = _read(_MIDDLEWARE)
        assert "./edge/negotiate.mjs" in src
        for symbol in ("planRequest", "planAfterProbe", "notAcceptableBody"):
            assert symbol in src, f"middleware no longer uses {symbol}"

    def test_the_matcher_excludes_static_files(self):
        """
        Static paths must bypass middleware, or the internal existence probe
        re-enters it and recurses.
        """
        src = _read(_MIDDLEWARE)
        matcher = re.search(r'"(/\(\(\?!.*?)"', src)
        assert matcher, "the page matcher is gone — re-check this guard"
        pattern = matcher.group(1)
        assert "_astro/" in pattern
        assert "[.][a-zA-Z0-9]" in pattern, (
            "extensioned paths (/llms.txt, /index.md) must be excluded from the matcher"
        )

    def test_vercel_types_and_varies_markdown(self):
        config = json.loads(_read(_VERCEL))
        rules = {rule["source"]: {h["key"]: h["value"] for h in rule["headers"]}
                 for rule in config["headers"]}
        md = rules.get("/(.*).md")
        assert md, "vercel.json sets no headers for .md files"
        assert md["Content-Type"] == "text/markdown; charset=utf-8"
        assert "Accept" in md["Vary"], "a CDN would cross the HTML and markdown variants"

    def test_the_apex_negotiates_and_varies(self):
        caddy = _read(_CADDYFILE)
        assert "rewrite @md_home /index.md" in caddy
        assert 'header @page Vary "Accept, Accept-Encoding"' in caddy
        assert 'header @markdown Content-Type "text/markdown; charset=utf-8"' in caddy

    def test_the_apex_serves_every_negotiated_route(self):
        """
        www (Vercel) and the apex (Caddy) must agree on which URLs answer in
        markdown, or the same request gets two different answers depending on
        which hostname the agent happened to resolve.
        """
        caddy = _read(_CADDYFILE)
        matched_paths = {
            token
            for line in caddy.splitlines()
            if line.strip().startswith("path ")
            for token in line.strip().split()[1:]
        }
        rewritten = set(re.findall(r"rewrite @md_\w+ (\S+)", caddy))
        for route, target in _markdown_routes().items():
            assert route in matched_paths, f"the apex does not negotiate {route}"
            if route != "/":
                assert f"{route}/" in matched_paths, (
                    f"the apex does not negotiate {route}/ (Caddy does not normalise it)"
                )
            assert target in rewritten, f"the apex does not rewrite anything to {target}"


# ── Structured data ───────────────────────────────────────────────────────────


class TestStructuredData:
    def _graph(self, layout: str) -> list[dict]:
        src = _read(_LAYOUTS / layout)
        assert "application/ld+json" in src, f"{layout} emits no JSON-LD"
        assert "'@graph'" in src, f"{layout} emits no @graph"
        return re.findall(r"'@type':\s*'([A-Za-z]+)'", src)

    def test_both_layouts_emit_json_ld(self):
        for layout in ("BaseLayout.astro", "Layout.astro"):
            types = self._graph(layout)
            assert "Organization" in types, f"{layout} has no Organization node"
            assert "WebPage" in types, f"{layout} has no WebPage node"

    def test_the_homepage_identifies_itself_as_a_product(self):
        src = _read(_PAGES / "index.astro")
        assert "SoftwareApplication" in src
        assert "AggregateOffer" in src
        assert "jsonLd={softwareApplication}" in src

    def test_no_layout_references_a_json_ld_node_it_does_not_publish(self):
        """
        Layout.astro pointed WebPage.isPartOf at a WebSite node only BaseLayout
        emitted, so every page built on it carried a dangling reference.
        """
        for layout in ("BaseLayout.astro", "Layout.astro"):
            src = _read(_LAYOUTS / layout)
            referenced = set(re.findall(r"'@id':\s*\{?\s*`\$\{SITE_URL\}/#(\w+)`", src))
            declared = set(re.findall(r"'@id':\s*`\$\{SITE_URL\}/#(\w+)`", src))
            assert referenced <= declared, (
                f"{layout} references JSON-LD nodes it never declares: {referenced - declared}"
            )

    def test_the_llms_txt_alternate_is_typed_as_it_is_served(self):
        """It is served as text/plain; advertising markdown invites a reject."""
        for layout in ("BaseLayout.astro", "Layout.astro"):
            src = _read(_LAYOUTS / layout)
            link = re.search(r'<link rel="alternate" type="([^"]+)" href="/llms\.txt"', src)
            assert link, f"{layout} no longer links llms.txt"
            assert link.group(1) == "text/plain", f"{layout} mistypes the llms.txt alternate"

    def test_open_graph_urls_are_absolute(self):
        for layout in ("BaseLayout.astro", "Layout.astro"):
            src = _read(_LAYOUTS / layout)
            assert 'property="og:url"' in src, f"{layout} publishes no og:url"
            image = re.search(r'property="og:image" content=\{([^}]+)\}', src)
            assert image and "SITE_URL" in image.group(1), (
                f"{layout} og:image is not an absolute URL"
            )

    def test_the_offer_links_a_page_listing_every_tier(self):
        """
        The AggregateOffer pointed at /price, which stops at Pro — advertising a
        $249 ceiling on a page that does not contain it.
        """
        src = _read(_PAGES / "index.astro")
        url = re.search(r"offers:.*?url:\s*'([^']+)'", src, re.S)
        assert url, "the offer URL is gone — re-check this guard"
        target = url.group(1).rsplit("/", 1)[-1]
        page = _read(_PAGES / f"{target}.astro")
        assert "enterprise" in page.lower(), (
            f"/{target} does not list the Enterprise tier the offer range includes"
        )

    def test_both_layouts_publish_a_canonical(self):
        for layout in ("BaseLayout.astro", "Layout.astro"):
            src = _read(_LAYOUTS / layout)
            assert 'rel="canonical"' in src, f"{layout} publishes no canonical URL"
            assert "canonicalPath" in src, (
                f"{layout} canonical is not trailing-slash normalised; "
                "vercel.json redirects /x/ to /x, so it would name a 308"
            )

    def test_the_built_homepage_carries_valid_json_ld(self):
        built = _SITE / "dist" / "index.html"
        if not built.is_file():
            pytest.skip("site/dist not built")
        blocks = re.findall(
            r'<script type="application/ld\+json">(.*?)</script>', _read(built), re.S
        )
        assert blocks, "the built homepage has no JSON-LD"
        graph = json.loads(blocks[0])["@graph"]
        types = {node["@type"] for node in graph}
        assert {"Organization", "WebSite", "WebPage", "SoftwareApplication"} <= types


# ── Agent instructions ────────────────────────────────────────────────────────


class TestAgentInstructions:
    _FILE = _PUBLIC / ".well-known" / "agent-instructions.md"

    def test_the_instructions_exist(self):
        assert self._FILE.is_file(), "no agent instruction file"

    def test_they_say_when_to_use_and_when_not_to(self):
        body = _read(self._FILE)
        assert "## When to use this" in body
        assert "## When not to use this" in body

    def test_they_name_concrete_jobs_not_marketing(self):
        body = _read(self._FILE)
        for job in ("POST /filter", "warden filter", "prompt-injection"):
            assert job in body, f"the instructions never mention {job}"

    def test_they_tell_an_agent_how_to_read_status_codes(self):
        body = _read(self._FILE)
        for code in ("402", "403", "406", "429"):
            assert code in body, f"the instructions do not explain a {code}"

    def test_llms_txt_carries_a_when_to_use_section(self):
        body = _read(_PUBLIC / "llms.txt")
        assert "## When to use this" in body
        assert "agent-instructions.md" in body, "llms.txt does not link the instructions"

    def test_llms_txt_does_not_quote_an_uninstrumented_latency(self):
        """CLAUDE.md claims rule: no number without an instrument behind it."""
        body = _read(_PUBLIC / "llms.txt")
        assert not re.search(r"<\s*\d+\s*ms", body), "llms.txt quotes a latency nobody measures"

    def test_no_published_markdown_claims_a_certification(self):
        for path in list(_PUBLIC.rglob("*.md")) + [_PUBLIC / "llms.txt"]:
            body = _read(path)
            assert "SOC 2 compliant" not in body, f"{path.name} claims a certification we do not hold"
            assert "SOC 2 certified" not in body, f"{path.name} claims a certification we do not hold"


# ── The CLI ───────────────────────────────────────────────────────────────────


class TestCliIsReal:
    _SDK = _ROOT / "sdk" / "python"

    def test_the_console_script_is_declared(self):
        pyproject = _read(self._SDK / "pyproject.toml")
        assert 'warden = "shadow_warden.cli:main"' in pyproject, (
            "the site documents a `warden` CLI that the package does not install"
        )

    def test_the_cli_module_exists(self):
        assert (self._SDK / "shadow_warden" / "cli.py").is_file()

    def test_the_advertised_minimum_version_matches_the_package(self):
        """
        The site says `shadow-warden-sdk >= 1.1.0` ships the CLI. If the package
        version falls behind that, the site is advertising a release that does
        not exist.
        """
        pyproject = _read(self._SDK / "pyproject.toml")
        version = re.search(r'^version = "([^"]+)"', pyproject, re.M)
        assert version, "the SDK has no version"
        advertised = re.search(r"shadow-warden-sdk[^0-9]*([0-9]+\.[0-9]+\.[0-9]+)", _read(_PUBLIC / "sdk.md"))
        assert advertised, "sdk.md no longer names the CLI's minimum version"
        assert tuple(int(p) for p in version.group(1).split(".")) >= tuple(
            int(p) for p in advertised.group(1).split(".")
        ), "the site advertises an SDK version newer than the package"

    def test_the_sdk_page_badge_matches_the_package_version(self):
        """The page carried a v1.0 badge while documenting the v1.1.0 CLI."""
        version = re.search(r'^version = "([^"]+)"', _read(self._SDK / "pyproject.toml"), re.M)
        badge = re.search(r">v([0-9][^<]*)</span>", _read(_PAGES / "sdk.astro"))
        assert badge, "the /sdk version badge is gone — re-check this guard"
        assert badge.group(1) == version.group(1), (
            f"/sdk shows v{badge.group(1)} for a package at {version.group(1)}"
        )

    def test_the_cli_exit_contract_is_described_the_same_everywhere(self):
        """
        `sdk.md` said exit 1 meant "blocked or flagged" while the code returns 1
        only when the verdict is not allowed. Two contracts is worse than none.
        """
        cli = _read(self._SDK / "shadow_warden" / "cli.py")
        assert "return EXIT_OK if result.allowed else EXIT_BLOCKED" in cli, (
            "the exit contract moved — re-check the docs it is mirrored in"
        )
        for path in (_PUBLIC / "sdk.md", _PUBLIC / "llms.txt"):
            body = _read(path)
            if "exit" not in body.lower():
                continue
            assert "blocked or flagged" not in body, (
                f"{path.name} promises exit 1 on a flagged-but-allowed verdict; the code exits 0"
            )

    def test_the_json_output_never_serialises_a_secret(self):
        """`--json` goes to CI logs. The matched token must not travel with it."""
        cli = _read(self._SDK / "shadow_warden" / "cli.py")
        assert "asdict(result)" not in cli, (
            "the filter payload is built from the whole dataclass again — that "
            "re-serialises secrets_found[].token and filtered_content"
        )
        assert '"kind": s.kind' in cli

    def test_the_sdk_page_documents_the_cli(self):
        page = _read(_PAGES / "sdk.astro")
        assert "warden filter" in page, "/sdk does not document the CLI"

    def test_the_sdk_exposes_the_health_call_the_site_documents(self):
        client = _read(self._SDK / "shadow_warden" / "client.py")
        assert "def health(" in client, "/sdk documents client.health(), which does not exist"


# ── The published copy ────────────────────────────────────────────────────────


class TestPublishedLanding:
    """
    `landing/` is what the VPS serves at the apex. CI already requires it to
    equal a fresh build of `site/`; these assertions name the specific files an
    agent asks for, so a partial regeneration cannot quietly drop them.
    """

    def _require(self, rel: str):
        path = _LANDING / rel
        if not _LANDING.is_dir():
            pytest.skip("landing/ not present in this checkout")
        assert path.is_file(), f"landing/{rel} is missing — the apex would 404 it"

    @pytest.mark.parametrize(
        "rel",
        [
            "llms.txt",
            "404.html",
            "index.md",
            "pricing.md",
            "doc.md",
            "sdk.md",
            "agentic.md",
            "trust.md",
            "404.md",
            ".well-known/agent-instructions.md",
            ".well-known/did.json",
            "openapi.json",
            "sitemap-index.xml",
        ],
    )
    def test_the_published_site_carries_the_machine_readable_files(self, rel):
        self._require(rel)
