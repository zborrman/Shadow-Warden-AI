"""
warden/tests/test_site_agent_readiness_r4.py — readiness audit, round 4.

The audit scored the site 100/100 and still marked four things Partial:

  * developer resources found "by name" but with no recognisable type;
  * trust anchors: /contact and /privacy verified, /about missing;
  * versioning found, but no deprecation or sunset policy detected;
  * a CLI mentioned on one page rather than published as a tool.

These guards hold each fix to the code it describes, so a published policy
cannot drift from the header the gateway actually sends.
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
_CADDYFILE = _ROOT / "docker" / "Caddyfile"
_VERCEL = _ROOT / "vercel.json"

pytestmark = pytest.mark.skipif(not _SITE.is_dir(), reason="site/ not present in this checkout")

_ALIASES = {
    "/docs": "/doc",
    "/developer": "/developers",
    "/api-docs": "/doc/api-reference",
    "/api-reference": "/doc/api-reference",
    "/versioning": "/doc/versioning",
    "/deprecation": "/doc/versioning",
    "/changelog": "/doc/changelog",
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _markdown_routes() -> dict[str, str]:
    block = re.search(r"MARKDOWN_ROUTES = Object\.freeze\(\{(.*?)\}\)", _read(_NEGOTIATE), re.S)
    assert block, "MARKDOWN_ROUTES is gone or reshaped — re-check this guard"
    return dict(re.findall(r'"([^"]+)":\s*"([^"]+)"', block.group(1)))


def _visible_text(astro: str) -> str:
    """Prose of an Astro page: no frontmatter, no tags, no whitespace runs."""
    body = re.sub(r"^---.*?---", "", astro, count=1, flags=re.S)
    body = re.sub(r"<[^>]+>", " ", body)
    return re.sub(r"\s+", " ", body).strip()


class TestTrustAnchorPages:
    @pytest.mark.parametrize("name", ["about", "contact", "privacy"])
    def test_each_page_has_substance(self, name):
        text = _visible_text(_read(_PAGES / f"{name}.astro"))
        assert len(text) >= 500, f"/{name} carries only {len(text)} characters of prose"

    def test_about_negotiates_markdown_and_declares_its_twin(self):
        assert "/about" in _markdown_routes()
        assert 'markdown="/about.md"' in _read(_PAGES / "about.astro")
        assert _read(_PUBLIC / "about.md").startswith("# ")

    def test_about_points_at_the_other_anchors(self):
        body = _read(_PAGES / "about.astro")
        for target in ("/contact", "/privacy", "/trust"):
            assert target in body, f"/about does not link {target}"

    def test_about_claims_nothing_the_capability_matrix_denies(self):
        for path in (_PAGES / "about.astro", _PUBLIC / "about.md"):
            body = _read(path).lower()
            for banned in ("soc 2 compliant", "soc 2 certified", "iso 27001 certified",
                           "trusted by", "our customers", "gmbh", "inc.", "ltd"):
                assert banned not in body, f"{path.name} contains {banned!r}"
            assert "no certification" in body
            assert "no registered customers" in body

    def test_the_footer_links_about(self):
        assert "href: '/about'" in _read(_LAYOUTS / "BaseLayout.astro")

    def test_llms_txt_lists_the_anchors(self):
        llms = _read(_PUBLIC / "llms.txt")
        for target in ("/about", "/contact", "/privacy"):
            assert f"https://shadow-warden-ai.com{target})" in llms


class TestDeprecationPolicyIsPublished:
    _PAGE = _PAGES / "doc" / "versioning.astro"

    def test_the_page_and_its_markdown_twin_exist(self):
        assert "/doc/versioning" in _markdown_routes()
        assert 'markdown="/versioning.md"' in _read(self._PAGE)

    def test_the_published_sunset_is_the_one_the_middleware_serves(self):
        from warden.api_versioning import SUNSET_DATE, _sunset_http_date

        for path in (self._PAGE, _PUBLIC / "versioning.md"):
            assert _sunset_http_date() in _read(path), f"{path.name} omits the Sunset header value"
        assert SUNSET_DATE in _read(self._PAGE)

    def test_the_published_deprecation_value_is_the_one_served(self):
        from warden.api_versioning import _deprecation_value

        for path in (self._PAGE, _PUBLIC / "versioning.md"):
            assert f"Deprecation: {_deprecation_value()}" in _read(path), path.name

    def test_the_policy_names_the_rfcs_it_follows(self):
        body = _read(_PUBLIC / "versioning.md")
        for rfc in ("RFC 9745", "RFC 8594", "RFC 8288"):
            assert rfc in body

    def test_the_policy_states_a_notice_period(self):
        assert "180 days" in _read(_PUBLIC / "versioning.md")
        assert "180 days" in _read(self._PAGE)

    def test_version_info_points_at_the_site_page(self):
        from warden.api_versioning import POLICY_URL, version_info

        assert version_info()["policy"] == POLICY_URL
        assert POLICY_URL == "https://shadow-warden-ai.com/doc/versioning"

    def test_the_openapi_description_states_the_policy(self):
        info = json.loads(_read(_PUBLIC / "openapi.json"))["info"]["description"]
        assert "https://shadow-warden-ai.com/doc/versioning" in info
        assert "Sunset" in info and "/v1/" in info

    def test_the_gateway_description_carries_the_same_paragraph(self):
        """Regenerating the spec must not silently drop the policy."""
        assert "doc/versioning" in _read(_ROOT / "warden" / "main.py")

    def test_llms_txt_links_the_policy(self):
        assert "/doc/versioning" in _read(_PUBLIC / "llms.txt")


class TestCliPage:
    _CLI = _ROOT / "sdk" / "python" / "shadow_warden" / "cli.py"

    def test_page_markdown_and_negotiation(self):
        assert "/cli" in _markdown_routes()
        assert 'markdown="/cli.md"' in _read(_PAGES / "cli.astro")

    def test_every_documented_command_exists(self):
        subcommands = set(re.findall(r'sub\.add_parser\("(\w+)"', _read(self._CLI)))
        documented = set(re.findall(r"^warden (\w+)", _read(_PUBLIC / "cli.md"), re.M))
        assert documented, "cli.md documents no commands"
        assert documented == subcommands, (documented ^ subcommands)

    def test_the_exit_codes_match_the_implementation(self):
        cli = _read(self._CLI)
        for name, code in (("EXIT_OK", 0), ("EXIT_BLOCKED", 1), ("EXIT_USAGE", 2), ("EXIT_GATEWAY", 3)):
            assert re.search(rf"^{name} = {code}$", cli, re.M), name
        body = _read(_PUBLIC / "cli.md")
        for code in "0123":
            assert f"| `{code}` |" in body

    def test_the_documented_environment_variables_are_read(self):
        for var in ("WARDEN_API_KEY", "WARDEN_GATEWAY_URL", "WARDEN_TENANT_ID"):
            assert var in _read(self._CLI) and var in _read(_PUBLIC / "cli.md")

    def test_the_install_command_pins_a_version_that_exists(self):
        pyproject = _read(_ROOT / "sdk" / "python" / "pyproject.toml")
        version = re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
        minimum = re.search(r">=([0-9.]+)", _read(_PUBLIC / "cli.md")).group(1)
        assert tuple(map(int, version.split("."))) >= tuple(map(int, minimum.split(".")))

    def test_the_cli_is_reachable_from_every_index(self):
        for path in (_PUBLIC / "llms.txt", _PUBLIC / "developers.md", _PUBLIC / "index.md",
                     _PAGES / "developers.astro", _PAGES / "sdk.astro", _PUBLIC / "sdk.md"):
            assert "/cli" in _read(path), f"{path.name} does not link /cli"


class TestDeveloperResourceAliases:
    @pytest.mark.parametrize("alias,target", sorted(_ALIASES.items()))
    def test_vercel_redirects_the_alias(self, alias, target):
        redirects = {r["source"]: r for r in json.loads(_read(_VERCEL)).get("redirects", [])}
        assert alias in redirects, f"vercel.json does not redirect {alias}"
        assert redirects[alias]["destination"] == target
        assert redirects[alias]["permanent"] is True

    @pytest.mark.parametrize("alias,target", sorted(_ALIASES.items()))
    def test_the_apex_redirects_the_alias(self, alias, target):
        assert f"redir {alias} {target} 301" in _read(_CADDYFILE)

    @pytest.mark.parametrize("target", sorted(set(_ALIASES.values())))
    def test_every_target_is_a_real_page(self, target):
        rel = target.strip("/")
        assert (_PAGES / f"{rel}.astro").is_file() or (_PAGES / rel / "index.astro").is_file(), target

    def test_no_alias_shadows_a_real_page(self):
        for alias in _ALIASES:
            assert not (_PAGES / f"{alias.strip('/')}.astro").exists(), f"{alias} is a real page"

    def test_the_new_pages_name_the_product_in_the_title(self):
        for page in ("cli.astro", "doc/versioning.astro", "about.astro", "sdk.astro"):
            title = re.search(r'title="([^"]+)"', _read(_PAGES / page)).group(1)
            assert "Shadow Warden AI" in title, page

    def test_the_apex_negotiates_the_new_routes(self):
        caddy = _read(_CADDYFILE)
        for route, target in (("/about", "/about.md"), ("/cli", "/cli.md"),
                              ("/doc/versioning", "/versioning.md")):
            assert f"path {route} {route}/" in caddy
            assert f"/{target.lstrip('/')}" in caddy
