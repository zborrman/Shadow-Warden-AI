# Multilingual Shadow Warden — plan (owner request 2026-11-27)

The owner asked for every page of the project in foreign languages, using the
translation engine built into the Listing Preflight artifact
(https://claude.ai/artifact/CCBRDhq3QZimtQp8pX8WSB). This document records what
that engine is, where it fits, and the order of work.

## The engine (artifact v1795760397-c74c)

A client-side runtime translator, ~240 KB of dictionaries for one tool:

- `EN` — every UI string, numbered; `{0}`-style placeholders for dynamic text.
- `T[lang]` — the same ids in 9 languages: ru, zh, ja, de, fr, es, pt, it, pl.
- A DOM walker + `MutationObserver` replaces text nodes and the `placeholder`,
  `aria-label`, `title`, `data-l` attributes by exact match or pattern; it skips
  `script/style/textarea/code` and anything under `translate="no"`.
- A language picker (`localStorage` `pf-lang`, else `navigator.language`),
  `html[lang]` kept in step.

## Where it fits — and where it does not

| Surface | Fit | Why |
|---|---|---|
| Portal tools (Listing Preflight, FraudScore in `portal/public/preflight/sim.html`) | **Yes — done in phase 1** | Interactive, signed-in, not indexed; the engine ships inside the tool |
| Portal screens (`portal/src/app/*`) | Yes, with a catalog | Client app behind login; a typed `i18n` catalog per screen (the storefront's `lib/storefront/i18n.ts` pattern) beats DOM rewriting |
| Public site (`site/`) | **No — use static locales** | Runtime rewriting is invisible to crawlers that run no JavaScript (most AI crawlers), gives no per-language URL or `hreflang`, and would ship megabytes of dictionaries to every visitor. Astro i18n routing (`/de/…`) with `hreflang` and per-locale markdown twins keeps SEO/GEO intact |
| Storefront `/s/*` | Already EN/FR/DE/ES/IT | Extend the catalog, not the mechanism |
| SOC dashboard | Last, if at all | Operator tool, English is acceptable |

## Rules that hold in every language

- **Claims Rule** — a translated sentence is a public claim. Translations come
  only from copy that already passed `docs/capability-matrix.md`; the
  `banned-claims` phrases are checked per language (the list needs translated
  equivalents before a locale ships).
- **SP-06 / SP-07** — "risk, never a verdict" and dated thresholds survive
  translation; a translator may not soften "estimate" into "result".
- **Legal pages** (terms, privacy, DPA, refund) are translated only with a
  notice that the English text prevails, and only after review by someone who
  can sign for them.
- **Source stays English.** Code, comments and the source strings are English;
  other languages live in catalogs keyed to them.

## Phases

1. **Portal tools (this PR)** — `sim.html` replaced by the artifact's
   multilingual build: 10 languages, picker in the tools bar. Verified in a
   browser (de/ru/ja/fr switch the UI; brand names stay).
2. **Public site, seller pages** — Astro i18n routing for `/sellers`,
   `/fraud-score`, `/price`, home in the storefront's approved set
   (EN, FR, DE, ES, IT), `hreflang` alternates, translated markdown twins,
   claims test per locale.
3. **Portal screens** — typed catalog per screen (login/register first: the
   only screens every seller sees), same five languages.
4. **Remaining site pages and the other five languages** (ru, zh, ja, pt, pl) —
   after phase 2 proves the review loop; legal pages last.

## Open owner decisions

- Final language list for the site (the engine has 10; the storefront has 5).
- Who reviews translations of claims and legal pages.
