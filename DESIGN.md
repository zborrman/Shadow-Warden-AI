---
name: Shadow Warden AI
description: An instrument-grade dark console where color only appears when something is true.
colors:
  sentinel-blue: "#80b4fd"
  signal-blue: "#4d9cfc"
  command-blue-deep: "#0051c3"
  pipeline-cyan: "#38bdf8"
  app-primary: "#2563eb"
  void-navy: "#070910"
  bunker-navy: "#0c1020"
  console-slate: "#111827"
  raised-slate: "#1a2236"
  hairline: "rgba(128,180,253,0.09)"
  hairline-strong: "rgba(128,180,253,0.20)"
  hairline-hover: "rgba(128,180,253,0.32)"
  screen-white: "#f0f4fc"
  muted-steel: "#a8b8d0"
  dim-steel: "#6b7c96"
  ghost-steel: "#404e66"
  verdict-clear: "#34d399"
  verdict-caution: "#fbbf24"
  verdict-escalate: "#fb923c"
  verdict-alert: "#f87171"
  verdict-block: "#ef4444"
typography:
  display:
    fontFamily: "JetBrains Mono, ui-monospace, SF Mono, Menlo, monospace"
    fontSize: "clamp(28px, 3.8vw, 50px)"
    fontWeight: 700
    lineHeight: 1.1
    letterSpacing: "normal"
  headline:
    fontFamily: "Inter, system-ui, -apple-system, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 600
    lineHeight: 1.25
    letterSpacing: "-0.025em"
  title:
    fontFamily: "Inter, system-ui, -apple-system, sans-serif"
    fontSize: "1.25rem"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "-0.01em"
  body:
    fontFamily: "Inter, system-ui, -apple-system, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.6
    letterSpacing: "normal"
    fontFeature: "'cv02','cv03','cv04','cv11'"
  label:
    fontFamily: "Inter, system-ui, -apple-system, sans-serif"
    fontSize: "0.6875rem"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "0.02em"
  code:
    fontFamily: "JetBrains Mono, ui-monospace, SF Mono, Menlo, monospace"
    fontSize: "0.8em"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "normal"
rounded:
  sm: "3px"
  md: "6px"
  lg: "8px"
  xl: "10px"
  app: "12px"
  pill: "100px"
spacing:
  1: "4px"
  2: "8px"
  3: "12px"
  4: "16px"
  5: "20px"
  6: "24px"
  8: "32px"
  10: "40px"
  12: "48px"
  16: "64px"
components:
  button-primary:
    backgroundColor: "{colors.sentinel-blue}"
    textColor: "{colors.void-navy}"
    rounded: "{rounded.lg}"
    padding: "10px 20px"
    typography: "{typography.body}"
  button-primary-hover:
    backgroundColor: "#9dc5fe"
    textColor: "{colors.void-navy}"
  button-ghost:
    backgroundColor: "rgba(128,180,253,0.04)"
    textColor: "{colors.muted-steel}"
    rounded: "{rounded.lg}"
    padding: "10px 20px"
    typography: "{typography.body}"
  button-ghost-hover:
    backgroundColor: "rgba(128,180,253,0.09)"
    textColor: "{colors.screen-white}"
  card:
    backgroundColor: "{colors.bunker-navy}"
    textColor: "{colors.screen-white}"
    rounded: "{rounded.lg}"
    padding: "24px"
  input:
    backgroundColor: "{colors.void-navy}"
    textColor: "{colors.screen-white}"
    rounded: "{rounded.lg}"
    padding: "4px 12px"
    height: "36px"
  badge-status:
    backgroundColor: "rgba(52,211,153,0.08)"
    textColor: "{colors.verdict-clear}"
    rounded: "{rounded.pill}"
    padding: "2px 8px"
    typography: "{typography.label}"
  nav-link:
    backgroundColor: "transparent"
    textColor: "#94a3b8"
    rounded: "{rounded.lg}"
    padding: "8px 12px"
  nav-link-active:
    backgroundColor: "rgba(255,255,255,0.06)"
    textColor: "{colors.sentinel-blue}"
---

# Design System: Shadow Warden AI

## Overview

**Creative North Star: "The Night Watch Console"**

This is an instrument, not a website. The surfaces are near-black navy because the product is read in the dark — SOC walls, terminal sessions, an incident at 02:00 — and every value on screen was measured by the system rather than composed by a designer. Structure is carried entirely by hairlines and tonal layering: four surface steps from Void Navy (`#070910`) up to Raised Slate (`#1a2236`), separated by blue-tinted borders at 9% opacity. Nothing floats. Nothing lifts on hover. Depth exists, but it is stacked, not thrown.

Color is a verdict, not decoration. Sentinel Blue is the only brand voice, and the green/amber/orange/red family belongs exclusively to states the pipeline actually reported. Because the palette is otherwise monochrome, a single amber badge in a table reads instantly from across a room — which is the entire operational point. Radii are deliberately tight (3–10px, never the soft 16px+ of consumer SaaS), body text sits at 14px, and density is treated as respect for an expert reader rather than a compromise.

The type pairing carries the product's argument: Inter for everything the user reads, JetBrains Mono for everything the *system* says. Headlines on the flagship pages are set in mono at 700 weight — a machine speaking in its own voice — while body copy stays in Inter so long-form technical prose remains comfortable. This system explicitly rejects the friendly-SaaS vocabulary (soft gradients, pastel accents, rounded pill cards, illustrated mascots) and the theatrical hacker aesthetic (neon green, matrix rain, alarm red as ambience) in equal measure.

**Key Characteristics:**
- Dark-first, four-step tonal surface ramp; light mode is a derived state, never the design target
- Hairline borders as the primary structural device — 1px, blue-tinted, 9% opacity at rest
- One brand hue (Sentinel Blue), one status family, nothing else
- Tight radii (3–10px) and a 4px spacing base
- 14px body text; information density over whitespace drama
- Mono for machine voice, Inter for human reading
- Motion is short (150–350ms), directional, and fully suppressed under `prefers-reduced-motion`

## Colors

A near-monochrome navy field with a single cool-blue voice, where saturated color is reserved for system verdicts.

### Primary
- **Sentinel Blue** (`#80b4fd`): the brand voice and the only accent used for identity — primary buttons, active navigation, links, focus rings, inline `code`. Light enough to hold ≥7:1 against Void Navy, which is why it is the accent on dark rather than the deeper blues.
- **Signal Blue** (`#4d9cfc`): the secondary accent, one step deeper and more saturated. Used for the second element in a paired gradient, category coding for Community surfaces, and to differentiate a second data series from the primary.
- **Deep Command Blue** (`#0051c3`): reserved for light-surface contexts and print/export artifacts where the light accent would fail contrast. Never used as a background on dark.

### Secondary
- **Pipeline Cyan** (`#38bdf8`): status and flow. It marks pipeline stages, streaming/live indicators, and the terminal stop of the brand gradient. Cyan means "in motion"; blue means "this is ours".

### Neutral
- **Void Navy** (`#070910`): the page floor. Almost black, faintly blue — the color the eye rests on for an entire shift.
- **Bunker Navy** (`#0c1020`): the default card and panel surface, one step above the floor.
- **Console Slate** (`#111827`): raised panels, table headers, popovers, inline code backgrounds.
- **Raised Slate** (`#1a2236`): the highest surface — modals, scrollbar thumbs, hovered rows.
- **Hairline** (`rgba(128,180,253,0.09)`): the default border. Blue-tinted rather than gray so edges belong to the palette instead of dirtying it.
- **Hairline Strong** (`rgba(128,180,253,0.20)`) / **Hairline Hover** (`rgba(128,180,253,0.32)`): emphasis and hover states of the same edge.
- **Screen White** (`#f0f4fc`), **Muted Steel** (`#a8b8d0`), **Dim Steel** (`#6b7c96`), **Ghost Steel** (`#404e66`): the four-step text ramp — primary reading, secondary description, tertiary metadata, and disabled. Ghost Steel is a structural color, never body copy.

### Verdict family
- **Verdict Clear** (`#34d399`), **Caution** (`#fbbf24`), **Escalate** (`#fb923c`), **Alert** (`#f87171`), **Block** (`#ef4444`): the five states the filter pipeline can report. Each appears as text on an 8–10% tint of itself with an 18–20% border of itself — never as a solid fill, which would out-shout the data.

### Named Rules
**The Earned Color Rule.** Saturated color covers ≤10% of any screen. If a color is not reporting a verdict, an active state, or the single primary action, it is not allowed to be there. When everything glows, nothing alerts.

**The Verdict Reservation Rule.** Green, amber, orange, and red are owned by the detection pipeline. They may never be borrowed for decoration, category coding, or chart series — a red chart line will be read as a BLOCK by this audience, and that misread is a product failure, not a style quibble.

**The Tinted Hairline Rule.** Borders are blue-tinted alpha (`rgba(128,180,253,·)`), never neutral gray and never a solid hex. On a navy floor, gray edges read as dirt.

## Typography

**Display Font:** JetBrains Mono (with `ui-monospace`, `SF Mono`, Menlo)
**Body Font:** Inter (with `system-ui`, `-apple-system`, sans-serif)
**Code Font:** JetBrains Mono

**Character:** Two voices with a strict division of labor. Inter — loaded variable with optical sizing and the `cv02/cv03/cv04/cv11` stylistic sets enabled for unambiguous digits and a straight-legged `l` — carries everything a person writes. JetBrains Mono carries everything the machine says: headlines on the flagship pages, verdict codes, latency figures, identifiers, and every inline snippet. The pairing is the product's thesis rendered as type.

### Hierarchy
- **Display** (JetBrains Mono, 700, `clamp(28px, 3.8vw, 50px)`, 1.1): flagship page headlines. Mono at this scale is a deliberate signature — it should feel like output, not marketing.
- **Headline** (Inter, 600, 24px, −0.025em): section headings and page titles inside the console.
- **Title** (Inter, 600, 20px): card titles and panel headers. `18px/600` with `tracking-tight` is the app-side equivalent.
- **Body** (Inter, 400, 14px, 1.6): the default reading size across every surface, marketing included. Cap measure at 65–75ch.
- **Small / Caption** (Inter, 400, 13px / 12px): table cells, helper text, secondary metadata.
- **Label** (Inter, 600, 11px, +0.02em): badges, tier chips, table column heads. 10px (`--sw-text-micro`) exists for dense telemetry only and never carries prose.
- **Code** (JetBrains Mono, 0.8em, Sentinel Blue on Console Slate, 1px hairline, 3px radius, 1px 5px padding): inline identifiers and values.

### Named Rules
**The 14px Rule.** Body is 14px everywhere — landing page included. This product is read by people who keep four panes open; a 18px marketing body size would announce that the marketing site is a different product than the console.

**The Machine Voice Rule.** Monospace is reserved for what the system produced or the user must type verbatim: verdicts, metrics, IDs, endpoints, code, and flagship display headlines. Never set descriptive prose in mono to look technical.

## Layout

A centered `max-w-7xl` (1280px) container with `16px` gutters, opening to `32px` at `lg`. Spacing is a strict 4px base (4 / 8 / 12 / 16 / 20 / 24 / 32 / 40 / 48 / 64) — no arbitrary values between steps.

Section rhythm on marketing surfaces is 64px vertical minimum between blocks, with 24px between a heading and its content. Console surfaces compress this: 24px page padding, 16px between cards, 12px internal row gaps. Density is the difference between the two contexts; the tokens do not change.

The navigation bar is fixed at 56px tall with a 36px announcement banner above it, backed by `rgba(10,10,15,0.85)` with a 20px backdrop blur so content dims rather than disappears as it scrolls beneath. Grids collapse at Tailwind defaults (`sm` 640 / `md` 768 / `lg` 1024 / `xl` 1280); the desktop nav gives way to a full-height mobile sheet at `lg`. Tables are the one element permitted to scroll horizontally inside their own container rather than reflow — an operator comparing columns needs the columns.

## Elevation & Depth

**This system is flat by conviction.** Depth comes from the four-step tonal ramp and hairline borders, not from shadows. A card is distinguishable from the page because it is one step lighter and edged in blue-tinted alpha, not because it casts anything.

Shadows exist in a small, black-only vocabulary and are used almost exclusively for elements that genuinely float above the page — dropdowns, modals, popovers. They carry no color, because a colored shadow on a navy field reads as a glow, and glow is the visual language of the hacker aesthetic this system rejects.

### Shadow Vocabulary
- **Ambient Small** (`0 1px 2px rgba(0,0,0,.35)`): resting separation for a raised row or chip.
- **Ambient Medium** (`0 2px 8px rgba(0,0,0,.40)`): dropdowns and hover cards.
- **Ambient Large** (`0 4px 20px rgba(0,0,0,.50)`): modals and the nav dropdown (`0 16px 40px rgba(0,0,0,0.5)` in the site header).
- **Focus Glow** (`0 0 0 2px rgba(128,180,253,.10)`): the only blue shadow — a focus companion to the ring, never an idle decoration.
- **Primary Button Inset** (three-layer `color(display-p3 …)` inset + drop): the single deliberate exception. It gives the primary CTA a physical, slightly convex face in wide-gamut displays. It belongs to that one component and must not be generalized.

### Named Rules
**The No-Lift Rule.** Cards never translate, scale, or shadow on hover. Hover changes the border color only, over 180ms. Buttons are the sole exception: they scale to `0.97` on `:active` as a press confirmation, and that is suppressed under reduced motion.

## Shapes

Rectilinear and tight. The radius scale runs 3px (chips, code, scrollbars) → 6px (compact controls) → 8px (the default: buttons, cards, inputs) → 10px (large panels) → 12px (the app-side `--radius`, `0.75rem`) → 100px (pills only). Nothing in this system is more rounded than 12px except a status pill or an avatar.

Borders are always exactly 1px. There are no double borders, no dashed edges outside a genuine drop-zone, and no decorative dividers where whitespace would do. Icons are 16px stroked at 1.5px, sharing the hairline weight so iconography and structure read as one material. The castle logo mark is the only figurative shape in the system and never gets a container, glow, or drop shadow.

**The Right-Angle Bias Rule.** When a radius is uncertain, choose the smaller step. Softness reads as consumer software to this audience, and this audience is buying infrastructure.

## Components

### Buttons
- **Shape:** 8px radius (`--sw-r-lg`), 10px×20px padding, 600 weight, 14px.
- **Primary:** Sentinel Blue fill with Void Navy text — dark-on-light, inverting the page and making the CTA the brightest object on screen. No border; the three-layer display-p3 inset supplies its face. Hover lightens the fill to `#9dc5fe` over 150ms; `:active` scales to `0.97` on a `cubic-bezier(0.23,1,0.32,1)` curve.
- **Ghost:** the default secondary — 4% blue wash, 14% blue border, 6% inset top highlight, Muted Steel text. Hover raises all three (9% / 28% / 10%) and lifts the text to Screen White. It reads as an engraved surface rather than an outline.
- **Destructive:** Verdict Block fill, used only where the action is irreversible.
- **App-side (DS-01):** heights are fixed by size token — `sm` 32px, `md` 36px, `lg` 44px — with a 2px `focus-visible` ring offset by 2px. Every button in the console carries a visible focus ring; this is non-negotiable.

### Cards / Containers
- **Corner Style:** 8px on the site, 12px (`rounded-xl`) in the console.
- **Background:** Bunker Navy on the site; `--card` (222.2 84% 6%) in the app.
- **Border:** 1px Hairline at rest → Hairline Strong on hover, 180ms border-color transition only.
- **Shadow Strategy:** none at rest. See The No-Lift Rule.
- **Internal Padding:** 24px, with the footer and content blocks sharing the same 24px inset and no top padding when they follow a header.
- **Variants:** `default` (filled + bordered), `outline` (bordered, transparent), `ghost` (no border, no background) — used to nest a card inside a card without doubling edges.

### Badges / Status Chips
- **Style:** pill (100px), 11px/600, 2px×8px padding. Text in the state color on an 8–10% tint of itself, bordered at 18–20% of itself.
- **Dot variant:** a 6px filled circle precedes the label for scan-ability in dense tables.
- **Verdict mapping:** Clear → shipped/allow, Caution → in-progress/flag, Escalate → high-risk, Block → blocked/error, Dim Steel with strikethrough → cancelled. Never invent a sixth status color.

### Inputs / Fields
- **Style:** 36px tall, 8px radius, 1px border in `--input`, page-floor background, 14px text, 12px horizontal padding.
- **Label:** 14px/500 above the field with a 6px gap; helper and error text at 12px below.
- **Focus:** 1px ring in Sentinel Blue, no glow, no border-width change (which would shift layout).
- **Error:** border and ring swap to Verdict Block, and the message replaces the helper text rather than appearing alongside it.
- **Disabled:** 50% opacity and `not-allowed` cursor.

### Navigation
- **Style:** fixed 56px bar, `rgba(10,10,15,0.85)` + 20px backdrop blur, 1px bottom hairline at `rgba(255,255,255,0.06)`. The logo sits at 52px height beside a 13px/900 wordmark.
- **Links:** 13px/500, 8px×12px, 8px radius, Dim Steel (`#94a3b8`) at rest; on hover and when active they take their **category color** and a 6% white wash.
- **Category coding:** each top-level section owns a hue drawn from the token set — Community (Signal Blue), Security (Verdict Alert), Dashboard (Sentinel Blue), Settings (Verdict Clear), Docs (Caution Amber), Pricing (Escalate Orange). This is the one sanctioned use of the verdict palette outside verdicts, and it is confined to navigation.
- **Dropdowns:** `#16161f` panel, 12px radius, `0 16px 40px rgba(0,0,0,0.5)`, 150ms opacity+visibility fade on group hover.
- **Mobile:** full-height sheet below `lg`; the chrome stays dark in light mode (see below).

### Signature: the dark-chrome light mode
Light mode on the marketing site is produced by inverting the entire document (`filter: invert(1) hue-rotate(180deg)`), then *double*-inverting the navbar, banner, and mobile menu so the chrome stays dark while the content flips. Images, video, and iframes in `main` are counter-inverted to restore their true colors; canvases are deliberately left inverted so dark-painted charts become legible light charts. The result is the Slack pattern — a permanently dark operational shell around invertible content. The console app takes a different route (`[data-theme="light"]` overrides), and DS-01 a third (`.dark` class on a light-default base).

### Motion
`150ms` for color and background, `180ms` for card borders, `350ms` for staggered grid entrances (40ms per child, capped at the 10th), `520ms` for scroll-reveal. Two easings only: `cubic-bezier(0.23, 1, 0.32, 1)` for anything entering or responding to a press, and `ease` for simple color changes. Every one of these is disabled wholesale under `prefers-reduced-motion: reduce`.

## Do's and Don'ts

### Do:
- **Do** build structure from the four-step surface ramp and 1px tinted hairlines before reaching for any other device.
- **Do** keep body copy at 14px and let density do the work — this audience reads dashboards for a living.
- **Do** set machine output (verdicts, latencies, IDs, endpoints, code) in JetBrains Mono, and human prose in Inter.
- **Do** give every interactive element a visible `focus-visible` ring; the product is sold to buyers who audit for it.
- **Do** express status as tinted-text-plus-border chips, never as solid saturated fills.
- **Do** gate every animation behind `prefers-reduced-motion` and keep durations under 550ms.
- **Do** hold ≥4.5:1 on body text in both themes — Ghost Steel (`#404e66`) is structural only and must never carry prose.

### Don't:
- **Don't** lift, scale, or shadow a card on hover. Change the border color and nothing else.
- **Don't** use gradient text. `.text-gradient` deliberately resolves to solid Sentinel Blue; the only surviving gradients are the hero radial wash and the two-stop brand mark.
- **Don't** spend a verdict color on decoration, category fills, or chart series. Red means blocked.
- **Don't** exceed 12px radius on anything that is not a pill or an avatar.
- **Don't** introduce a second brand hue. Indigo/violet (`#6366f1`, `#7c3aed`, `#7B5CF0`) are legacy residue, not part of this palette.
- **Don't** add neutral-gray borders, colored drop shadows, glass panels, or animated background orbs.
- **Don't** invent a new token because a value is missing — extend `site/src/styles/tokens.css`, which is the source of truth, and let the other surfaces mirror it.

---

## Known drift (recorded, not endorsed)

Three token sources exist and have diverged. This file documents `site/src/styles/tokens.css` (v5.6, "Cloudflare Edition") as canonical, because it is the newest and covers the largest surface (54 pages).

1. **`dashboard/tailwind.config.ts`** still carries the pre-v5.6 identity: a violet/blue/cyan accent set (`#7c3aed`, `#2563eb`, `#06b6d4`), `.text-gradient` as a real three-stop gradient, and `.glow-purple` / `.glow-blue` box-shadow utilities. Its surface ramp (`#050810 → #1a2236`) is also one step darker at the floor than the site's. Aligning it is a real task, not a cleanup.
2. **`packages/ui/globals.css` (DS-01)** is a shadcn-shaped HSL system that is *light by default* with a `.dark` override, while every other surface is dark-first. Its brand ramp resolves to `#3b82f6`/`#2563eb` rather than Sentinel Blue, and its radius is `0.75rem` against the site's 8px. The site carries a hand-written "DS-01 compatibility bridge" block to paper over the gap.
3. **`site/src/pages/index.astro`** hardcodes two off-token colors in the hero — emerald `#10b981` on the headline highlight and violet `#7B5CF0` on the tagline — and the navbar wordmark still uses legacy indigo `#6366f1`.
