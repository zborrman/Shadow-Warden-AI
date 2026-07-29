---
name: shadow-warden-design
description: Shadow Warden AI design system — dark theme, indigo primary, Cloudflare-inspired enterprise UI patterns
---

# Shadow Warden AI Design System

Inspired by Cloudflare dashboard: clean data-first layouts, clear visual hierarchy, metrics-up-front pattern. Applied to a dark theme with indigo primary.

## Color Tokens
```
background:  #070b14 (page) / #0b1120 (modal) / #04070f (card)
border:      rgba(129,140,248,.12) default / .22 hover / .45 selected
text:        #f1f5f9 primary / #94a3b8 label / #64748b muted / #334155 hint / #2d3a4e dim
primary:     #818cf8 (indigo) — gradients: #818cf8→#9ea5fb
success:     #34d399 (green)
danger:      #f87171 (red)
amber:       #fbbf24
cyan:        #22d3ee
easing:      cubic-bezier(0.23,1,0.32,1)
```

## Key Patterns (from Cloudflare)

### Metrics row (like DNS Analytics stats)
```html
<div class="arch-metrics">
  <div class="arch-metric">
    <div class="arch-metric-n">6</div>
    <div class="arch-metric-l">Modules</div>
  </div>
  ...
</div>
```
CSS: `grid; 4-col; dark card; monospace number at 22px; uppercase label at 9px`

### Provider/option cards (like Cloud Connector selection)
```css
.tog-card {
  border: 1px solid rgba(129,140,248,.1);
  background: rgba(4,7,16,.85);
  border-radius: 11px;
}
.tog-card.sel {
  border-color: rgba(129,140,248,.5);
  background: rgba(129,140,248,.09);
}
/* Checkmark badge on selected */
.tog-card.sel::after {
  content: '✓';
  position: absolute; top: 8px; right: 9px;
  width: 16px; height: 16px; border-radius: 50%;
  background: #818cf8; color: #07090f; font-size: 8px; font-weight: 800;
}
```

### Step sidebar with numbered circles
```css
.m-si-num {
  width: 24px; height: 24px; border-radius: 50%;
  border: 1.5px solid rgba(129,140,248,.16);
  background: rgba(4,7,16,.95); color: #2d3a4e;
}
.active .m-si-num { background: #818cf8; color: #07090f; box-shadow: 0 0 0 4px rgba(129,140,248,.1); }
.done .m-si-num   { background: rgba(52,211,153,.12); color: #34d399; border-color: rgba(52,211,153,.3); }
.future           { opacity: .30; }
```

### Primary button with gradient + glow
```css
.btn-primary {
  background: linear-gradient(135deg, #818cf8 0%, #9ea5fb 100%);
  border: none; color: #07090f; font-weight: 700;
  border-radius: 9px; padding: 9px 20px;
  box-shadow: 0 4px 14px rgba(129,140,248,.25);
  transition: transform 120ms, filter 120ms, box-shadow 120ms;
}
.btn-primary:hover { filter: brightness(1.07); box-shadow: 0 6px 20px rgba(129,140,248,.35); }
.btn-primary:active { transform: scale(.97); }
```

### Checkbox row (like Cloudflare rule toggle)
```css
.check-row.sel .check-box {
  background: #818cf8; border-color: #818cf8; color: #07090f;
}
```

### Toggle switch (iOS-style)
- off: `rgba(255,255,255,.07)` pill, dot at left, opacity .5
- on: `#818cf8` pill, dot at right, opacity 1
- transition: 200ms ease

### Dialog entry animation
```css
dialog {
  transform: scale(.97) translateY(6px); opacity: 0;
  transition: transform 220ms cubic-bezier(0.23,1,0.32,1), opacity 220ms;
}
dialog[open] { transform: scale(1) translateY(0); opacity: 1; }
```

### Progress bar
```css
.m-prog-fill {
  background: linear-gradient(90deg, #818cf8 0%, #a78bfa 100%);
  transition: width 350ms cubic-bezier(0.23,1,0.32,1);
}
```

## Layout Rules
- Modal: `min(960px, calc(100vw - 24px))` wide, `min(700px, calc(100vh - 40px))` tall
- Sidebar: 235px, dark bg, step numbers + labels
- Arch metrics: 4-col grid at top of overview step (Cloudflare analytics pattern)
- Cards have `border-radius: 10-11px`, transitions on `border-color + background`
- Never animate `all` — specify `border-color, background, transform, filter`
- Sidebar collapses at 640px, arch-flow goes vertical

## Typography
- Heading: 14-15px, font-weight 700, color #f1f5f9
- Label: 11.5px, font-weight 600, color #94a3b8
- Hint: 10-10.5px, color #334155-#475569
- Step section header: 9-10px uppercase, letter-spacing .1em, color #334155
- Monospace numbers: `ui-monospace,'SF Mono',monospace`
