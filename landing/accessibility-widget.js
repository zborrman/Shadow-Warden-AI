/**
 * Shadow Warden AI — Accessibility Widget v2
 * ────────────────────────────────────────────
 * Standards: WCAG 2.1 AA · Section 508 (US) · EN 301 549 (EU) · ADA
 *
 * Drop-in, zero-dependency, self-contained IIFE.
 * Add one <script> tag to any page — works everywhere.
 *
 * Features & WCAG mapping
 *   • Skip-to-content link     WCAG 2.4.1
 *   • Text resize ×3 steps     WCAG 1.4.4
 *   • High-contrast dark/light WCAG 1.4.3
 *   • Colour-vision simulation WCAG 1.4.1  (SVG feColorMatrix LUT)
 *   • Dyslexia-friendly font   WCAG 1.4.8
 *   • Reduce motion            WCAG 2.3.3  (auto-detects prefers-reduced-motion)
 *   • Enhanced focus ring      WCAG 2.4.7
 *   • Large cursor             motor accessibility
 *   • Line / word spacing      WCAG 1.4.12
 *   • Reading guide
 *   • ARIA live announcer      WCAG 4.1.3
 *   • Focus-trap in panel      WCAG 2.1.1 / 2.1.2
 *   • Keyboard shortcut Alt+A  WCAG 2.1.1
 *   • Persistent localStorage  UX
 *   • Respects prefers-contrast on first load
 */
(function () {
  'use strict';

  /* guard against double-init (e.g. Next.js hot-reload) */
  if (document.getElementById('sw-a11y-btn')) return;

  /* ── constants ────────────────────────────────────────────── */
  const STORAGE_KEY = 'sw-a11y';
  const NS          = 'sw-a11y';

  /* ── detect OS preferences on first visit ─────────────────── */
  const osPrefersReducedMotion =
    typeof window !== 'undefined' &&
    window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const osPrefersHighContrast =
    typeof window !== 'undefined' &&
    window.matchMedia &&
    (window.matchMedia('(prefers-contrast: more)').matches ||
     window.matchMedia('(forced-colors: active)').matches);

  const DEFAULTS = {
    textSize      : 'normal',
    contrast      : osPrefersHighContrast ? 'dark' : 'none',
    colorBlind    : 'none',
    dyslexiaFont  : false,
    reduceMotion  : osPrefersReducedMotion,
    enhancedFocus : false,
    largeCursor   : false,
    lineSpacing   : false,
    readingGuide  : false,
  };

  /* ── helpers ──────────────────────────────────────────────── */
  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => {
      if (k === 'className')   node.className = v;
      else if (k === 'textContent') node.textContent = v;
      else if (k === 'innerHTML')   node.innerHTML = v;
      else node.setAttribute(k, v);
    });
    (children || []).forEach(c => c && node.appendChild(c));
    return node;
  }

  function load() {
    try {
      const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null');
      /* first visit: use OS defaults */
      return saved ? Object.assign({}, DEFAULTS, saved) : Object.assign({}, DEFAULTS);
    } catch { return Object.assign({}, DEFAULTS); }
  }

  function save(s) {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(s)); } catch {}
  }

  /* ── state ────────────────────────────────────────────────── */
  let state   = load();
  let panelEl = null;
  let btnEl   = null;
  let guideEl = null;
  let liveEl  = null;

  /* ── CSS ──────────────────────────────────────────────────── */
  const STYLE = `
    @keyframes ${NS}-spin-ring {
      0%   { transform:rotate(0deg); }
      100% { transform:rotate(360deg); }
    }
    @keyframes ${NS}-pop-in {
      0%   { opacity:0; transform:translateY(18px) scale(.94); }
      100% { opacity:1; transform:translateY(0)    scale(1); }
    }

    /* skip link */
    #${NS}-skip {
      position:fixed;top:-9999px;left:50%;transform:translateX(-50%);
      z-index:999999;padding:12px 28px;border-radius:10px;
      background:linear-gradient(135deg,#0A84FF,#BF5AF2);
      color:#fff;font:700 14px/1.4 system-ui,sans-serif;
      text-decoration:none;white-space:nowrap;
      transition:top .15s ease;
      box-shadow:0 8px 32px rgba(10,132,255,.5);
    }
    #${NS}-skip:focus { top:16px; outline:3px solid #FFD700; outline-offset:2px; }

    /* ── trigger button ── */
    #${NS}-btn {
      position:fixed;bottom:24px;right:24px;z-index:99998;
      width:58px;height:58px;border-radius:50%;border:none;
      background:linear-gradient(135deg,#0A84FF 0%,#BF5AF2 100%);
      color:#fff;cursor:pointer;display:flex;align-items:center;justify-content:center;
      box-shadow:0 4px 20px rgba(10,132,255,.45),0 2px 8px rgba(0,0,0,.5);
      transition:transform .18s cubic-bezier(.34,1.56,.64,1),box-shadow .18s;
      padding:0;
    }
    #${NS}-btn::before {
      content:'';position:absolute;inset:-3px;border-radius:50%;
      background:linear-gradient(135deg,rgba(10,132,255,.4),rgba(191,90,242,.4));
      animation:${NS}-spin-ring 4s linear infinite;
      opacity:0;transition:opacity .2s;
    }
    #${NS}-btn:hover { transform:scale(1.1); box-shadow:0 8px 32px rgba(10,132,255,.6); }
    #${NS}-btn:hover::before { opacity:1; }
    #${NS}-btn:focus-visible { outline:3px solid #FFD700; outline-offset:4px; }
    #${NS}-btn[data-active="true"] {
      box-shadow:0 0 0 3px rgba(10,132,255,.35),0 4px 24px rgba(191,90,242,.5);
    }
    #${NS}-btn[data-active="true"]::before { opacity:1; }

    /* ── panel ── */
    #${NS}-panel {
      position:fixed;bottom:96px;right:24px;z-index:99997;
      width:340px;max-height:84vh;overflow-y:auto;overflow-x:hidden;
      border-radius:20px;
      background:rgba(7,10,20,0.97);
      border:1px solid rgba(255,255,255,.09);
      backdrop-filter:blur(24px) saturate(1.4);
      -webkit-backdrop-filter:blur(24px) saturate(1.4);
      box-shadow:
        0 0 0 1px rgba(10,132,255,.12),
        0 32px 80px rgba(0,0,0,.85),
        0 8px 32px rgba(10,132,255,.08),
        inset 0 1px 0 rgba(255,255,255,.06);
      font-family:system-ui,-apple-system,sans-serif;
      color:#E8ECF4;font-size:13px;line-height:1.55;
      opacity:0;transform:translateY(16px) scale(.96);pointer-events:none;
      transition:opacity .22s cubic-bezier(.4,0,.2,1),transform .22s cubic-bezier(.4,0,.2,1);
      scrollbar-width:thin;scrollbar-color:rgba(255,255,255,.1) transparent;
    }
    #${NS}-panel::-webkit-scrollbar { width:4px; }
    #${NS}-panel::-webkit-scrollbar-thumb { background:rgba(255,255,255,.1);border-radius:4px; }
    #${NS}-panel.open {
      opacity:1;transform:translateY(0) scale(1);pointer-events:all;
      animation:${NS}-pop-in .22s cubic-bezier(.4,0,.2,1) forwards;
    }
    @media(max-width:420px){
      #${NS}-panel { width:calc(100vw - 16px);right:8px;bottom:82px;max-height:90vh;border-radius:16px; }
      #${NS}-btn   { bottom:16px;right:16px; }
    }

    /* ── header ── */
    #${NS}-panel-header {
      display:flex;align-items:center;justify-content:space-between;
      padding:14px 16px 13px;
      border-bottom:1px solid rgba(255,255,255,.06);
      position:sticky;top:0;
      background:rgba(7,10,20,0.98);
      backdrop-filter:blur(24px);
      z-index:1;border-radius:20px 20px 0 0;
    }
    #${NS}-header-left { display:flex;align-items:center;gap:10px; }
    #${NS}-header-icon {
      width:32px;height:32px;border-radius:9px;flex-shrink:0;
      background:linear-gradient(135deg,#0A84FF,#BF5AF2);
      display:flex;align-items:center;justify-content:center;font-size:16px;
      box-shadow:0 4px 12px rgba(10,132,255,.35);
    }
    #${NS}-panel-header h2 {
      margin:0;font-size:13px;font-weight:700;letter-spacing:.01em;color:#F2F4F8;
    }
    #${NS}-panel-header small {
      display:block;font-size:9px;font-weight:500;
      color:#4A5568;margin-top:1px;letter-spacing:.08em;text-transform:uppercase;
    }
    #${NS}-close {
      background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);
      color:#6B7A90;border-radius:8px;width:28px;height:28px;
      cursor:pointer;font-size:13px;display:flex;align-items:center;
      justify-content:center;padding:0;flex-shrink:0;
      transition:all .15s;
    }
    #${NS}-close:hover { color:#fff;background:rgba(255,255,255,.12);border-color:rgba(255,255,255,.25); }
    #${NS}-close:focus-visible { outline:3px solid #FFD700;outline-offset:2px; }

    /* ── sections ── */
    .${NS}-section { padding:12px 16px;border-bottom:1px solid rgba(255,255,255,.04); }
    .${NS}-section:last-of-type { border-bottom:0; }
    .${NS}-label {
      display:flex;align-items:center;gap:6px;
      font-size:9px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;
      color:#3A4A5E;margin-bottom:10px;
    }
    .${NS}-label::before {
      content:'';display:inline-block;width:14px;height:2px;border-radius:2px;
      background:linear-gradient(90deg,#0A84FF,#BF5AF2);flex-shrink:0;
    }

    /* ── group pill buttons ── */
    .${NS}-group { display:flex;gap:4px;flex-wrap:wrap; }
    .${NS}-group button {
      flex:1;min-width:56px;padding:6px 8px;border-radius:10px;
      background:rgba(255,255,255,.04);
      border:1px solid rgba(255,255,255,.07);
      color:#7A8BA0;cursor:pointer;font-size:11px;font-weight:600;
      transition:all .15s;text-align:center;white-space:nowrap;font-family:inherit;
      letter-spacing:.01em;
    }
    .${NS}-group button:focus-visible { outline:3px solid #FFD700;outline-offset:2px; }
    .${NS}-group button[aria-pressed="true"] {
      background:linear-gradient(135deg,rgba(10,132,255,.25),rgba(191,90,242,.2));
      border-color:rgba(10,132,255,.45);color:#C4DCFF;font-weight:700;
      box-shadow:0 0 12px rgba(10,132,255,.15);
    }
    .${NS}-group button:hover:not([aria-pressed="true"]) {
      background:rgba(255,255,255,.09);color:#D0D8E8;border-color:rgba(255,255,255,.16);
    }

    /* ── toggle rows ── */
    .${NS}-toggle-row { padding:5px 0; }
    .${NS}-toggle-label {
      display:flex;align-items:center;justify-content:space-between;gap:10px;
      cursor:pointer;user-select:none;width:100%;
    }
    .${NS}-toggle-label > span:first-child {
      font-size:12px;color:#A0AABB;display:flex;align-items:center;gap:7px;flex:1;
      transition:color .15s;
    }
    .${NS}-toggle-label:hover > span:first-child { color:#D0D8E8; }

    /* switch track */
    .${NS}-switch { position:relative;width:42px;height:24px;flex-shrink:0; }
    .${NS}-switch input { opacity:0;width:0;height:0;position:absolute; }
    .${NS}-slider {
      position:absolute;inset:0;border-radius:24px;cursor:pointer;
      background:rgba(255,255,255,.08);border:1.5px solid rgba(255,255,255,.1);
      transition:background .22s,border-color .22s,box-shadow .22s;
    }
    .${NS}-slider::before {
      content:'';position:absolute;left:3px;top:3px;
      width:16px;height:16px;border-radius:50%;
      background:rgba(255,255,255,.35);
      box-shadow:0 1px 3px rgba(0,0,0,.4);
      transition:transform .22s cubic-bezier(.34,1.56,.64,1),background .22s;
    }
    .${NS}-switch input:checked + .${NS}-slider {
      background:linear-gradient(135deg,#0A84FF,#BF5AF2);
      border-color:rgba(10,132,255,.5);
      box-shadow:0 0 10px rgba(10,132,255,.3);
    }
    .${NS}-switch input:checked + .${NS}-slider::before {
      transform:translateX(18px);background:#fff;
      box-shadow:0 2px 6px rgba(0,0,0,.3);
    }
    .${NS}-switch input:focus-visible + .${NS}-slider { outline:3px solid #FFD700;outline-offset:2px; }

    /* ── reset button ── */
    #${NS}-reset {
      width:100%;padding:9px;border-radius:10px;
      background:rgba(255,45,85,.08);
      border:1px solid rgba(255,45,85,.2);
      color:rgba(255,120,130,.9);cursor:pointer;font-size:11px;font-weight:700;
      letter-spacing:.04em;text-transform:uppercase;
      transition:all .15s;font-family:inherit;
    }
    #${NS}-reset:hover { background:rgba(255,45,85,.16);color:#FFB0B8;border-color:rgba(255,45,85,.4); }
    #${NS}-reset:focus-visible { outline:3px solid #FFD700;outline-offset:2px; }

    /* ── compliance bar ── */
    .${NS}-compliance {
      display:flex;gap:4px;flex-wrap:wrap;padding:10px 16px 16px;
    }
    .${NS}-badge {
      font-size:8.5px;font-weight:800;letter-spacing:.07em;text-transform:uppercase;
      padding:3px 7px;border-radius:5px;
      background:rgba(10,132,255,.1);border:1px solid rgba(10,132,255,.2);
      color:rgba(100,180,255,.8);
    }

    /* live announcer */
    #${NS}-live {
      position:absolute;width:1px;height:1px;overflow:hidden;
      clip:rect(0 0 0 0);clip-path:inset(50%);white-space:nowrap;border:0;
    }

    /* ── body modifier classes ── */
    body.${NS}-text-large *{font-size:115% !important}
    body.${NS}-text-xl    *{font-size:135% !important}

    /* ── HIGH CONTRAST DARK — WCAG AAA ── */
    body.${NS}-contrast-dark{
      filter:contrast(2.8) brightness(0.62) saturate(1.6) !important;
      background:#000 !important;
    }
    /* restore natural look on media — they get over-darkened by the body filter */
    body.${NS}-contrast-dark img,
    body.${NS}-contrast-dark video,
    body.${NS}-contrast-dark canvas{
      filter:brightness(1.45) contrast(0.8) !important;
    }

    /* ── HIGH CONTRAST LIGHT — WCAG AAA ── */
    /* Invert the dark site → white background; hue-rotate restores natural colours */
    body.${NS}-contrast-light{
      filter:invert(1) hue-rotate(180deg) contrast(1.15) saturate(1.1) !important;
      background:#fff !important;
    }
    /* re-invert media so photos/videos look natural */
    body.${NS}-contrast-light img,
    body.${NS}-contrast-light video,
    body.${NS}-contrast-light canvas{
      filter:invert(1) hue-rotate(180deg) !important;
    }
    body.${NS}-cb-protanopia   {filter:url('#${NS}-cb-protanopia')}
    body.${NS}-cb-deuteranopia {filter:url('#${NS}-cb-deuteranopia')}
    body.${NS}-cb-tritanopia   {filter:url('#${NS}-cb-tritanopia')}
    body.${NS}-cb-achromatopsia{filter:grayscale(1)}
    body.${NS}-dyslexia *{font-family:'OpenDyslexic','Comic Sans MS','Arial',sans-serif !important;letter-spacing:.08em !important;word-spacing:.22em !important;}
    body.${NS}-reduce-motion *,body.${NS}-reduce-motion *::before,body.${NS}-reduce-motion *::after{
      animation-duration:.001ms !important;animation-iteration-count:1 !important;
      transition-duration:.001ms !important;scroll-behavior:auto !important;
    }
    body.${NS}-enhanced-focus *:focus,body.${NS}-enhanced-focus *:focus-visible{
      outline:4px solid #FFD700 !important;outline-offset:4px !important;
      box-shadow:0 0 0 8px rgba(255,215,0,.22) !important;
    }
    body.${NS}-large-cursor,body.${NS}-large-cursor *{
      cursor:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='44' height='44' viewBox='0 0 44 44'%3E%3Cpath d='M10 3 L10 34 L18 26 L24 40 L29 38 L23 24 L34 24 Z' fill='%23000' stroke='%23fff' stroke-width='2.5' stroke-linejoin='round'/%3E%3C/svg%3E") 10 3,auto !important
    }
    body.${NS}-line-spacing *{line-height:2.0 !important;letter-spacing:.05em !important;word-spacing:.18em !important;}

    /* reading guide */
    #${NS}-guide{
      position:fixed;left:0;right:0;height:44px;z-index:99990;
      background:rgba(255,215,0,.08);
      border-top:2px solid rgba(255,215,0,.45);
      border-bottom:2px solid rgba(255,215,0,.45);
      pointer-events:none;display:none;backdrop-filter:brightness(1.05);
    }
    body.${NS}-reading-guide #${NS}-guide{display:block}

    /* ── contrast: panel & button counter-corrections ── */

    /* DARK — lift panel out of the heavy body filter; apply its own crisp dark shell */
    body.${NS}-contrast-dark #${NS}-panel{
      filter:none !important;
      background:linear-gradient(160deg,#08080f 0%,#03030a 100%) !important;
      border:1.5px solid rgba(255,255,255,.55) !important;
      box-shadow:0 0 0 1px rgba(255,255,255,.15),0 28px 80px rgba(0,0,0,.98) !important;
      color:#fff !important;
    }
    body.${NS}-contrast-dark #${NS}-panel .${NS}-label{color:rgba(255,255,255,.55) !important}
    body.${NS}-contrast-dark .${NS}-badge{
      color:#7df !important;border-color:rgba(100,200,255,.5) !important;
      background:rgba(100,200,255,.12) !important;
    }
    body.${NS}-contrast-dark #${NS}-close{
      color:#fff !important;border-color:rgba(255,255,255,.4) !important;
      background:rgba(255,255,255,.07) !important;
    }
    body.${NS}-contrast-dark .${NS}-group button{
      color:#fff !important;border-color:rgba(255,255,255,.3) !important;
      background:rgba(255,255,255,.06) !important;
    }
    body.${NS}-contrast-dark .${NS}-group button[aria-pressed="true"]{
      background:rgba(100,180,255,.22) !important;
      border-color:rgba(100,180,255,.7) !important;
      color:#7df !important;
    }
    /* button stays visible — counter the body filter just enough */
    body.${NS}-contrast-dark #${NS}-btn{
      filter:brightness(1.35) contrast(0.7) !important;
    }

    /* LIGHT — counter-invert the panel so it shows in its original dark glassmorphism */
    body.${NS}-contrast-light #${NS}-panel{
      filter:invert(1) hue-rotate(180deg) !important;
    }
    /* counter-invert the trigger button so it looks correct */
    body.${NS}-contrast-light #${NS}-btn{
      filter:invert(1) hue-rotate(180deg) !important;
    }
  `;

  /* ── SVG colour-vision filters ────────────────────────────── */
  const CB_SVG = `<svg xmlns="http://www.w3.org/2000/svg"
      style="position:absolute;width:0;height:0;overflow:hidden" aria-hidden="true">
    <defs>
      <filter id="${NS}-cb-protanopia">
        <feColorMatrix type="matrix" values="
          0.567 0.433 0     0 0
          0.558 0.442 0     0 0
          0     0.242 0.758 0 0
          0     0     0     1 0"/>
      </filter>
      <filter id="${NS}-cb-deuteranopia">
        <feColorMatrix type="matrix" values="
          0.625 0.375 0     0 0
          0.700 0.300 0     0 0
          0     0.300 0.700 0 0
          0     0     0     1 0"/>
      </filter>
      <filter id="${NS}-cb-tritanopia">
        <feColorMatrix type="matrix" values="
          0.950 0.050 0     0 0
          0     0.433 0.567 0 0
          0     0.475 0.525 0 0
          0     0     0     1 0"/>
      </filter>
    </defs>
  </svg>`;

  /* ── screen-reader announcer ──────────────────────────────── */
  function announce(msg) {
    if (!liveEl) return;
    liveEl.textContent = '';
    requestAnimationFrame(() => { liveEl.textContent = msg; });
  }

  /* ── apply body classes from state ───────────────────────── */
  function applyState() {
    const c = document.body.classList;

    c.remove(`${NS}-text-large`, `${NS}-text-xl`);
    if (state.textSize === 'large') c.add(`${NS}-text-large`);
    else if (state.textSize === 'xl') c.add(`${NS}-text-xl`);

    c.remove(`${NS}-contrast-dark`, `${NS}-contrast-light`);
    if (state.contrast === 'dark')  c.add(`${NS}-contrast-dark`);
    else if (state.contrast === 'light') c.add(`${NS}-contrast-light`);

    c.remove(
      `${NS}-cb-protanopia`, `${NS}-cb-deuteranopia`,
      `${NS}-cb-tritanopia`, `${NS}-cb-achromatopsia`
    );
    if (state.colorBlind !== 'none') c.add(`${NS}-cb-${state.colorBlind}`);

    c.toggle(`${NS}-dyslexia`,        !!state.dyslexiaFont);
    c.toggle(`${NS}-reduce-motion`,   !!state.reduceMotion);
    c.toggle(`${NS}-enhanced-focus`,  !!state.enhancedFocus);
    c.toggle(`${NS}-large-cursor`,    !!state.largeCursor);
    c.toggle(`${NS}-line-spacing`,    !!state.lineSpacing);
    c.toggle(`${NS}-reading-guide`,   !!state.readingGuide);

    /* dot indicator on button */
    const hasActive = Object.entries(state).some(([, v]) =>
      v !== false && v !== 'none' && v !== 'normal'
    );
    if (btnEl) {
      btnEl.dataset.active = String(hasActive);
      btnEl.setAttribute('aria-label',
        hasActive
          ? 'Accessibility tools — options active (Alt+A)'
          : 'Accessibility tools — open panel (Alt+A)'
      );
    }
  }

  /* ── panel builder ────────────────────────────────────────── */
  function buildPanel() {
    const panel = el('div', {
      id          : `${NS}-panel`,
      role        : 'dialog',
      'aria-modal': 'true',
      'aria-label': 'Accessibility options',
    });

    /* sticky header */
    const closeBtn = el('button', {
      id          : `${NS}-close`,
      'aria-label': 'Close accessibility panel',
      innerHTML   : '✕',
    });
    closeBtn.addEventListener('click', closePanel);

    const iconEl = el('div', { id: `${NS}-header-icon`, 'aria-hidden': 'true' });
    iconEl.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="18" height="18">
      <circle cx="50" cy="18" r="11" fill="#fff"/>
      <path fill="#fff" d="M38 34 a12 12 0 0 1 24 0 v18 h10 a4 4 0 0 1 0 8 H58 a4 4 0 0 1-4-4 V42 H46 v10 l8 13 a4 4 0 1 1-6.9 4 L38 56 Z"/>
      <circle cx="38" cy="79" r="13" fill="none" stroke="#fff" stroke-width="7"/>
      <circle cx="68" cy="79" r="7" fill="none" stroke="#fff" stroke-width="5"/>
    </svg>`;
    const titleEl = el('div');
    titleEl.appendChild(el('h2', { textContent: 'Accessibility' }));
    titleEl.appendChild(el('small', { textContent: 'Alt + A  ·  WCAG 2.1 AA' }));
    const leftEl = el('div', { id: `${NS}-header-left` }, [iconEl, titleEl]);
    panel.appendChild(el('div', { id: `${NS}-panel-header` }, [leftEl, closeBtn]));

    /* text size */
    panel.appendChild(section('Text Size', group([
      { label: 'Normal',  value: 'normal', key: 'textSize' },
      { label: 'Large',   value: 'large',  key: 'textSize' },
      { label: 'X-Large', value: 'xl',     key: 'textSize' },
    ])));

    /* contrast */
    panel.appendChild(section('Contrast', group([
      { label: 'Default', value: 'none',  key: 'contrast' },
      { label: '⬛ Dark',  value: 'dark',  key: 'contrast' },
      { label: '⬜ Light', value: 'light', key: 'contrast' },
    ])));

    /* colour vision */
    panel.appendChild(section('Colour Vision', group([
      { label: 'Off',          value: 'none',          key: 'colorBlind' },
      { label: 'Protanopia',   value: 'protanopia',    key: 'colorBlind' },
      { label: 'Deuteranopia', value: 'deuteranopia',  key: 'colorBlind' },
      { label: 'Tritanopia',   value: 'tritanopia',    key: 'colorBlind' },
      { label: 'Greyscale',    value: 'achromatopsia', key: 'colorBlind' },
    ])));

    /* toggles */
    const toggleSec = el('div', { className: `${NS}-section` });
    toggleSec.appendChild(el('div', { className: `${NS}-label`, textContent: 'Reading & Motor' }));
    [
      { key: 'dyslexiaFont',  label: '📖 Dyslexia font'       },
      { key: 'lineSpacing',   label: '↕ Line & word spacing'   },
      { key: 'reduceMotion',  label: '🎞 Reduce motion'        },
      { key: 'enhancedFocus', label: '🔲 Enhanced focus ring'  },
      { key: 'largeCursor',   label: '🖱 Large cursor'         },
      { key: 'readingGuide',  label: '📏 Reading guide'        },
    ].forEach(({ key, label }) => toggleSec.appendChild(toggle(key, label)));
    panel.appendChild(toggleSec);

    /* reset */
    const resetSec = el('div', { className: `${NS}-section` });
    const resetBtn = el('button', {
      id          : `${NS}-reset`,
      textContent : 'Reset all settings',
      'aria-label': 'Reset all accessibility settings to defaults',
    });
    resetBtn.addEventListener('click', () => {
      state = Object.assign({}, DEFAULTS);
      save(state);
      applyState();
      syncPanel();
      announce('All accessibility settings reset to defaults.');
    });
    resetSec.appendChild(resetBtn);
    panel.appendChild(resetSec);

    /* compliance badges */
    const comp = el('div', { className: `${NS}-compliance`, 'aria-label': 'Compliance standards' });
    ['WCAG 2.1 AA', 'Section 508', 'EN 301 549', 'ADA'].forEach(s =>
      comp.appendChild(el('span', { className: `${NS}-badge`, textContent: s }))
    );
    panel.appendChild(comp);

    return panel;
  }

  function section(title, content) {
    const s = el('div', { className: `${NS}-section` });
    s.appendChild(el('div', { className: `${NS}-label`, textContent: title }));
    s.appendChild(content);
    return s;
  }

  function group(items) {
    const g = el('div', { className: `${NS}-group`, role: 'group' });
    items.forEach(({ label, value, key }) => {
      const b = el('button', {
        textContent    : label,
        'aria-pressed' : String(state[key] === value),
        'data-key'     : key,
        'data-value'   : value,
      });
      b.addEventListener('click', () => {
        state[key] = value;
        save(state);
        applyState();
        g.querySelectorAll('button').forEach(x =>
          x.setAttribute('aria-pressed', String(state[key] === x.dataset.value))
        );
        announce(`${label} selected.`);
      });
      g.appendChild(b);
    });
    return g;
  }

  function toggle(key, label) {
    const row = el('div',   { className: `${NS}-toggle-row` });
    const id  = `${NS}-toggle-${key}`;
    const lbl = el('label', { className: `${NS}-toggle-label`, 'for': id });
    lbl.appendChild(el('span', { textContent: label }));
    const sw  = el('span',  { className: `${NS}-switch` });
    const inp = el('input', {
      type: 'checkbox', id, role: 'switch',
      'aria-checked': String(!!state[key]),
    });
    inp.checked = !!state[key];
    inp.addEventListener('change', () => {
      state[key] = inp.checked;
      inp.setAttribute('aria-checked', String(inp.checked));
      save(state);
      applyState();
      announce(`${label.replace(/^\S+\s/, '')}: ${inp.checked ? 'on' : 'off'}.`);
    });
    sw.appendChild(inp);
    sw.appendChild(el('span', { className: `${NS}-slider`, 'aria-hidden': 'true' }));
    lbl.appendChild(sw);
    row.appendChild(lbl);
    return row;
  }

  /* ── sync panel UI to current state ──────────────────────── */
  function syncPanel() {
    if (!panelEl) return;
    panelEl.querySelectorAll('[data-key]').forEach(b =>
      b.setAttribute('aria-pressed', String(state[b.dataset.key] === b.dataset.value))
    );
    panelEl.querySelectorAll('input[type=checkbox]').forEach(inp => {
      const k = inp.id.replace(`${NS}-toggle-`, '');
      inp.checked = !!state[k];
      inp.setAttribute('aria-checked', String(!!state[k]));
    });
  }

  /* ── focus trap ───────────────────────────────────────────── */
  function focusable() {
    return [...panelEl.querySelectorAll(
      'button:not([disabled]),input:not([disabled]),[tabindex]:not([tabindex="-1"])'
    )].filter(e => e.offsetParent !== null);
  }

  function trapFocus(e) {
    if (e.key !== 'Tab') return;
    const f = focusable();
    if (!f.length) return;
    if (e.shiftKey && document.activeElement === f[0]) {
      e.preventDefault(); f[f.length - 1].focus();
    } else if (!e.shiftKey && document.activeElement === f[f.length - 1]) {
      e.preventDefault(); f[0].focus();
    }
  }

  /* ── open / close ─────────────────────────────────────────── */
  function openPanel() {
    panelEl.classList.add('open');
    btnEl.setAttribute('aria-expanded', 'true');
    panelEl.addEventListener('keydown', trapFocus);
    panelEl.addEventListener('keydown', escClose);
    requestAnimationFrame(() => { const f = focusable(); if (f[0]) f[0].focus(); });
    announce('Accessibility panel opened. Use Tab to navigate, Escape to close.');
  }

  function closePanel() {
    panelEl.classList.remove('open');
    btnEl.setAttribute('aria-expanded', 'false');
    panelEl.removeEventListener('keydown', trapFocus);
    panelEl.removeEventListener('keydown', escClose);
    btnEl.focus();
    announce('Accessibility panel closed.');
  }

  function escClose(e) { if (e.key === 'Escape') closePanel(); }
  function togglePanel() { panelEl.classList.contains('open') ? closePanel() : openPanel(); }

  /* ── reading guide ────────────────────────────────────────── */
  function initGuide() {
    guideEl = el('div', { id: `${NS}-guide`, 'aria-hidden': 'true' });
    document.body.appendChild(guideEl);
    document.addEventListener('mousemove', e => {
      if (state.readingGuide) guideEl.style.top = `${e.clientY - 22}px`;
    }, { passive: true });
  }

  /* ── ensure a skip-link target exists ────────────────────── */
  function ensureMainLandmark() {
    const existing = document.querySelector('main,[role="main"],#main-content');
    if (existing) {
      if (!existing.id) existing.id = 'main-content';
      return existing.id;
    }
    /* inject a non-visual anchor at the start of body content */
    const anchor = el('div', { id: 'main-content', tabindex: '-1',
      style: 'outline:none', 'aria-hidden': 'true' });
    const ref = document.body.querySelector(':not(#' + NS + '-skip):not(style):not(script)');
    document.body.insertBefore(anchor, ref || document.body.firstChild);
    return 'main-content';
  }

  /* ── bootstrap ────────────────────────────────────────────── */
  function init() {
    /* 1. styles */
    document.head.appendChild(el('style', { id: `${NS}-styles`, textContent: STYLE }));

    /* 2. SVG colour-vision filters */
    const svgWrap = document.createElement('div');
    svgWrap.innerHTML = CB_SVG;
    svgWrap.style.cssText = 'position:absolute;width:0;height:0;overflow:hidden;';
    document.body.insertBefore(svgWrap, document.body.firstChild);

    /* 3. live region */
    liveEl = el('div', {
      id: `${NS}-live`, role: 'status',
      'aria-live': 'polite', 'aria-atomic': 'true',
    });
    document.body.appendChild(liveEl);

    /* 4. skip link — injected as FIRST child so Tab hits it first */
    const mainId = ensureMainLandmark();
    const skipLink = el('a', {
      id: `${NS}-skip`, href: `#${mainId}`,
      textContent: 'Skip to main content',
    });
    document.body.insertBefore(skipLink, document.body.firstChild);

    /* 5. trigger button */
    btnEl = el('button', {
      id              : `${NS}-btn`,
      'aria-label'    : 'Accessibility tools — open panel (Alt+A)',
      'aria-controls' : `${NS}-panel`,
      'aria-expanded' : 'false',
      'aria-haspopup' : 'dialog',
      title           : 'Accessibility options — WCAG 2.1 AA · Section 508 · EN 301 549',
      /* International Symbol of Access (ISO 7001 PF 001) */
      innerHTML: `<svg xmlns="http://www.w3.org/2000/svg" width="30" height="30"
            viewBox="0 0 100 100" aria-hidden="true" focusable="false" role="img">
          <title>Accessibility options</title>
          <rect width="100" height="100" rx="14" fill="#0057B8"/>
          <circle cx="50" cy="18" r="11" fill="#fff"/>
          <path fill="#fff" d="M38 34 a12 12 0 0 1 24 0 v18 h10 a4 4 0 0 1 0 8 H58 a4 4 0 0 1-4-4 V42 H46 v10 l8 13 a4 4 0 1 1-6.9 4 L38 56 Z"/>
          <circle cx="38" cy="79" r="13" fill="none" stroke="#fff" stroke-width="7"/>
          <circle cx="68" cy="79" r="7" fill="none" stroke="#fff" stroke-width="5"/>
        </svg>`,
    });
    btnEl.addEventListener('click', togglePanel);
    document.body.appendChild(btnEl);

    /* 6. panel */
    panelEl = buildPanel();
    document.body.appendChild(panelEl);

    /* 7. reading guide layer */
    initGuide();

    /* 8. close on outside click */
    document.addEventListener('click', e => {
      if (panelEl.classList.contains('open') &&
          !panelEl.contains(e.target) && !btnEl.contains(e.target)) {
        closePanel();
      }
    });

    /* 9. global keyboard shortcut Alt+A */
    document.addEventListener('keydown', e => {
      if (e.altKey && !e.ctrlKey && !e.metaKey && e.key.toLowerCase() === 'a') {
        e.preventDefault();
        togglePanel();
      }
    });

    /* 10. apply saved / OS-detected state */
    applyState();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
