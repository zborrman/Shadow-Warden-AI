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
    /* skip link */
    #${NS}-skip {
      position:fixed;top:-9999px;left:50%;transform:translateX(-50%);
      z-index:999999;padding:12px 28px;border-radius:8px;
      background:#0051C3;color:#fff;font:700 14px/1.4 system-ui,sans-serif;
      text-decoration:none;white-space:nowrap;
      transition:top .15s ease;border:2px solid rgba(255,255,255,.8);
      box-shadow:0 4px 24px rgba(0,0,0,.5);
    }
    #${NS}-skip:focus { top:16px; outline:3px solid #FFD700; outline-offset:2px; }

    /* trigger button */
    #${NS}-btn {
      position:fixed;bottom:24px;right:24px;z-index:99998;
      width:56px;height:56px;border-radius:50%;
      background:#0051C3;border:2.5px solid rgba(255,255,255,.3);
      color:#fff;cursor:pointer;display:flex;align-items:center;
      justify-content:center;
      box-shadow:0 4px 24px rgba(0,81,195,.55),0 2px 8px rgba(0,0,0,.4);
      transition:background .15s,transform .15s,box-shadow .15s;
    }
    #${NS}-btn:hover {
      background:#0066FF;transform:scale(1.08);
      box-shadow:0 6px 32px rgba(0,102,255,.65);
    }
    #${NS}-btn:focus-visible {
      outline:3px solid #FFD700;outline-offset:4px;
    }
    #${NS}-btn[data-active="true"] {
      background:#0044A8;
      box-shadow:0 0 0 4px rgba(255,215,0,.4),0 4px 24px rgba(0,81,195,.55);
    }

    /* panel */
    #${NS}-panel {
      position:fixed;bottom:92px;right:24px;z-index:99997;
      width:330px;max-height:82vh;overflow-y:auto;overflow-x:hidden;
      background:#0D1117;border:1px solid rgba(255,255,255,.14);
      border-radius:18px;
      box-shadow:0 24px 64px rgba(0,0,0,.8),0 4px 16px rgba(0,0,0,.4);
      font-family:system-ui,-apple-system,sans-serif;
      color:#EFEFEF;font-size:13px;line-height:1.5;
      opacity:0;transform:translateY(14px) scale(.97);
      pointer-events:none;
      transition:opacity .2s cubic-bezier(.4,0,.2,1),transform .2s cubic-bezier(.4,0,.2,1);
      scrollbar-width:thin;scrollbar-color:#2A3040 transparent;
    }
    #${NS}-panel::-webkit-scrollbar{width:5px}
    #${NS}-panel::-webkit-scrollbar-thumb{background:#2A3040;border-radius:3px}
    #${NS}-panel.open {
      opacity:1;transform:translateY(0) scale(1);pointer-events:all;
    }
    @media(max-width:420px){
      #${NS}-panel{
        width:calc(100vw - 16px);right:8px;bottom:80px;
        max-height:90vh;border-radius:14px;
      }
      #${NS}-btn{bottom:16px;right:16px;}
    }

    /* panel header */
    #${NS}-panel-header {
      display:flex;align-items:center;justify-content:space-between;
      padding:14px 16px 12px;
      border-bottom:1px solid rgba(255,255,255,.07);
      position:sticky;top:0;background:#0D1117;z-index:1;
    }
    #${NS}-panel-header h2 {
      margin:0;font-size:13px;font-weight:700;letter-spacing:.02em;
      color:#F0F0F0;display:flex;align-items:center;gap:8px;
    }
    #${NS}-panel-header small {
      display:block;font-size:9.5px;font-weight:400;
      color:#5A6880;margin-top:1px;letter-spacing:.06em;
    }
    #${NS}-close {
      background:transparent;border:1px solid rgba(255,255,255,.12);
      color:#8A9AAA;border-radius:7px;width:30px;height:30px;
      cursor:pointer;font-size:15px;display:flex;align-items:center;
      justify-content:center;line-height:1;padding:0;flex-shrink:0;
      transition:color .12s,border-color .12s,background .12s;
    }
    #${NS}-close:hover{color:#fff;border-color:rgba(255,255,255,.35);background:rgba(255,255,255,.07)}
    #${NS}-close:focus-visible{outline:3px solid #FFD700;outline-offset:2px}

    /* sections */
    .${NS}-section{padding:11px 16px;border-bottom:1px solid rgba(255,255,255,.05)}
    .${NS}-section:last-of-type{border-bottom:0}
    .${NS}-label{
      font-size:9.5px;font-weight:700;letter-spacing:.12em;
      text-transform:uppercase;color:#5A6880;margin-bottom:9px;
    }

    /* group buttons */
    .${NS}-group{display:flex;gap:5px;flex-wrap:wrap}
    .${NS}-group button{
      flex:1;min-width:58px;padding:6px 7px;border-radius:8px;
      background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.09);
      color:#B0BEC8;cursor:pointer;font-size:11px;font-weight:500;
      transition:background .12s,border-color .12s,color .12s;
      text-align:center;white-space:nowrap;font-family:inherit;
    }
    .${NS}-group button:focus-visible{outline:3px solid #FFD700;outline-offset:2px}
    .${NS}-group button[aria-pressed="true"]{
      background:#0051C3;border-color:#4494FF;color:#fff;font-weight:600;
    }
    .${NS}-group button:hover:not([aria-pressed="true"]){
      background:rgba(255,255,255,.11);color:#fff;border-color:rgba(255,255,255,.2);
    }

    /* toggle rows */
    .${NS}-toggle-row{
      display:flex;align-items:center;justify-content:space-between;
      padding:6px 0;gap:10px;
    }
    .${NS}-toggle-label{
      font-size:12px;color:#C0CCD8;display:flex;align-items:center;gap:7px;
      cursor:pointer;user-select:none;flex:1;
    }
    .${NS}-switch{position:relative;width:40px;height:23px;flex-shrink:0}
    .${NS}-switch input{opacity:0;width:0;height:0;position:absolute}
    .${NS}-slider{
      position:absolute;inset:0;background:#1E2533;
      border-radius:23px;cursor:pointer;
      transition:background .2s,border-color .2s;
      border:1.5px solid rgba(255,255,255,.08);
    }
    .${NS}-slider::before{
      content:'';position:absolute;left:3px;top:3px;
      width:15px;height:15px;border-radius:50%;background:#6A7A8A;
      transition:transform .2s,background .2s;
    }
    .${NS}-switch input:checked+.${NS}-slider{background:#0051C3;border-color:#4494FF}
    .${NS}-switch input:checked+.${NS}-slider::before{transform:translateX(17px);background:#fff}
    .${NS}-switch input:focus-visible+.${NS}-slider{outline:3px solid #FFD700;outline-offset:2px}

    /* reset */
    #${NS}-reset{
      width:100%;padding:9px;border-radius:9px;
      background:rgba(255,60,60,.1);border:1px solid rgba(255,80,80,.2);
      color:#FF9999;cursor:pointer;font-size:12px;font-weight:600;
      transition:background .15s;font-family:inherit;
    }
    #${NS}-reset:hover{background:rgba(255,60,60,.2);color:#FFB5B5}
    #${NS}-reset:focus-visible{outline:3px solid #FFD700;outline-offset:2px}

    /* compliance badges */
    .${NS}-compliance{
      display:flex;gap:5px;flex-wrap:wrap;
      padding:10px 16px 14px;
    }
    .${NS}-badge{
      font-size:9px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;
      padding:3px 7px;border-radius:4px;
      background:rgba(0,81,195,.2);border:1px solid rgba(68,148,255,.25);color:#7BB8FF;
    }

    /* live announcer (visually hidden) */
    #${NS}-live{
      position:absolute;width:1px;height:1px;overflow:hidden;
      clip:rect(0 0 0 0);clip-path:inset(50%);white-space:nowrap;border:0;
    }

    /* ── body modifier classes ── */
    body.${NS}-text-large *{font-size:115% !important}
    body.${NS}-text-xl    *{font-size:135% !important}

    body.${NS}-contrast-dark{
      filter:contrast(1.55) brightness(0.88) !important;
      background:#000 !important;
    }
    body.${NS}-contrast-light{
      filter:contrast(1.65) !important;
      background:#fff !important;color:#000 !important;
    }

    body.${NS}-cb-protanopia   {filter:url('#${NS}-cb-protanopia')}
    body.${NS}-cb-deuteranopia {filter:url('#${NS}-cb-deuteranopia')}
    body.${NS}-cb-tritanopia   {filter:url('#${NS}-cb-tritanopia')}
    body.${NS}-cb-achromatopsia{filter:grayscale(1)}

    body.${NS}-dyslexia *{
      font-family:'OpenDyslexic','Comic Sans MS','Arial',sans-serif !important;
      letter-spacing:.08em !important;word-spacing:.22em !important;
    }

    body.${NS}-reduce-motion *,
    body.${NS}-reduce-motion *::before,
    body.${NS}-reduce-motion *::after{
      animation-duration:.001ms !important;
      animation-iteration-count:1 !important;
      transition-duration:.001ms !important;
      scroll-behavior:auto !important;
    }

    body.${NS}-enhanced-focus *:focus,
    body.${NS}-enhanced-focus *:focus-visible{
      outline:4px solid #FFD700 !important;
      outline-offset:4px !important;
      box-shadow:0 0 0 8px rgba(255,215,0,.22) !important;
    }

    body.${NS}-large-cursor,body.${NS}-large-cursor *{
      cursor:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='44' height='44' viewBox='0 0 44 44'%3E%3Cpath d='M10 3 L10 34 L18 26 L24 40 L29 38 L23 24 L34 24 Z' fill='%23000' stroke='%23fff' stroke-width='2.5' stroke-linejoin='round'/%3E%3C/svg%3E") 10 3,auto !important
    }

    body.${NS}-line-spacing *{
      line-height:2.0 !important;
      letter-spacing:.05em !important;
      word-spacing:.18em !important;
    }

    /* reading guide */
    #${NS}-guide{
      position:fixed;left:0;right:0;height:44px;z-index:99990;
      background:rgba(255,215,0,.1);
      border-top:2px solid rgba(255,215,0,.5);
      border-bottom:2px solid rgba(255,215,0,.5);
      pointer-events:none;display:none;
      backdrop-filter:brightness(1.05);
    }
    body.${NS}-reading-guide #${NS}-guide{display:block}

    /* panel stays readable in contrast modes */
    body.${NS}-contrast-dark  #${NS}-panel{filter:none;background:#000;border-color:#fff}
    body.${NS}-contrast-light #${NS}-panel{filter:none;background:#fff;border-color:#000;color:#000}
    body.${NS}-contrast-light #${NS}-panel .${NS}-label{color:#333}
    body.${NS}-contrast-light .${NS}-badge{color:#003080;border-color:#0044cc;background:rgba(0,65,195,.1)}
    body.${NS}-contrast-light #${NS}-close{color:#333;border-color:#999}
    body.${NS}-contrast-light .${NS}-group button{color:#333;border-color:#999;background:rgba(0,0,0,.05)}
    body.${NS}-contrast-light .${NS}-toggle-label{color:#111}
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

    const titleGroup = el('div');
    titleGroup.appendChild(el('h2', {}, [
      el('span', { 'aria-hidden': 'true', textContent: '♿' }),
      el('span', { textContent: ' Accessibility' }),
    ]));
    titleGroup.querySelector('h2').appendChild(
      el('small', { textContent: 'Alt + A  ·  WCAG 2.1 AA' })
    );
    panel.appendChild(el('div', { id: `${NS}-panel-header` }, [titleGroup, closeBtn]));

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
    const row   = el('div',   { className: `${NS}-toggle-row` });
    const id    = `${NS}-toggle-${key}`;
    const lbl   = el('label', { className: `${NS}-toggle-label`, 'for': id, textContent: label });
    const sw    = el('span',  { className: `${NS}-switch` });
    const inp   = el('input', {
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
    row.appendChild(lbl);
    row.appendChild(sw);
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
      innerHTML: `<span style="font-size:30px;line-height:1;display:flex;align-items:center;justify-content:center" aria-hidden="true">♿</span>`,
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
