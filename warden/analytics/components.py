"""
warden/analytics/components.py  (DS-01)
────────────────────────────────────────
Shared Streamlit UI helpers that mirror the @shadow-warden/ui design tokens.
All colours reference the same CSS custom-property values so dark/light mode
remains consistent with the Portal and SOC Dashboard.

Usage:
    from warden.analytics.components import card, metric_card, badge, section_header
"""
from __future__ import annotations

import streamlit as st

# ── Design tokens ─────────────────────────────────────────────────────────────

_SURFACE   = "#1e293b"
_SURFACE_2 = "#0f172a"
_BORDER    = "#334155"
_TEXT      = "#f8fafc"
_MUTED     = "#94a3b8"
_BRAND     = "#3b82f6"

_BADGE_STYLES: dict[str, dict[str, str]] = {
    "success": {"bg": "rgba(34,197,94,0.12)",  "border": "rgba(34,197,94,0.25)",  "color": "#4ade80"},
    "warning": {"bg": "rgba(245,158,11,0.12)", "border": "rgba(245,158,11,0.25)", "color": "#fbbf24"},
    "error":   {"bg": "rgba(239,68,68,0.12)",  "border": "rgba(239,68,68,0.25)",  "color": "#f87171"},
    "info":    {"bg": "rgba(59,130,246,0.12)",  "border": "rgba(59,130,246,0.25)", "color": "#60a5fa"},
    "neutral": {"bg": "rgba(148,163,184,0.10)", "border": "rgba(148,163,184,0.20)","color": "#94a3b8"},
    "violet":  {"bg": "rgba(139,92,246,0.12)",  "border": "rgba(139,92,246,0.25)", "color": "#a78bfa"},
}


# ── Components ─────────────────────────────────────────────────────────────────

def card(title: str, content: str, footer: str | None = None) -> None:
    """Render a styled card matching the @shadow-warden/ui Card component."""
    footer_html = (
        f'<div style="margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid {_BORDER};'
        f'font-size:0.75rem;color:{_MUTED};">{footer}</div>'
        if footer else ""
    )
    st.markdown(
        f"""<div style="
            background:{_SURFACE};
            border:1px solid {_BORDER};
            border-radius:0.75rem;
            padding:1.25rem 1.5rem;
            margin-bottom:1rem;
        ">
            <h3 style="margin:0 0 0.5rem;font-size:1rem;font-weight:600;color:{_TEXT};">{title}</h3>
            <p style="margin:0;font-size:0.875rem;color:{_MUTED};">{content}</p>
            {footer_html}
        </div>""",
        unsafe_allow_html=True,
    )


def metric_card(
    label: str,
    value: str | int | float,
    sub:   str | None = None,
    delta: str | None = None,
    delta_positive: bool = True,
) -> None:
    """Render a metric card (mirrors the SOC Dashboard StatCard)."""
    delta_html = ""
    if delta is not None:
        delta_color = "#4ade80" if delta_positive else "#f87171"
        delta_html = f'<p style="margin:0.25rem 0 0;font-size:0.75rem;color:{delta_color};">{delta}</p>'

    sub_html = f'<p style="margin:0.125rem 0 0;font-size:0.75rem;color:{_MUTED};">{sub}</p>' if sub else ""

    st.markdown(
        f"""<div style="
            background:{_SURFACE};
            border:1px solid {_BORDER};
            border-radius:0.75rem;
            padding:1.25rem 1.5rem;
        ">
            <p style="margin:0 0 0.5rem;font-size:0.6875rem;font-weight:500;letter-spacing:0.05em;
               text-transform:uppercase;color:{_MUTED};">{label}</p>
            <p style="margin:0;font-size:1.5rem;font-weight:700;color:{_TEXT};">{value}</p>
            {sub_html}
            {delta_html}
        </div>""",
        unsafe_allow_html=True,
    )


def badge(text: str, variant: str = "neutral") -> str:
    """Return an inline HTML badge string. Use inside st.markdown(..., unsafe_allow_html=True)."""
    s = _BADGE_STYLES.get(variant, _BADGE_STYLES["neutral"])
    return (
        f'<span style="display:inline-flex;align-items:center;gap:0.375rem;'
        f'padding:0.125rem 0.625rem;border-radius:9999px;font-size:0.6875rem;font-weight:600;'
        f'background:{s["bg"]};border:1px solid {s["border"]};color:{s["color"]};">{text}</span>'
    )


def section_header(title: str, description: str | None = None) -> None:
    """Render a section heading consistent with the Portal/Dashboard headings."""
    desc_html = (
        f'<p style="margin:0.25rem 0 0;font-size:0.875rem;color:{_MUTED};">{description}</p>'
        if description else ""
    )
    st.markdown(
        f"""<div style="margin-bottom:1.25rem;">
            <h2 style="margin:0;font-size:1.125rem;font-weight:600;color:{_TEXT};">{title}</h2>
            {desc_html}
        </div>""",
        unsafe_allow_html=True,
    )


def alert(message: str, variant: str = "info", icon: str | None = None) -> None:
    """Render an alert banner matching the design system status colours."""
    s = _BADGE_STYLES.get(variant, _BADGE_STYLES["info"])
    icon_html = f'<span style="margin-right:0.5rem;">{icon}</span>' if icon else ""
    st.markdown(
        f"""<div style="
            display:flex;align-items:flex-start;gap:0.5rem;
            background:{s["bg"]};border:1px solid {s["border"]};border-radius:0.5rem;
            padding:0.75rem 1rem;margin-bottom:0.75rem;
            font-size:0.875rem;color:{s["color"]};
        ">{icon_html}{message}</div>""",
        unsafe_allow_html=True,
    )


def divider() -> None:
    """Render a subtle horizontal rule matching the border token."""
    st.markdown(
        f'<hr style="border:none;border-top:1px solid {_BORDER};margin:1rem 0;">',
        unsafe_allow_html=True,
    )
