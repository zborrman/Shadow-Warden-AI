"""
Accessibility widget injection for Streamlit dashboards.
WCAG 2.1 AA · Section 508 · EN 301 549

Usage:
    from warden.analytics.accessibility import inject_accessibility_widget
    inject_accessibility_widget()   # call once, before any st.* content
"""
from __future__ import annotations

from pathlib import Path

import streamlit as st


def inject_accessibility_widget() -> None:
    """
    Inject the Shadow Warden accessibility toolbar into the Streamlit page.

    Reads the shared accessibility-widget.js and injects it via
    st.markdown(unsafe_allow_html=True).  The widget is idempotent —
    a guard in the JS prevents double-initialisation on Streamlit reruns.
    """
    js_path = Path(__file__).resolve().parents[2] / "landing" / "accessibility-widget.js"
    if not js_path.exists():
        return  # fail-open: widget missing doesn't break the dashboard

    js_code = js_path.read_text(encoding="utf-8")

    # Streamlit renders st.markdown HTML into the page DOM.
    # The <script> tag executes in the browser on first render.
    st.markdown(
        f"""
<div id="sw-a11y-streamlit-host" style="display:none" aria-hidden="true"></div>
<script>
(function(){{
  if(document.getElementById('sw-a11y-btn'))return;
  var s=document.createElement('script');
  s.textContent={repr(js_code)};
  document.head.appendChild(s);
}})();
</script>
""",
        unsafe_allow_html=True,
    )
