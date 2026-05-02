'use client';

import { useEffect } from 'react';

/**
 * AccessibilityWidget — React/Next.js client component
 * WCAG 2.1 AA · Section 508 (US) · EN 301 549 (EU)
 *
 * Injects the standalone accessibility-widget.js at runtime.
 * Add <AccessibilityWidget /> to the root layout once.
 */
export default function AccessibilityWidget() {
  useEffect(() => {
    if (document.getElementById('sw-a11y-btn')) return; // already loaded
    const script = document.createElement('script');
    script.src = '/accessibility-widget.js';
    script.async = true;
    document.body.appendChild(script);
    return () => { /* leave widget mounted across navigation */ };
  }, []);

  return null;
}
