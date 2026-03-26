/**
 * portal/src/utils/format.ts
 * ──────────────────────────
 * Pure formatting utilities — no side effects, no imports from project code.
 */

// ── Currency ───────────────────────────────────────────────────────────────────

/** Format a number as a USD dollar amount with optional compact notation. */
export function formatUsd(value: number, compact = false): string {
  if (compact) {
    if (value >= 1_000_000) return `$${(value / 1_000_000).toFixed(1)}M`
    if (value >= 1_000)     return `$${(value / 1_000).toFixed(0)}K`
  }
  return '$' + value.toLocaleString('en-US', { maximumFractionDigits: 0 })
}

/** Format a percentage (0–100 or 0–1). Pass `fraction=true` if value is 0–1. */
export function formatPct(value: number, fraction = false): string {
  const pct = fraction ? value * 100 : value
  return `${pct.toFixed(1)}%`
}

// ── Numbers ────────────────────────────────────────────────────────────────────

/** Compact number: 1_234_567 → "1.2M" */
export function formatCompact(n: number): string {
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1)}B`
  if (n >= 1_000_000)     return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000)         return `${(n / 1_000).toFixed(0)}K`
  return n.toLocaleString()
}

/** Format latency in ms, auto-switching to seconds for values ≥ 1000ms. */
export function formatLatency(ms: number): string {
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)}s`
  return `${ms.toFixed(1)}ms`
}

// ── Dates ──────────────────────────────────────────────────────────────────────

/** ISO string → "Mar 26, 2026" */
export function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
  })
}

/** ISO string → "Mar 26, 14:32" */
export function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString('en-US', {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false,
  })
}

/** ISO string → relative "2 minutes ago" */
export function formatRelative(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const sec  = Math.floor(diff / 1000)
  if (sec < 60)   return `${sec}s ago`
  const min = Math.floor(sec / 60)
  if (min < 60)   return `${min}m ago`
  const hr  = Math.floor(min / 60)
  if (hr < 24)    return `${hr}h ago`
  return `${Math.floor(hr / 24)}d ago`
}

// ── Risk level ─────────────────────────────────────────────────────────────────

/** Returns a Tailwind color class string for a given risk level string. */
export function riskColor(level: string): string {
  switch (level.toLowerCase()) {
    case 'block':  return 'text-red-400'
    case 'high':   return 'text-orange-400'
    case 'medium': return 'text-amber-400'
    case 'low':    return 'text-green-400'
    default:       return 'text-slate-400'
  }
}

export function riskBg(level: string): string {
  switch (level.toLowerCase()) {
    case 'block':  return 'bg-red-400/10 border-red-400/20'
    case 'high':   return 'bg-orange-400/10 border-orange-400/20'
    case 'medium': return 'bg-amber-400/10 border-amber-400/20'
    case 'low':    return 'bg-green-400/10 border-green-400/20'
    default:       return 'bg-white/5 border-white/10'
  }
}

// ── Strings ────────────────────────────────────────────────────────────────────

/** Truncate with ellipsis: "very long string" → "very lon…" */
export function truncate(s: string, max = 40): string {
  return s.length > max ? s.slice(0, max) + '…' : s
}

/** snake_case / kebab-case → "Title Case" */
export function toTitleCase(s: string): string {
  return s.replace(/[_-]/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

/** UUID string → short 8-char prefix for display: "a1b2c3d4…" */
export function shortId(id: string): string {
  return id.slice(0, 8) + '…'
}

// ── Requests / quota ───────────────────────────────────────────────────────────

/** Returns usage percentage clamped to [0, 100]. */
export function usagePct(used: number, quota: number): number {
  if (quota <= 0) return 0
  return Math.min(100, Math.round((used / quota) * 100))
}

/** Returns a color class based on usage percentage. */
export function usageColor(pct: number): string {
  if (pct >= 90) return 'bg-red-500'
  if (pct >= 75) return 'bg-amber-500'
  return 'bg-brand-400'
}
