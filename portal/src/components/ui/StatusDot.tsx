/**
 * portal/src/components/ui/StatusDot.tsx
 * ─────────────────────────────────────────
 * Animated status indicator dot. 'ok' pulses green, 'error' red, 'loading' amber.
 */
type Status = 'ok' | 'error' | 'loading' | 'disabled'

const COLOR: Record<Status, string> = {
  ok:       'bg-green-400',
  error:    'bg-red-400',
  loading:  'bg-amber-400',
  disabled: 'bg-slate-600',
}

const RING: Record<Status, string> = {
  ok:       'ring-green-400/30',
  error:    'ring-red-400/30',
  loading:  'ring-amber-400/30',
  disabled: 'ring-slate-600/30',
}

interface StatusDotProps {
  status?:   Status
  label?:    string
  size?:     'sm' | 'md'
  pulse?:    boolean
}

export function StatusDot({ status = 'ok', label, size = 'md', pulse = true }: StatusDotProps) {
  const sz = size === 'sm' ? 'w-1.5 h-1.5' : 'w-2 h-2'
  const shouldPulse = pulse && (status === 'ok' || status === 'loading')

  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={`relative inline-flex ${sz}`}>
        {shouldPulse && (
          <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${COLOR[status]} opacity-40`} />
        )}
        <span className={`relative inline-flex rounded-full ${sz} ${COLOR[status]} ring-2 ${RING[status]}`} />
      </span>
      {label && <span className="text-xs text-slate-400">{label}</span>}
    </span>
  )
}
