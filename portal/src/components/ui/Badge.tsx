/**
 * portal/src/components/ui/Badge.tsx
 * ────────────────────────────────────
 * Reusable badge / pill component. Supports risk levels, status, and custom variants.
 */
import { riskBg, riskColor } from '@/utils/format'

type Variant = 'risk' | 'green' | 'amber' | 'red' | 'gray' | 'blue' | 'violet'

interface BadgeProps {
  children:  React.ReactNode
  variant?:  Variant
  riskLevel?: string   // 'low' | 'medium' | 'high' | 'block'
  className?: string
  dot?:       boolean  // show a status dot
}

const VARIANT_CLASSES: Record<Variant, string> = {
  risk:   '',   // handled by riskLevel prop
  green:  'text-green-400 bg-green-400/10 border-green-400/20',
  amber:  'text-amber-400 bg-amber-400/10 border-amber-400/20',
  red:    'text-red-400   bg-red-400/10   border-red-400/20',
  gray:   'text-slate-400 bg-white/5      border-white/10',
  blue:   'text-blue-400  bg-blue-400/10  border-blue-400/20',
  violet: 'text-violet-400 bg-violet-400/10 border-violet-400/20',
}

const DOT_COLORS: Record<Variant, string> = {
  risk:   'bg-slate-400',
  green:  'bg-green-400',
  amber:  'bg-amber-400',
  red:    'bg-red-400',
  gray:   'bg-slate-500',
  blue:   'bg-blue-400',
  violet: 'bg-violet-400',
}

export function Badge({ children, variant = 'gray', riskLevel, className = '', dot }: BadgeProps) {
  const cls = riskLevel
    ? `${riskColor(riskLevel)} ${riskBg(riskLevel)}`
    : VARIANT_CLASSES[variant]

  const dotColor = riskLevel
    ? riskColor(riskLevel).replace('text-', 'bg-')
    : DOT_COLORS[variant]

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${cls} ${className}`}>
      {dot && <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dotColor}`} />}
      {children}
    </span>
  )
}
