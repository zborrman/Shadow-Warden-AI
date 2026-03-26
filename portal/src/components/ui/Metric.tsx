/**
 * portal/src/components/ui/Metric.tsx
 * ──────────────────────────────────────
 * Stat / metric card used across the dashboard and settings pages.
 */
interface MetricProps {
  label:     string
  value:     string | number
  sub?:      string
  icon?:     React.ReactNode
  iconBg?:   string   // Tailwind bg class, e.g. "bg-brand-400/10"
  trend?:    { value: number; label?: string }  // positive = good
  loading?:  boolean
}

export function Metric({ label, value, sub, icon, iconBg = 'bg-brand-400/10', trend, loading }: MetricProps) {
  const displayValue = loading ? '—' : typeof value === 'number' ? value.toLocaleString() : value

  return (
    <div className="card p-5 flex items-start justify-between gap-4">
      <div className="min-w-0">
        <p className="text-sm text-slate-400 truncate">{label}</p>
        <p className="text-3xl font-bold text-white mt-1 tabular-nums">{displayValue}</p>
        {sub && !loading && (
          <p className="text-xs text-slate-500 mt-1">{sub}</p>
        )}
        {trend && !loading && (
          <p className={`text-xs mt-1 font-medium ${trend.value >= 0 ? 'text-green-400' : 'text-red-400'}`}>
            {trend.value >= 0 ? '↑' : '↓'} {Math.abs(trend.value).toFixed(1)}%
            {trend.label && <span className="text-slate-500 font-normal ml-1">{trend.label}</span>}
          </p>
        )}
      </div>
      {icon && (
        <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${iconBg}`}>
          {icon}
        </div>
      )}
    </div>
  )
}
