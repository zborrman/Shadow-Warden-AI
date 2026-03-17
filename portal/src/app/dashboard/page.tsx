'use client'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { TopBar } from '@/components/layout/TopBar'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts'
import { Shield, ShieldOff, Activity, AlertTriangle, TrendingUp } from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────
interface Summary {
  total: number; blocked: number; allowed: number
  risk_dist: { low: number; medium: number; high: number; block: number }
}
interface DailyPoint { date: string; total: number; blocked: number; allowed: number }
interface FlagRow    { flag: string; count: number }

// ── Stat card ─────────────────────────────────────────────────────────────────
function StatCard({
  label, value, icon: Icon, color, sub,
}: {
  label: string; value: string | number; icon: React.ElementType
  color: string; sub?: string
}) {
  return (
    <div className="card-glow p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-slate-400">{label}</p>
          <p className="text-3xl font-bold text-white mt-1">{value.toLocaleString()}</p>
          {sub && <p className="text-xs text-slate-500 mt-1">{sub}</p>}
        </div>
        <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${color}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  )
}

// ── Custom tooltip ────────────────────────────────────────────────────────────
function ChartTooltip({ active, payload, label }: {
  active?: boolean; payload?: { name: string; value: number; color: string }[]; label?: string
}) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-dark-800 border border-white/10 rounded-xl p-3 text-xs shadow-xl">
      <p className="text-slate-400 mb-2">{label}</p>
      {payload.map(p => (
        <p key={p.name} style={{ color: p.color }} className="flex gap-2 justify-between">
          <span className="capitalize">{p.name}</span>
          <span className="font-semibold">{p.value}</span>
        </p>
      ))}
    </div>
  )
}

// ── Risk distribution bar ─────────────────────────────────────────────────────
function RiskBar({ dist, total }: { dist: Summary['risk_dist']; total: number }) {
  const levels = [
    { key: 'low',    label: 'Low',    color: 'bg-green-500' },
    { key: 'medium', label: 'Medium', color: 'bg-amber-500' },
    { key: 'high',   label: 'High',   color: 'bg-red-500'   },
    { key: 'block',  label: 'Block',  color: 'bg-red-700'   },
  ] as const

  return (
    <div className="space-y-3">
      {levels.map(({ key, label, color }) => {
        const count = dist[key] || 0
        const pct   = total ? Math.round((count / total) * 100) : 0
        return (
          <div key={key}>
            <div className="flex justify-between text-xs mb-1.5">
              <span className="text-slate-400">{label}</span>
              <span className="text-slate-300 font-medium">{count.toLocaleString()} <span className="text-slate-500">({pct}%)</span></span>
            </div>
            <div className="h-1.5 bg-white/[0.05] rounded-full overflow-hidden">
              <div className={`h-full ${color} rounded-full transition-all duration-700`} style={{ width: `${pct}%` }} />
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function DashboardPage() {
  const { data: summary, isLoading: loadS } = useQuery<Summary>({
    queryKey: ['stats-summary'],
    queryFn:  () => api.get('/stats/summary').then(r => r.data),
  })
  const { data: daily = [], isLoading: loadD } = useQuery<DailyPoint[]>({
    queryKey: ['stats-daily'],
    queryFn:  () => api.get('/stats/daily?days=30').then(r => r.data),
  })
  const { data: flags = [] } = useQuery<FlagRow[]>({
    queryKey: ['stats-flags'],
    queryFn:  () => api.get('/stats/flags').then(r => r.data),
  })

  const blockRate = summary && summary.total > 0
    ? Math.round((summary.blocked / summary.total) * 100)
    : 0

  return (
    <>
      <TopBar title="Dashboard" />
      <div className="flex-1 p-6 space-y-6 min-h-0">

        {/* Stat cards */}
        <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
          <StatCard label="Total Requests"  value={summary?.total   ?? '—'} icon={Activity}     color="bg-brand-400/10 text-brand-400"  sub="last 30 days" />
          <StatCard label="Allowed"         value={summary?.allowed ?? '—'} icon={Shield}        color="bg-green-500/10 text-green-400"  sub={`${100 - blockRate}% pass rate`} />
          <StatCard label="Blocked"         value={summary?.blocked ?? '—'} icon={ShieldOff}     color="bg-red-500/10 text-red-400"      sub={`${blockRate}% block rate`} />
          <StatCard label="Threats Flagged" value={flags.reduce((s, f) => s + f.count, 0)} icon={AlertTriangle} color="bg-amber-500/10 text-amber-400" sub="unique signals" />
        </div>

        {/* Chart + Risk dist */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          {/* Area chart */}
          <div className="xl:col-span-2 card p-5">
            <div className="flex items-center justify-between mb-5">
              <div>
                <h2 className="font-semibold text-white">Request Volume</h2>
                <p className="text-xs text-slate-500 mt-0.5">Last 30 days</p>
              </div>
              <TrendingUp className="w-4 h-4 text-brand-400" />
            </div>
            {loadD ? (
              <div className="h-52 flex items-center justify-center">
                <div className="w-6 h-6 border-2 border-brand-400 border-t-transparent rounded-full animate-spin" />
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={210}>
                <AreaChart data={daily} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="gAllowed" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#38bdf8" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#38bdf8" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gBlocked" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                  <XAxis dataKey="date" tick={{ fill: '#64748b', fontSize: 11 }} tickLine={false} axisLine={false}
                    tickFormatter={d => d.slice(5)} />
                  <YAxis tick={{ fill: '#64748b', fontSize: 11 }} tickLine={false} axisLine={false} />
                  <Tooltip content={<ChartTooltip />} />
                  <Legend wrapperStyle={{ fontSize: 12, color: '#94a3b8' }} />
                  <Area type="monotone" dataKey="allowed" stroke="#38bdf8" strokeWidth={2} fill="url(#gAllowed)" name="allowed" />
                  <Area type="monotone" dataKey="blocked" stroke="#ef4444" strokeWidth={2} fill="url(#gBlocked)" name="blocked" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Risk distribution */}
          <div className="card p-5">
            <h2 className="font-semibold text-white mb-5">Risk Distribution</h2>
            {loadS ? (
              <div className="h-40 flex items-center justify-center">
                <div className="w-6 h-6 border-2 border-brand-400 border-t-transparent rounded-full animate-spin" />
              </div>
            ) : (
              <RiskBar dist={summary?.risk_dist ?? { low: 0, medium: 0, high: 0, block: 0 }} total={summary?.total ?? 0} />
            )}
          </div>
        </div>

        {/* Top flags */}
        {flags.length > 0 && (
          <div className="card p-5">
            <h2 className="font-semibold text-white mb-4">Top Threat Signals</h2>
            <div className="space-y-2">
              {flags.map(f => (
                <div key={f.flag} className="flex items-center justify-between py-2 border-b border-white/[0.04] last:border-0">
                  <span className="text-sm text-slate-300 font-mono">{f.flag}</span>
                  <span className="badge badge-medium">{f.count}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </>
  )
}
