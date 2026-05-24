'use client'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  LineChart, Line, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid,
} from 'recharts'
import { TrendingUp, Shield, CheckCircle2, AlertTriangle, Activity, Brain, RefreshCw } from 'lucide-react'
import clsx from 'clsx'
import { TopBar } from '@/components/layout/TopBar'
import { api } from '@/lib/api'

// ── types ──────────────────────────────────────────────────────────────────────

type BIUsage = {
  tenant_id: string; period_days: number
  total_requests: number; blocked_requests: number
  block_rate_pct: number; avg_latency_ms: number
  daily_breakdown: Record<string, { total: number; blocked: number }>
}

type BIThreats = {
  tenant_id: string; period_days: number; total_flags: number
  by_severity: Record<string, number>
  top_threats: { flag: string; count: number }[]
}

type BICompliance = {
  tenant_id: string; overall_score: number
  standards: { standard: string; score: number; attestation: string }[]
  incidents_open: number; training_compliance_pct: number
}

type BIPredictive = {
  tenant_id: string; metric: string
  current_value: number; predicted_value: number
  trend_direction: 'up' | 'down' | 'stable'; r_squared: number
}

// ── mock fallbacks ─────────────────────────────────────────────────────────────

const MOCK_USAGE: BIUsage = {
  tenant_id: 'default', period_days: 7, total_requests: 4_287,
  blocked_requests: 312, block_rate_pct: 7.3, avg_latency_ms: 18.4,
  daily_breakdown: {
    Mon: { total: 580, blocked: 42 }, Tue: { total: 624, blocked: 55 },
    Wed: { total: 711, blocked: 61 }, Thu: { total: 598, blocked: 38 },
    Fri: { total: 703, blocked: 52 }, Sat: { total: 490, blocked: 34 },
    Sun: { total: 581, blocked: 30 },
  },
}

const MOCK_THREATS: BIThreats = {
  tenant_id: 'default', period_days: 7, total_flags: 312,
  by_severity: { LOW: 88, MEDIUM: 124, HIGH: 78, CRITICAL: 22 },
  top_threats: [
    { flag: 'jailbreak_attempt', count: 98 },
    { flag: 'prompt_injection',  count: 74 },
    { flag: 'pii_detected',      count: 67 },
    { flag: 'secret_leak',       count: 43 },
    { flag: 'social_engineering',count: 30 },
  ],
}

const MOCK_COMPLIANCE: BICompliance = {
  tenant_id: 'default', overall_score: 0.84,
  standards: [
    { standard: 'GDPR',     score: 0.91, attestation: 'PASS'    },
    { standard: 'SOC 2',    score: 0.82, attestation: 'PARTIAL' },
    { standard: 'ISO 27001',score: 0.79, attestation: 'PARTIAL' },
  ],
  incidents_open: 2, training_compliance_pct: 87,
}

const MOCK_PREDICTIVE: BIPredictive = {
  tenant_id: 'default', metric: 'block_rate',
  current_value: 7.3, predicted_value: 8.1,
  trend_direction: 'up', r_squared: 0.87,
}

// ── sub-components ─────────────────────────────────────────────────────────────

function KpiCard({ label, value, icon: Icon, color }: { label: string; value: string; icon: React.ElementType; color: string }) {
  return (
    <div className="card p-4 flex items-start gap-3">
      <div className={clsx('w-9 h-9 rounded-lg flex items-center justify-center shrink-0', color)}>
        <Icon className="w-4 h-4" />
      </div>
      <div>
        <p className="text-[11px] text-slate-400 uppercase tracking-wider">{label}</p>
        <p className="text-xl font-bold text-white mt-0.5">{value}</p>
      </div>
    </div>
  )
}

function ScoreGauge({ score }: { score: number }) {
  const pct   = Math.round(score * 100)
  const color = pct >= 85 ? '#10b981' : pct >= 70 ? '#f59e0b' : '#ef4444'
  const r     = 32
  const circ  = 2 * Math.PI * r
  return (
    <div className="flex flex-col items-center">
      <svg width="80" height="80" viewBox="0 0 80 80">
        <circle cx="40" cy="40" r={r} fill="none" stroke="#1e2a42" strokeWidth="8" />
        <circle cx="40" cy="40" r={r} fill="none" stroke={color} strokeWidth="8"
          strokeDasharray={`${circ * score} ${circ * (1 - score)}`}
          strokeLinecap="round" transform="rotate(-90 40 40)" />
        <text x="40" y="45" textAnchor="middle" fill="white" fontSize="16" fontWeight="bold">{pct}%</text>
      </svg>
    </div>
  )
}

function SectionCard({ title, icon: Icon, color, children }: {
  title: string; icon: React.ElementType; color: string; children: React.ReactNode
}) {
  return (
    <div className="card p-5">
      <div className="flex items-center gap-2 mb-4">
        <Icon className={clsx('w-3.5 h-3.5', color)} />
        <h2 className="text-sm font-semibold text-white">{title}</h2>
      </div>
      {children}
    </div>
  )
}

const attestColor = (a: string) =>
  a === 'PASS' ? 'text-green-400' : a === 'PARTIAL' ? 'text-yellow-400' : 'text-red-400'

// ── page ───────────────────────────────────────────────────────────────────────

export default function IntelligencePage() {
  const [tenant, setTenant] = useState('default')
  const [days, setDays]     = useState(7)

  const { data: usage, isLoading: loadingUsage } = useQuery<BIUsage>({
    queryKey: ['bi-usage', tenant, days],
    queryFn:  () => api.get(`/business-intelligence/usage?tenant_id=${tenant}&period_days=${days}`).then(r => r.data),
    placeholderData: MOCK_USAGE,
  })

  const { data: threats } = useQuery<BIThreats>({
    queryKey: ['bi-threats', tenant, days],
    queryFn:  () => api.get(`/business-intelligence/threats?tenant_id=${tenant}&period_days=${days}`).then(r => r.data),
    placeholderData: MOCK_THREATS,
  })

  const { data: compliance } = useQuery<BICompliance>({
    queryKey: ['bi-compliance', tenant],
    queryFn:  () => api.get(`/business-intelligence/compliance?tenant_id=${tenant}`).then(r => r.data),
    placeholderData: MOCK_COMPLIANCE,
  })

  const { data: predictive } = useQuery<BIPredictive>({
    queryKey: ['bi-predictive', tenant],
    queryFn:  () => api.get(`/business-intelligence/predictions?tenant_id=${tenant}`).then(r => r.data),
    placeholderData: MOCK_PREDICTIVE,
  })

  const u = usage      ?? MOCK_USAGE
  const t = threats    ?? MOCK_THREATS
  const c = compliance ?? MOCK_COMPLIANCE
  const p = predictive ?? MOCK_PREDICTIVE

  const usageData   = Object.entries(u.daily_breakdown ?? {}).map(([day, v]) => ({ day, ...v }))
  const threatData  = (t.top_threats ?? []).map(x => ({ name: x.flag.replace(/_/g, ' '), count: x.count }))

  return (
    <div className="flex flex-col h-screen">
      <TopBar title="Business Intelligence" />
      <div className="flex-1 overflow-y-auto p-6 space-y-6">

        {/* Controls */}
        <div className="flex items-center gap-3 flex-wrap">
          <label className="text-xs text-slate-400">Tenant</label>
          <input className="input w-40 text-sm" value={tenant}
            onChange={e => setTenant(e.target.value)} placeholder="Tenant ID" />
          <div className="flex gap-1 bg-dark-800 rounded-lg p-0.5 border border-white/[0.06] ml-4">
            {[7, 14, 30].map(d => (
              <button key={d} onClick={() => setDays(d)}
                className={clsx('px-3 py-1.5 rounded-md text-xs font-medium transition-colors',
                  days === d ? 'bg-brand-400/20 text-brand-400' : 'text-slate-400 hover:text-slate-200')}>
                {d}d
              </button>
            ))}
          </div>
          {loadingUsage && <RefreshCw className="w-4 h-4 text-slate-500 animate-spin ml-2" />}
        </div>

        {/* KPI row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <KpiCard label="Total Requests"   value={u.total_requests.toLocaleString()} icon={Activity}      color="bg-blue-500/15 text-blue-400" />
          <KpiCard label="Block Rate"       value={`${u.block_rate_pct.toFixed(1)}%`} icon={Shield}        color="bg-red-500/15 text-red-400" />
          <KpiCard label="Avg Latency"      value={`${u.avg_latency_ms.toFixed(1)}ms`} icon={TrendingUp}   color="bg-green-500/15 text-green-400" />
          <KpiCard label="Compliance Score" value={`${Math.round(c.overall_score * 100)}%`} icon={CheckCircle2} color="bg-purple-500/15 text-purple-400" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">

          {/* Usage trends */}
          <SectionCard title="Usage Trends" icon={Activity} color="text-blue-400">
            <ResponsiveContainer width="100%" height={180}>
              <LineChart data={usageData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2a42" />
                <XAxis dataKey="day" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} />
                <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} />
                <Tooltip contentStyle={{ background: '#0d1117', border: '1px solid #1e2a42', borderRadius: 8, fontSize: 11 }} />
                <Line type="monotone" dataKey="total"   stroke="#6366f1" strokeWidth={2} dot={false} name="Total" />
                <Line type="monotone" dataKey="blocked" stroke="#ef4444" strokeWidth={2} dot={false} name="Blocked" />
              </LineChart>
            </ResponsiveContainer>
            <div className="flex items-center gap-4 mt-2 text-[11px] text-slate-500">
              <span className="flex items-center gap-1.5"><span className="w-3 h-0.5 bg-indigo-500 inline-block rounded" />Total</span>
              <span className="flex items-center gap-1.5"><span className="w-3 h-0.5 bg-red-500 inline-block rounded" />Blocked</span>
            </div>
          </SectionCard>

          {/* Top threats */}
          <SectionCard title="Top Threat Flags" icon={AlertTriangle} color="text-red-400">
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={threatData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2a42" horizontal={false} />
                <XAxis type="number" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} />
                <YAxis type="category" dataKey="name" tick={{ fill: '#94a3b8', fontSize: 10 }} width={110} axisLine={false} />
                <Tooltip contentStyle={{ background: '#0d1117', border: '1px solid #1e2a42', borderRadius: 8, fontSize: 11 }} />
                <Bar dataKey="count" fill="#ef4444" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </SectionCard>

          {/* Compliance */}
          <SectionCard title="Compliance Score" icon={CheckCircle2} color="text-green-400">
            <div className="flex items-center gap-6">
              <ScoreGauge score={c.overall_score} />
              <div className="flex-1 space-y-2">
                {(c.standards ?? []).map(s => (
                  <div key={s.standard} className="flex items-center justify-between">
                    <span className="text-xs text-slate-300">{s.standard}</span>
                    <div className="flex items-center gap-3">
                      <div className="w-24 h-1.5 rounded-full bg-dark-700">
                        <div className="h-1.5 rounded-full bg-indigo-500 transition-all"
                             style={{ width: `${Math.round(s.score * 100)}%` }} />
                      </div>
                      <span className={clsx('text-[11px] font-medium w-14 text-right', attestColor(s.attestation))}>
                        {s.attestation}
                      </span>
                    </div>
                  </div>
                ))}
                <div className="pt-2 border-t border-white/[0.05] flex gap-4 text-xs text-slate-500">
                  <span>Open incidents: <strong className="text-white">{c.incidents_open}</strong></span>
                  <span>Training: <strong className="text-white">{c.training_compliance_pct}%</strong></span>
                </div>
              </div>
            </div>
          </SectionCard>

          {/* Predictive */}
          <SectionCard title="Predictive Analytics" icon={Brain} color="text-purple-400">
            <div className="space-y-4">
              <div className="flex items-center justify-between p-3 rounded-xl bg-dark-800">
                <div>
                  <p className="text-xs text-slate-400 uppercase tracking-wider">{p.metric.replace(/_/g, ' ')}</p>
                  <p className="text-2xl font-bold text-white mt-1">{p.current_value.toFixed(1)}%</p>
                  <p className="text-[11px] text-slate-500 mt-0.5">current value</p>
                </div>
                <div className="text-right">
                  <p className="text-xs text-slate-400 uppercase tracking-wider">7-day forecast</p>
                  <p className={clsx('text-2xl font-bold mt-1',
                    p.trend_direction === 'up' ? 'text-red-400' : 'text-green-400')}>
                    {p.predicted_value.toFixed(1)}%
                  </p>
                  <p className={clsx('text-[11px] mt-0.5 flex items-center gap-1 justify-end',
                    p.trend_direction === 'up' ? 'text-red-400' : 'text-green-400')}>
                    <TrendingUp className="w-2.5 h-2.5" />
                    {p.trend_direction === 'up' ? 'Increasing' : 'Decreasing'}
                  </p>
                </div>
              </div>
              <p className="text-xs text-slate-500">
                Model fit: <strong className="text-white">R²={p.r_squared.toFixed(2)}</strong>
                <span className="mx-1 text-slate-700">·</span>
                OLS linear trend over last 30 samples
              </p>
            </div>
          </SectionCard>
        </div>

        {/* Severity breakdown */}
        <div className="card p-5">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-3.5 h-3.5 text-orange-400" />
            <span className="text-sm font-semibold text-white">Threat Severity Distribution</span>
          </div>
          <div className="grid grid-cols-4 gap-3">
            {Object.entries(t.by_severity ?? {}).map(([sev, count]) => {
              const colors: Record<string, string> = {
                CRITICAL: 'border-red-500/30 bg-red-500/10 text-red-400',
                HIGH:     'border-orange-500/30 bg-orange-500/10 text-orange-400',
                MEDIUM:   'border-yellow-500/30 bg-yellow-500/10 text-yellow-400',
                LOW:      'border-green-500/30 bg-green-500/10 text-green-400',
              }
              return (
                <div key={sev} className={clsx('rounded-xl p-4 border text-center', colors[sev] ?? 'border-slate-700 bg-slate-800 text-slate-400')}>
                  <p className="text-2xl font-bold">{count}</p>
                  <p className="text-[11px] font-semibold mt-1 uppercase tracking-wider">{sev}</p>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
