'use client'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Activity, AlertTriangle, Building2, DollarSign, Shield,
  BarChart2, Brain, FileText, RefreshCw, Download, TrendingUp,
  TrendingDown, CheckCircle2, Award, Package,
} from 'lucide-react'
import {
  LineChart, Line, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid, PieChart, Pie, Cell,
} from 'recharts'
import clsx from 'clsx'
import { TopBar } from '@/components/layout/TopBar'
import { api, API_URL } from '@/lib/api'

// ── Types ──────────────────────────────────────────────────────────────────────

type BiTab = 'usage' | 'threats' | 'vendors' | 'costs' | 'compliance' | 'benchmarks' | 'predictions' | 'reports'

const TABS: { key: BiTab; label: string; icon: React.ElementType; color: string }[] = [
  { key: 'usage',       label: 'Usage',       icon: Activity,      color: 'text-blue-400'   },
  { key: 'threats',     label: 'Threats',     icon: AlertTriangle, color: 'text-red-400'    },
  { key: 'vendors',     label: 'Vendors',     icon: Building2,     color: 'text-violet-400' },
  { key: 'costs',       label: 'Costs',       icon: DollarSign,    color: 'text-amber-400'  },
  { key: 'compliance',  label: 'Compliance',  icon: Shield,        color: 'text-green-400'  },
  { key: 'benchmarks',  label: 'Benchmarks',  icon: Award,         color: 'text-cyan-400'   },
  { key: 'predictions', label: 'Predictions', icon: Brain,         color: 'text-purple-400' },
  { key: 'reports',     label: 'Reports',     icon: FileText,      color: 'text-slate-400'  },
]

// ── Mock data ──────────────────────────────────────────────────────────────────

const MOCK_USAGE = {
  total_requests: 4_287, blocked_requests: 312, block_rate_pct: 7.3,
  avg_latency_ms: 18.4,
  daily_breakdown: {
    Mon: { total: 580, blocked: 42 }, Tue: { total: 624, blocked: 55 },
    Wed: { total: 711, blocked: 61 }, Thu: { total: 598, blocked: 38 },
    Fri: { total: 703, blocked: 52 }, Sat: { total: 490, blocked: 34 },
    Sun: { total: 581, blocked: 30 },
  },
}

const MOCK_THREATS = {
  total_flags: 312,
  by_severity: { CRITICAL: 22, HIGH: 78, MEDIUM: 124, LOW: 88 },
  top_threats: [
    { flag: 'jailbreak_attempt', count: 98 }, { flag: 'prompt_injection', count: 74 },
    { flag: 'pii_detected', count: 67 },      { flag: 'secret_leak', count: 43 },
    { flag: 'social_engineering', count: 30 },
  ],
}

const MOCK_VENDOR_STATS = {
  total: 8, expiring_dpas: 2, active_dpas: 6,
  by_risk_tier: { LOW: 3, MEDIUM: 3, HIGH: 2 },
  by_status: { active: 7, inactive: 1 },
}

const MOCK_COSTS = {
  total_usd: 4250.80, period_month: new Date().toISOString().slice(0, 7),
  by_department: { Engineering: 1820, Marketing: 730, Operations: 950, HR: 500, Finance: 250.8 },
  by_vendor: { 'OpenAI': 2100, 'Anthropic': 1200, 'Azure AI': 950.8 },
}

const MOCK_COMPLIANCE = {
  overall_score: 0.84, incidents_open: 2, training_compliance_pct: 87,
  standards: [
    { standard: 'SOC 2',     score: 0.82, attestation: 'PARTIAL' },
    { standard: 'GDPR',      score: 0.91, attestation: 'PASS'    },
    { standard: 'ISO 27001', score: 0.79, attestation: 'PARTIAL' },
    { standard: 'HIPAA',     score: 0.88, attestation: 'PASS'    },
    { standard: 'NIS2',      score: 0.75, attestation: 'PARTIAL' },
  ],
}

const MOCK_BENCHMARKS = {
  metrics: [
    { metric: 'Block Rate',        value: 7.3,  percentile: 68, unit: '%',  delta: '+0.8' },
    { metric: 'P99 Latency',       value: 18.4, percentile: 85, unit: 'ms', delta: '-2.1' },
    { metric: 'Compliance Score',  value: 84,   percentile: 72, unit: '%',  delta: '+3'   },
    { metric: 'Secret Catch Rate', value: 99.2, percentile: 91, unit: '%',  delta: '+0.1' },
  ],
}

const MOCK_PREDICTIONS = [
  { metric: 'block_rate',       current: 7.3,  predicted: 8.1,  trend: 'up',   r2: 0.87 },
  { metric: 'avg_latency_ms',   current: 18.4, predicted: 16.2, trend: 'down', r2: 0.91 },
  { metric: 'compliance_score', current: 84,   predicted: 87,   trend: 'up',   r2: 0.78 },
]

// ── Shared components ──────────────────────────────────────────────────────────

function KpiCard({ label, value, sub, color }: { label: string; value: string; sub?: string; color: string }) {
  return (
    <div className="card p-4">
      <p className="text-[11px] text-slate-400 uppercase tracking-wider">{label}</p>
      <p className={clsx('text-2xl font-bold mt-1', color)}>{value}</p>
      {sub && <p className="text-[11px] text-slate-500 mt-0.5">{sub}</p>}
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
        <h3 className="text-sm font-semibold text-white">{title}</h3>
      </div>
      {children}
    </div>
  )
}

const CHART_TOOLTIP = { contentStyle: { background: '#0d1117', border: '1px solid #1e2a42', borderRadius: 8, fontSize: 11 } }

// ── Tab panels ─────────────────────────────────────────────────────────────────

function UsageTab({ tenant, days }: { tenant: string; days: number }) {
  const { data = MOCK_USAGE, isLoading } = useQuery({
    queryKey: ['bi-usage', tenant, days],
    queryFn: () => api.get(`/business-intelligence/usage?tenant_id=${tenant}&period_days=${days}`).then(r => r.data),
    placeholderData: MOCK_USAGE,
  })
  const chart = Object.entries(data.daily_breakdown ?? {}).map(([day, v]: [string, unknown]) => ({ day, ...(v as object) }))
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard label="Total Requests"  value={data.total_requests.toLocaleString()} color="text-blue-400"  />
        <KpiCard label="Blocked"         value={data.blocked_requests.toLocaleString()} color="text-red-400" />
        <KpiCard label="Block Rate"      value={`${data.block_rate_pct?.toFixed(1)}%`} color="text-orange-400" />
        <KpiCard label="Avg Latency"     value={`${data.avg_latency_ms?.toFixed(1)}ms`} color="text-green-400" />
      </div>
      <SectionCard title="Daily Traffic" icon={Activity} color="text-blue-400">
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={chart}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e2a42" />
            <XAxis dataKey="day" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} />
            <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} />
            <Tooltip {...CHART_TOOLTIP} />
            <Line type="monotone" dataKey="total"   stroke="#6366f1" strokeWidth={2} dot={false} name="Total" />
            <Line type="monotone" dataKey="blocked" stroke="#ef4444" strokeWidth={2} dot={false} name="Blocked" />
          </LineChart>
        </ResponsiveContainer>
        {isLoading && <p className="text-xs text-slate-500 mt-2 text-center">Loading live data…</p>}
      </SectionCard>
    </div>
  )
}

function ThreatsTab({ tenant, days }: { tenant: string; days: number }) {
  const { data = MOCK_THREATS } = useQuery({
    queryKey: ['bi-threats', tenant, days],
    queryFn: () => api.get(`/business-intelligence/threats?tenant_id=${tenant}&period_days=${days}`).then(r => r.data),
    placeholderData: MOCK_THREATS,
  })
  const flagData = (data.top_threats ?? []).map((x: { flag: string; count: number }) => ({
    name: x.flag.replace(/_/g, ' '), count: x.count,
  }))
  const SEV_COLORS: Record<string, string> = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#10b981' }
  const sevPie = Object.entries(data.by_severity ?? {}).map(([sev, v]) => ({ name: sev, value: v as number, fill: SEV_COLORS[sev] ?? '#6b7280' }))
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {Object.entries(data.by_severity ?? {}).map(([sev, count]) => {
          const cls = { CRITICAL: 'text-red-400', HIGH: 'text-orange-400', MEDIUM: 'text-yellow-400', LOW: 'text-green-400' } as Record<string,string>
          return <KpiCard key={sev} label={sev} value={String(count)} color={cls[sev] ?? 'text-white'} />
        })}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <SectionCard title="Top Threat Flags" icon={AlertTriangle} color="text-red-400">
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={flagData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2a42" horizontal={false} />
              <XAxis type="number" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} />
              <YAxis type="category" dataKey="name" tick={{ fill: '#94a3b8', fontSize: 10 }} width={120} axisLine={false} />
              <Tooltip {...CHART_TOOLTIP} />
              <Bar dataKey="count" fill="#ef4444" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </SectionCard>
        <SectionCard title="Severity Distribution" icon={Shield} color="text-orange-400">
          <div className="flex items-center gap-4">
            <ResponsiveContainer width={140} height={140}>
              <PieChart>
                <Pie data={sevPie} cx="50%" cy="50%" innerRadius={40} outerRadius={65} dataKey="value" paddingAngle={2}>
                  {sevPie.map((e, i) => <Cell key={i} fill={e.fill} />)}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            <div className="space-y-2">
              {sevPie.map(e => (
                <div key={e.name} className="flex items-center gap-2 text-xs">
                  <span className="w-2.5 h-2.5 rounded-sm shrink-0" style={{ background: e.fill }} />
                  <span className="text-slate-300 w-16">{e.name}</span>
                  <span className="text-white font-medium">{e.value}</span>
                </div>
              ))}
            </div>
          </div>
        </SectionCard>
      </div>
    </div>
  )
}

function VendorsTab({ tenant }: { tenant: string }) {
  const { data = MOCK_VENDOR_STATS } = useQuery({
    queryKey: ['vendor-stats', tenant],
    queryFn: () => api.get(`/vendor-gov/stats?tenant_id=${tenant}`).then(r => r.data),
    placeholderData: MOCK_VENDOR_STATS,
  })
  const RISK_COLORS: Record<string, string> = { LOW: '#10b981', MEDIUM: '#f59e0b', HIGH: '#ef4444', CRITICAL: '#dc2626' }
  const riskPie = Object.entries(data.by_risk_tier ?? {}).map(([t, v]) => ({ name: t, value: v as number, fill: RISK_COLORS[t] ?? '#6b7280' }))
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard label="Total Vendors" value={String(data.total)}         color="text-violet-400" />
        <KpiCard label="Active DPAs"   value={String(data.active_dpas)}   color="text-green-400"  />
        <KpiCard label="Expiring DPAs" value={String(data.expiring_dpas)} color="text-amber-400" sub="within 30 days" />
        <KpiCard label="Active"        value={String((data.by_status as Record<string,number>)?.active ?? 0)} color="text-blue-400" />
      </div>
      <SectionCard title="Vendor Risk Distribution" icon={Building2} color="text-violet-400">
        <div className="flex items-center gap-6">
          <ResponsiveContainer width={160} height={160}>
            <PieChart>
              <Pie data={riskPie} cx="50%" cy="50%" innerRadius={45} outerRadius={70} dataKey="value" paddingAngle={2}>
                {riskPie.map((e, i) => <Cell key={i} fill={e.fill} />)}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="space-y-3">
            {riskPie.map(e => (
              <div key={e.name} className="flex items-center gap-3">
                <span className="w-3 h-3 rounded-sm shrink-0" style={{ background: e.fill }} />
                <span className="text-sm text-slate-300 w-20">{e.name} risk</span>
                <span className="text-lg font-bold text-white">{e.value}</span>
              </div>
            ))}
          </div>
        </div>
        {data.expiring_dpas > 0 && (
          <div className="mt-4 flex items-center gap-2 p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            {data.expiring_dpas} DPA{data.expiring_dpas !== 1 ? 's' : ''} expiring within 30 days — review in Vendor Governance
          </div>
        )}
      </SectionCard>
    </div>
  )
}

function CostsTab({ tenant }: { tenant: string }) {
  const month = new Date().toISOString().slice(0, 7)
  const { data = MOCK_COSTS } = useQuery({
    queryKey: ['costs-summary', tenant, month],
    queryFn: () => api.get(`/financial/allocation/summary?tenant_id=${tenant}&period_month=${month}`).then(r => r.data),
    placeholderData: MOCK_COSTS,
  })
  const deptData = Object.entries(data.by_department ?? {}).map(([dept, v]) => ({ dept, usd: v as number }))
  const vendorData = Object.entries(data.by_vendor ?? {}).map(([vendor, v]) => ({ vendor, usd: v as number }))
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4">
        <KpiCard label="MTD Total Spend" value={`$${Number(data.total_usd).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`} color="text-amber-400" sub={data.period_month} />
        <KpiCard label="Departments"     value={String(deptData.length)} color="text-blue-400" />
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <SectionCard title="Spend by Department" icon={BarChart2} color="text-amber-400">
          <ResponsiveContainer width="100%" height={190}>
            <BarChart data={deptData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2a42" />
              <XAxis dataKey="dept" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} />
              <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} />
              <Tooltip {...CHART_TOOLTIP} formatter={(v: number) => [`$${v}`, 'Spend']} />
              <Bar dataKey="usd" fill="#f59e0b" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </SectionCard>
        <SectionCard title="Spend by Vendor" icon={Building2} color="text-violet-400">
          <div className="space-y-2 mt-1">
            {vendorData.sort((a, b) => b.usd - a.usd).map(v => (
              <div key={v.vendor} className="flex items-center gap-3">
                <span className="text-xs text-slate-300 w-24 truncate">{v.vendor}</span>
                <div className="flex-1 h-2 rounded-full bg-dark-700">
                  <div className="h-2 rounded-full bg-violet-500 transition-all"
                       style={{ width: `${(v.usd / Number(data.total_usd)) * 100}%` }} />
                </div>
                <span className="text-xs text-white font-medium w-16 text-right">${v.usd.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </SectionCard>
      </div>
    </div>
  )
}

function ComplianceTab({ tenant }: { tenant: string }) {
  const { data = MOCK_COMPLIANCE } = useQuery({
    queryKey: ['bi-compliance', tenant],
    queryFn: () => api.get(`/business-intelligence/compliance?tenant_id=${tenant}`).then(r => r.data),
    placeholderData: MOCK_COMPLIANCE,
  })
  const pct = Math.round(data.overall_score * 100)
  const color = pct >= 85 ? '#10b981' : pct >= 70 ? '#f59e0b' : '#ef4444'
  const r = 40, circ = 2 * Math.PI * r
  const attestColor = (a: string) =>
    a === 'PASS' ? 'text-green-400' : a === 'PARTIAL' ? 'text-yellow-400' : 'text-red-400'
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
        <KpiCard label="Overall Score"    value={`${pct}%`}                              color={pct >= 85 ? 'text-green-400' : pct >= 70 ? 'text-yellow-400' : 'text-red-400'} />
        <KpiCard label="Open Incidents"   value={String(data.incidents_open)}             color="text-red-400" />
        <KpiCard label="Training Compliance" value={`${data.training_compliance_pct}%`}  color="text-blue-400" />
      </div>
      <SectionCard title="Standards Posture" icon={Shield} color="text-green-400">
        <div className="flex items-center gap-8">
          <svg width="100" height="100" viewBox="0 0 100 100">
            <circle cx="50" cy="50" r={r} fill="none" stroke="#1e2a42" strokeWidth="10" />
            <circle cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="10"
              strokeDasharray={`${circ * data.overall_score} ${circ * (1 - data.overall_score)}`}
              strokeLinecap="round" transform="rotate(-90 50 50)" />
            <text x="50" y="56" textAnchor="middle" fill="white" fontSize="18" fontWeight="bold">{pct}%</text>
          </svg>
          <div className="flex-1 space-y-2.5">
            {(data.standards ?? []).map((s: { standard: string; score: number; attestation: string }) => (
              <div key={s.standard} className="flex items-center gap-3">
                <span className="text-xs text-slate-300 w-20">{s.standard}</span>
                <div className="flex-1 h-1.5 rounded-full bg-dark-700">
                  <div className="h-1.5 rounded-full bg-indigo-500 transition-all"
                       style={{ width: `${Math.round(s.score * 100)}%` }} />
                </div>
                <span className="text-xs w-10 text-right text-slate-400">{Math.round(s.score * 100)}%</span>
                <span className={clsx('text-[11px] font-semibold w-16 text-right', attestColor(s.attestation))}>
                  {s.attestation}
                </span>
              </div>
            ))}
          </div>
        </div>
      </SectionCard>
    </div>
  )
}

function BenchmarksTab({ tenant }: { tenant: string }) {
  const { data = MOCK_BENCHMARKS } = useQuery({
    queryKey: ['bi-benchmarks', tenant],
    queryFn: () => api.get(`/business-intelligence/benchmarks?tenant_id=${tenant}`).then(r => r.data),
    placeholderData: MOCK_BENCHMARKS,
  })
  const metrics = data.metrics ?? []
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {metrics.map((m: { metric: string; value: number; percentile: number; unit: string; delta: string }) => {
          const pct = m.percentile
          const isGood = m.metric.includes('Latency') ? pct >= 70 : pct >= 60
          return (
            <div key={m.metric} className="card p-5">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <p className="text-xs text-slate-400 uppercase tracking-wider">{m.metric}</p>
                  <p className="text-2xl font-bold text-white mt-1">{m.value}{m.unit}</p>
                </div>
                <div className={clsx('text-right', isGood ? 'text-green-400' : 'text-amber-400')}>
                  <p className="text-3xl font-bold">{pct}th</p>
                  <p className="text-[11px]">percentile</p>
                </div>
              </div>
              <div className="h-2 rounded-full bg-dark-700">
                <div className={clsx('h-2 rounded-full transition-all', isGood ? 'bg-green-500' : 'bg-amber-500')}
                     style={{ width: `${pct}%` }} />
              </div>
              <div className="flex justify-between mt-1.5 text-[11px] text-slate-500">
                <span>vs community peers</span>
                <span className={clsx(m.delta.startsWith('+') ? 'text-green-400' : 'text-red-400')}>
                  {m.delta} vs last month
                </span>
              </div>
            </div>
          )
        })}
      </div>
      <div className="card p-4 text-xs text-slate-500 flex items-start gap-2">
        <Award className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        Benchmarks computed against anonymised community cohort (p50/p75/p90 percentiles). Data refreshed every 6 hours.
      </div>
    </div>
  )
}

function PredictionsTab({ tenant }: { tenant: string }) {
  const { data } = useQuery({
    queryKey: ['bi-predictions', tenant],
    queryFn: () => api.get(`/business-intelligence/predictions?tenant_id=${tenant}`).then(r => r.data),
  })
  const rows = data ? [data] : MOCK_PREDICTIONS
  return (
    <div className="space-y-4">
      {rows.map((p: { metric: string; current: number; current_value?: number; predicted: number; predicted_value?: number; trend: string; trend_direction?: string; r2: number; r_squared?: number }) => {
        const cur  = p.current  ?? p.current_value  ?? 0
        const pred = p.predicted ?? p.predicted_value ?? 0
        const trend = p.trend ?? p.trend_direction ?? 'stable'
        const r2 = p.r2 ?? p.r_squared ?? 0
        const up = trend === 'up'
        const metricLabel = p.metric.replace(/_/g, ' ')
        return (
          <div key={p.metric} className="card p-5">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-xs text-slate-400 uppercase tracking-wider">{metricLabel}</p>
                <p className="text-3xl font-bold text-white mt-1">{cur.toFixed(1)}</p>
                <p className="text-xs text-slate-500 mt-0.5">current value</p>
              </div>
              <div className="text-right">
                <p className="text-xs text-slate-400 uppercase tracking-wider">7-day forecast</p>
                <p className={clsx('text-3xl font-bold mt-1', up ? 'text-red-400' : 'text-green-400')}>
                  {pred.toFixed(1)}
                </p>
                <div className={clsx('flex items-center gap-1 justify-end mt-0.5 text-xs', up ? 'text-red-400' : 'text-green-400')}>
                  {up ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
                  {up ? 'Increasing' : 'Decreasing'}
                </div>
              </div>
            </div>
            <div className="mt-4 h-1.5 rounded-full bg-dark-700">
              <div className={clsx('h-1.5 rounded-full transition-all', up ? 'bg-red-500' : 'bg-green-500')}
                   style={{ width: `${Math.min(100, Math.abs(pred - cur) / (cur || 1) * 100 * 10 + 50)}%` }} />
            </div>
            <p className="text-[11px] text-slate-500 mt-2">OLS linear regression · R²={r2.toFixed(2)}</p>
          </div>
        )
      })}
    </div>
  )
}

function ReportsTab({ tenant }: { tenant: string }) {
  const [downloading, setDownloading] = useState<string | null>(null)

  async function download(label: string, path: string) {
    setDownloading(label)
    try {
      const res = await fetch(`${API_URL}${path}?tenant_id=${tenant}`, {
        headers: { 'Accept': 'application/json' },
      })
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url; a.download = `${label.toLowerCase().replace(/\s+/g, '_')}.json`
      a.click(); URL.revokeObjectURL(url)
    } catch {
      alert('Report endpoint not yet available.')
    } finally {
      setDownloading(null)
    }
  }

  const REPORTS = [
    { label: 'Usage Metrics',       path: '/business-intelligence/usage',       icon: Activity,      color: 'text-blue-400',   bg: 'bg-blue-500/10'   },
    { label: 'Threat Report',       path: '/business-intelligence/threats',     icon: AlertTriangle, color: 'text-red-400',    bg: 'bg-red-500/10'    },
    { label: 'Vendor Register',     path: '/vendor-gov/stats',                  icon: Building2,     color: 'text-violet-400', bg: 'bg-violet-500/10' },
    { label: 'Cost Allocation',     path: '/financial/allocation/summary',      icon: DollarSign,    color: 'text-amber-400',  bg: 'bg-amber-500/10'  },
    { label: 'Compliance Bundle',   path: '/compliance/posture',                icon: Shield,        color: 'text-green-400',  bg: 'bg-green-500/10'  },
    { label: 'Predictive Analytics',path: '/business-intelligence/predictions', icon: Brain,         color: 'text-purple-400', bg: 'bg-purple-500/10' },
    { label: 'Incident Register',   path: '/incidents/stats',                   icon: AlertTriangle, color: 'text-orange-400', bg: 'bg-orange-500/10' },
    { label: 'Full BI Report',      path: '/business-intelligence/usage',       icon: FileText,      color: 'text-cyan-400',   bg: 'bg-cyan-500/10'   },
  ]

  return (
    <div className="space-y-4">
      <p className="text-sm text-slate-400">Download reports for the selected tenant as JSON. PDF export requires Enterprise tier.</p>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {REPORTS.map(r => {
          const Icon = r.icon
          return (
            <div key={r.label} className="card p-4 flex items-center gap-4">
              <div className={clsx('w-10 h-10 rounded-xl flex items-center justify-center shrink-0', r.bg)}>
                <Icon className={clsx('w-4 h-4', r.color)} />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-white">{r.label}</p>
                <p className="text-xs text-slate-500 truncate">{r.path}</p>
              </div>
              <button
                onClick={() => download(r.label, r.path)}
                disabled={downloading === r.label}
                className="btn-secondary text-xs px-3 py-1.5 shrink-0 flex items-center gap-1.5"
              >
                {downloading === r.label
                  ? <RefreshCw className="w-3 h-3 animate-spin" />
                  : <Download className="w-3 h-3" />}
                JSON
              </button>
            </div>
          )
        })}
      </div>
      <div className="card p-4 text-xs text-slate-500 flex items-start gap-2">
        <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0 mt-0.5" />
        Reports are generated on demand from live data. No sensitive content is stored — only metadata and aggregates.
      </div>
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export default function CommunityIntelligencePage() {
  const [activeTab, setActiveTab] = useState<BiTab>('usage')
  const [tenant, setTenant] = useState('default')
  const [days, setDays] = useState(7)

  const activeTabMeta = TABS.find(t => t.key === activeTab)!

  return (
    <div className="flex flex-col h-screen">
      <TopBar title="Business Intelligence" />

      <div className="flex-1 overflow-y-auto">
        {/* Controls bar */}
        <div className="px-6 pt-5 pb-3 flex items-center gap-3 flex-wrap border-b border-white/[0.06]">
          <label className="text-xs text-slate-400">Tenant</label>
          <input
            className="input w-40 text-sm"
            value={tenant}
            onChange={e => setTenant(e.target.value)}
            placeholder="Tenant ID"
          />
          <div className="flex gap-1 bg-dark-800 rounded-lg p-0.5 border border-white/[0.06] ml-3">
            {[7, 14, 30].map(d => (
              <button key={d} onClick={() => setDays(d)}
                className={clsx('px-3 py-1.5 rounded-md text-xs font-medium transition-colors',
                  days === d ? 'bg-brand-400/20 text-brand-400' : 'text-slate-400 hover:text-slate-200')}>
                {d}d
              </button>
            ))}
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-0.5 px-6 pt-3 overflow-x-auto">
          {TABS.map(tab => {
            const Icon = tab.icon
            const isActive = activeTab === tab.key
            return (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={clsx(
                  'flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-t-lg transition-all whitespace-nowrap border-b-2',
                  isActive
                    ? `${tab.color} border-current bg-white/[0.04]`
                    : 'text-slate-400 hover:text-slate-200 border-transparent',
                )}
              >
                <Icon className="w-3.5 h-3.5" />
                {tab.label}
              </button>
            )
          })}
        </div>
        <div className="h-px bg-white/[0.06] mx-6" />

        {/* Tab content */}
        <div className="p-6">
          <div className="flex items-center gap-2 mb-5">
            {(() => { const Icon = activeTabMeta.icon; return <Icon className={clsx('w-4 h-4', activeTabMeta.color)} /> })()}
            <h2 className="text-base font-semibold text-white">{activeTabMeta.label}</h2>
          </div>

          {activeTab === 'usage'       && <UsageTab       tenant={tenant} days={days} />}
          {activeTab === 'threats'     && <ThreatsTab     tenant={tenant} days={days} />}
          {activeTab === 'vendors'     && <VendorsTab     tenant={tenant} />}
          {activeTab === 'costs'       && <CostsTab       tenant={tenant} />}
          {activeTab === 'compliance'  && <ComplianceTab  tenant={tenant} />}
          {activeTab === 'benchmarks'  && <BenchmarksTab  tenant={tenant} />}
          {activeTab === 'predictions' && <PredictionsTab tenant={tenant} />}
          {activeTab === 'reports'     && <ReportsTab     tenant={tenant} />}
        </div>
      </div>
    </div>
  )
}
