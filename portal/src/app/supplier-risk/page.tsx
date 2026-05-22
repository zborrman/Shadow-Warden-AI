'use client'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ShieldAlert, Plus, TrendingDown, AlertTriangle, CheckCircle2, XCircle } from 'lucide-react'
import clsx from 'clsx'
import { TopBar } from '@/components/layout/TopBar'
import { supplierApi, type SupplierAssessment } from '@/lib/smbApi'

const RISK_COLOR: Record<string, string> = {
  LOW:      'bg-green-500/15 text-green-400',
  MEDIUM:   'bg-yellow-500/15 text-yellow-400',
  HIGH:     'bg-orange-500/15 text-orange-400',
  CRITICAL: 'bg-red-500/15 text-red-400',
}

const RISK_ICON: Record<string, React.ElementType> = {
  LOW:      CheckCircle2,
  MEDIUM:   AlertTriangle,
  HIGH:     AlertTriangle,
  CRITICAL: XCircle,
}

function scoreBar(score: number) {
  const color = score < 0.3 ? 'bg-green-500' : score < 0.6 ? 'bg-yellow-500' : score < 0.8 ? 'bg-orange-500' : 'bg-red-500'
  return (
    <div className="h-1.5 w-full rounded-full bg-dark-700">
      <div className={clsx('h-1.5 rounded-full transition-all', color)} style={{ width: `${Math.round(score * 100)}%` }} />
    </div>
  )
}

export default function SupplierRiskPage() {
  const qc = useQueryClient()
  const [community, setCommunity] = useState('default')
  const [showAssess, setShowAssess] = useState(false)
  const [form, setForm] = useState({ vendor_id: '', data_access: '0.5', ai_capability: '0.5', compliance_posture: '0.5' })

  const { data, isLoading } = useQuery({
    queryKey: ['supplier-report', community],
    queryFn:  () => supplierApi.report(community),
  })

  const assess = useMutation({
    mutationFn: () => supplierApi.assess({
      community_id: community,
      vendor_id:    form.vendor_id,
      context: {
        data_access:        parseFloat(form.data_access),
        ai_capability:      parseFloat(form.ai_capability),
        compliance_posture: parseFloat(form.compliance_posture),
      },
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['supplier-report', community] })
      setShowAssess(false)
      setForm({ vendor_id: '', data_access: '0.5', ai_capability: '0.5', compliance_posture: '0.5' })
    },
  })

  const assessments: SupplierAssessment[] = data?.assessments ?? []
  const byRisk = data?.by_risk_label ?? {}

  const riskOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const
  const total = assessments.length

  return (
    <div className="flex flex-col h-screen">
      <TopBar title="Supplier AI Risk" />
      <div className="flex-1 overflow-y-auto p-6 space-y-5">

        {/* Controls */}
        <div className="flex items-center gap-3 flex-wrap">
          <label className="text-xs text-slate-400">Community</label>
          <input className="input w-40 text-sm" value={community} onChange={e => setCommunity(e.target.value)} />
          <button onClick={() => setShowAssess(v => !v)} className="btn-primary text-sm px-4 py-2 ml-auto">
            <Plus className="w-4 h-4" /> Assess Supplier
          </button>
        </div>

        {/* Risk distribution */}
        {total > 0 && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {riskOrder.map(label => {
              const count = (byRisk[label] as number) ?? 0
              const Icon  = RISK_ICON[label]
              return (
                <div key={label} className="card p-4 flex items-start gap-3">
                  <Icon className={clsx('w-5 h-5 mt-0.5 shrink-0', RISK_COLOR[label].split(' ')[1])} />
                  <div>
                    <p className="text-xs text-slate-400">{label}</p>
                    <p className={clsx('text-2xl font-bold mt-1', RISK_COLOR[label].split(' ')[1])}>{count}</p>
                    <p className="text-[11px] text-slate-500">{total ? Math.round((count / total) * 100) : 0}%</p>
                  </div>
                </div>
              )
            })}
          </div>
        )}

        {/* Assess form */}
        {showAssess && (
          <div className="card p-5 space-y-3">
            <h3 className="text-sm font-semibold text-white">Assess Supplier Risk</h3>
            <input className="input" placeholder="Vendor ID" value={form.vendor_id}
              onChange={e => setForm(f => ({ ...f, vendor_id: e.target.value }))} />
            <div className="grid grid-cols-3 gap-3">
              {[
                { key: 'data_access',        label: 'Data Access' },
                { key: 'ai_capability',      label: 'AI Capability' },
                { key: 'compliance_posture', label: 'Compliance' },
              ].map(({ key, label }) => (
                <div key={key}>
                  <label className="text-xs text-slate-400 mb-1 block">{label} (0–1)</label>
                  <input className="input" type="number" step="0.1" min="0" max="1"
                    value={(form as Record<string, string>)[key]}
                    onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))} />
                </div>
              ))}
            </div>
            <p className="text-[11px] text-slate-500">
              Composite score also incorporates peering transfer velocity and DPA status automatically.
            </p>
            <div className="flex gap-2 justify-end">
              <button onClick={() => setShowAssess(false)} className="btn-secondary text-sm px-3 py-1.5">Cancel</button>
              <button onClick={() => assess.mutate()} disabled={!form.vendor_id || assess.isPending}
                className="btn-primary text-sm px-4 py-1.5">
                {assess.isPending ? 'Assessing…' : 'Run Assessment'}
              </button>
            </div>
          </div>
        )}

        {/* Assessment list */}
        <div className="card overflow-hidden">
          <div className="px-4 py-3 border-b border-white/[0.06] flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-orange-400" />
            <span className="text-sm font-medium text-white">{total} Assessments</span>
          </div>
          {isLoading ? (
            <p className="text-center py-12 text-slate-500 text-sm">Loading…</p>
          ) : total === 0 ? (
            <div className="text-center py-12">
              <TrendingDown className="w-8 h-8 text-slate-600 mx-auto mb-3" />
              <p className="text-sm text-slate-500">No assessments yet — run one above.</p>
            </div>
          ) : (
            <div className="divide-y divide-white/[0.04]">
              {assessments.map((a: SupplierAssessment) => (
                <div key={a.assessment_id} className="px-4 py-3 hover:bg-white/[0.02]">
                  <div className="flex items-center gap-3 mb-2">
                    <span className={clsx('text-[11px] font-medium px-2 py-0.5 rounded-full shrink-0', RISK_COLOR[a.risk_label] ?? 'bg-slate-500/15 text-slate-400')}>
                      {a.risk_label}
                    </span>
                    <p className="text-sm text-white font-mono truncate flex-1">{a.vendor_id}</p>
                    <span className="text-xs text-slate-400 font-mono shrink-0">
                      {Math.round(a.composite_score * 100)}
                    </span>
                  </div>
                  {scoreBar(a.composite_score)}
                  <p className="text-[11px] text-slate-600 mt-1.5">
                    {new Date(a.assessed_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>

        <p className="text-[11px] text-slate-600">
          Risk scores are computed from peering transfer history, DPA status, and 5 weighted criteria — no external API calls.
        </p>
      </div>
    </div>
  )
}
