'use client'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Plus, Shield, CheckCircle2, Clock, XCircle } from 'lucide-react'
import clsx from 'clsx'
import { TopBar } from '@/components/layout/TopBar'
import { incidentApi, type Incident } from '@/lib/smbApi'

const SEV_COLOR: Record<string, string> = {
  CRITICAL: 'bg-red-500/20 text-red-300 border-red-500/30',
  HIGH:     'bg-orange-500/15 text-orange-300 border-orange-500/20',
  MEDIUM:   'bg-yellow-500/15 text-yellow-300 border-yellow-500/20',
  LOW:      'bg-green-500/15 text-green-300 border-green-500/20',
}

const STATUS_ICON: Record<string, React.ElementType> = {
  open: AlertTriangle, investigating: Clock,
  resolved: CheckCircle2, closed: XCircle,
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

export default function IncidentsPage() {
  const qc = useQueryClient()
  const [tenant, setTenant] = useState('default')
  const [showAdd, setShowAdd] = useState(false)
  const [filter, setFilter] = useState<string>('all')
  const [form, setForm] = useState({ title: '', severity: 'MEDIUM', category: 'OTHER', description: '' })

  const { data, isLoading } = useQuery({
    queryKey: ['incidents', tenant],
    queryFn:  () => incidentApi.list(tenant),
  })

  const { data: stats } = useQuery({
    queryKey: ['incident-stats', tenant],
    queryFn:  () => incidentApi.stats(tenant),
  })

  const create = useMutation({
    mutationFn: () => incidentApi.create({ tenant_id: tenant, ...form }),
    onSuccess:  () => {
      qc.invalidateQueries({ queryKey: ['incidents', tenant] })
      qc.invalidateQueries({ queryKey: ['incident-stats', tenant] })
      setShowAdd(false)
      setForm({ title: '', severity: 'MEDIUM', category: 'OTHER', description: '' })
    },
  })

  const allIncidents: Incident[] = data?.incidents ?? []
  const incidents = filter === 'all' ? allIncidents : allIncidents.filter(i => i.status === filter)
  const st = stats as Record<string, unknown> | undefined

  return (
    <div className="flex flex-col h-screen">
      <TopBar title="Incident Register" />
      <div className="flex-1 overflow-y-auto p-6 space-y-5">

        {/* Controls */}
        <div className="flex items-center gap-3 flex-wrap">
          <label className="text-xs text-slate-400">Tenant</label>
          <input className="input w-40 text-sm" value={tenant} onChange={e => setTenant(e.target.value)} />
          <div className="flex gap-1 bg-dark-800 rounded-lg p-0.5 border border-white/[0.06]">
            {['all', 'open', 'investigating', 'resolved', 'closed'].map(s => (
              <button key={s} onClick={() => setFilter(s)}
                className={clsx('px-3 py-1.5 rounded-md text-xs font-medium capitalize transition-colors',
                  filter === s ? 'bg-brand-400/20 text-brand-400' : 'text-slate-400 hover:text-slate-200')}>
                {s}
              </button>
            ))}
          </div>
          <button onClick={() => setShowAdd(v => !v)} className="btn-primary text-sm px-4 py-2 ml-auto">
            <Plus className="w-4 h-4" /> Log Incident
          </button>
        </div>

        {/* Stats row */}
        {st && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: 'Total',    value: (st.total as number) ?? 0,     color: 'text-white' },
              { label: 'Open',     value: (st.open as number) ?? 0,      color: 'text-red-400' },
              { label: 'Critical', value: ((st.by_severity as Record<string, number>)?.CRITICAL ?? 0), color: 'text-red-400' },
              { label: 'High',     value: ((st.by_severity as Record<string, number>)?.HIGH ?? 0),     color: 'text-orange-400' },
            ].map(s => (
              <div key={s.label} className="card p-4">
                <p className="text-xs text-slate-400 uppercase tracking-wide">{s.label}</p>
                <p className={clsx('text-2xl font-bold mt-1', s.color)}>{s.value}</p>
              </div>
            ))}
          </div>
        )}

        {/* Log form */}
        {showAdd && (
          <div className="card p-5 space-y-3">
            <h3 className="text-sm font-semibold text-white">Log AI Incident</h3>
            <input className="input" placeholder="Incident title" value={form.title}
              onChange={e => setForm(f => ({ ...f, title: e.target.value }))} />
            <div className="grid grid-cols-2 gap-3">
              <select className="input" value={form.severity}
                onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}>
                {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
              <select className="input" value={form.category}
                onChange={e => setForm(f => ({ ...f, category: e.target.value }))}>
                {['JAILBREAK', 'PII_LEAK', 'HALLUCINATION', 'ABUSE', 'COMPLIANCE', 'OTHER'].map(c =>
                  <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <textarea className="input min-h-20 resize-none" placeholder="Description (optional)"
              value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
            <div className="flex gap-2 justify-end">
              <button onClick={() => setShowAdd(false)} className="btn-secondary text-sm px-3 py-1.5">Cancel</button>
              <button onClick={() => create.mutate()} disabled={!form.title || create.isPending}
                className="btn-primary text-sm px-4 py-1.5">
                {create.isPending ? 'Logging…' : 'Log Incident'}
              </button>
            </div>
          </div>
        )}

        {/* Incident list */}
        <div className="card overflow-hidden">
          <div className="px-4 py-3 border-b border-white/[0.06]">
            <span className="text-sm font-medium text-white">{incidents.length} incidents</span>
          </div>
          {isLoading ? (
            <p className="text-center py-12 text-slate-500 text-sm">Loading…</p>
          ) : incidents.length === 0 ? (
            <div className="text-center py-12">
              <Shield className="w-8 h-8 text-slate-600 mx-auto mb-3" />
              <p className="text-sm text-slate-500">No incidents recorded.</p>
            </div>
          ) : (
            <div className="divide-y divide-white/[0.04]">
              {incidents.map((inc: Incident) => {
                const StatusIcon = STATUS_ICON[inc.status] ?? AlertTriangle
                return (
                  <div key={inc.incident_id} className="flex items-start gap-4 px-4 py-3 hover:bg-white/[0.02]">
                    <span className={clsx('text-[11px] font-bold px-2 py-0.5 rounded border mt-0.5 shrink-0',
                      SEV_COLOR[inc.severity] ?? 'bg-slate-500/15 text-slate-300 border-slate-500/20')}>
                      {inc.severity}
                    </span>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-white truncate">{inc.title}</p>
                      <p className="text-xs text-slate-500 mt-0.5">{inc.category} · {fmtDate(inc.created_at)}</p>
                    </div>
                    <div className="flex items-center gap-1.5 text-xs capitalize text-slate-400 shrink-0">
                      <StatusIcon className="w-3.5 h-3.5" />
                      {inc.status}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        <p className="text-[11px] text-slate-600">
          All incidents are automatically appended to the STIX 2.1 tamper-evident audit chain.
        </p>
      </div>
    </div>
  )
}
