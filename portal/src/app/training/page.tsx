'use client'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { GraduationCap, Plus, CheckCircle2, AlertTriangle, Clock, Users } from 'lucide-react'
import clsx from 'clsx'
import { TopBar } from '@/components/layout/TopBar'
import { trainingApi, type Training } from '@/lib/smbApi'

export default function TrainingPage() {
  const qc = useQueryClient()
  const [community, setCommunity] = useState('default')
  const [showAdd, setShowAdd]     = useState(false)
  const [form, setForm] = useState({ title: '', passing_score: '0.8', valid_days: '365' })

  const { data: programs, isLoading } = useQuery({
    queryKey: ['training-programs', community],
    queryFn:  () => trainingApi.programs(community),
  })

  const { data: report } = useQuery({
    queryKey: ['training-compliance', community],
    queryFn:  () => trainingApi.compliance(community),
  })

  const create = useMutation({
    mutationFn: () => trainingApi.create({
      community_id: community,
      title: form.title,
      passing_score: parseFloat(form.passing_score),
      valid_days: parseInt(form.valid_days, 10),
      required_for: [],
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['training-programs', community] })
      setShowAdd(false)
      setForm({ title: '', passing_score: '0.8', valid_days: '365' })
    },
  })

  const allPrograms: Training[] = programs?.programs ?? []
  const rep = report as Record<string, unknown> | undefined
  const compliancePct = (rep?.compliant_pct as number | undefined) ?? 0

  return (
    <div className="flex flex-col h-screen">
      <TopBar title="Employee AI Training" />
      <div className="flex-1 overflow-y-auto p-6 space-y-5">

        {/* Controls */}
        <div className="flex items-center gap-3 flex-wrap">
          <label className="text-xs text-slate-400">Community</label>
          <input className="input w-40 text-sm" value={community} onChange={e => setCommunity(e.target.value)} />
          <button onClick={() => setShowAdd(v => !v)} className="btn-primary text-sm px-4 py-2 ml-auto">
            <Plus className="w-4 h-4" /> New Program
          </button>
        </div>

        {/* Compliance summary */}
        {rep && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Compliance Rate', value: `${Math.round(compliancePct)}%`, icon: CheckCircle2, color: compliancePct >= 80 ? 'text-green-400' : 'text-yellow-400' },
              { label: 'Employees',       value: rep.total_employees as number ?? 0, icon: Users,       color: 'text-blue-400' },
              { label: 'Expiring Soon',   value: rep.expiring_count  as number ?? 0, icon: Clock,       color: 'text-yellow-400' },
              { label: 'Overdue',         value: rep.overdue_count   as number ?? 0, icon: AlertTriangle, color: 'text-red-400' },
            ].map(s => (
              <div key={s.label} className="card p-4 flex items-start gap-3">
                <s.icon className={clsx('w-5 h-5 mt-0.5 shrink-0', s.color)} />
                <div>
                  <p className="text-xs text-slate-400">{s.label}</p>
                  <p className={clsx('text-2xl font-bold mt-1', s.color)}>{s.value}</p>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Compliance progress bar */}
        {rep && (
          <div className="card p-4">
            <div className="flex justify-between text-sm mb-2">
              <span className="text-white font-medium">Overall Compliance</span>
              <span className={clsx('font-bold', compliancePct >= 80 ? 'text-green-400' : 'text-yellow-400')}>
                {Math.round(compliancePct)}%
              </span>
            </div>
            <div className="h-2.5 rounded-full bg-dark-700">
              <div
                className={clsx('h-2.5 rounded-full transition-all', compliancePct >= 80 ? 'bg-green-500' : 'bg-yellow-500')}
                style={{ width: `${Math.min(compliancePct, 100)}%` }}
              />
            </div>
          </div>
        )}

        {/* Add form */}
        {showAdd && (
          <div className="card p-5 space-y-3">
            <h3 className="text-sm font-semibold text-white">Create Training Program</h3>
            <input className="input" placeholder="Program title (e.g. AI Safety Basics)" value={form.title}
              onChange={e => setForm(f => ({ ...f, title: e.target.value }))} />
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-slate-400 mb-1 block">Passing score (0.0–1.0)</label>
                <input className="input" type="number" step="0.05" min="0" max="1" value={form.passing_score}
                  onChange={e => setForm(f => ({ ...f, passing_score: e.target.value }))} />
              </div>
              <div>
                <label className="text-xs text-slate-400 mb-1 block">Valid for (days)</label>
                <input className="input" type="number" min="30" value={form.valid_days}
                  onChange={e => setForm(f => ({ ...f, valid_days: e.target.value }))} />
              </div>
            </div>
            <div className="flex gap-2 justify-end">
              <button onClick={() => setShowAdd(false)} className="btn-secondary text-sm px-3 py-1.5">Cancel</button>
              <button onClick={() => create.mutate()} disabled={!form.title || create.isPending}
                className="btn-primary text-sm px-4 py-1.5">
                {create.isPending ? 'Creating…' : 'Create Program'}
              </button>
            </div>
          </div>
        )}

        {/* Program list */}
        <div className="card overflow-hidden">
          <div className="px-4 py-3 border-b border-white/[0.06]">
            <span className="text-sm font-medium text-white">{allPrograms.length} Training Programs</span>
          </div>
          {isLoading ? (
            <p className="text-center py-12 text-slate-500 text-sm">Loading…</p>
          ) : allPrograms.length === 0 ? (
            <div className="text-center py-12">
              <GraduationCap className="w-8 h-8 text-slate-600 mx-auto mb-3" />
              <p className="text-sm text-slate-500">No training programs yet.</p>
            </div>
          ) : (
            <div className="divide-y divide-white/[0.04]">
              {allPrograms.map((p: Training) => (
                <div key={p.program_id} className="flex items-center gap-4 px-4 py-3 hover:bg-white/[0.02]">
                  <div className="w-9 h-9 rounded-xl bg-green-500/10 flex items-center justify-center shrink-0">
                    <GraduationCap className="w-4.5 h-4.5 text-green-400" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-white truncate">{p.title}</p>
                    <p className="text-xs text-slate-500">Pass: {Math.round(p.passing_score * 100)}% · Valid {p.valid_days} days</p>
                  </div>
                  <span className="text-[11px] text-slate-500 font-mono">
                    {new Date(p.created_at).toLocaleDateString()}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        <p className="text-[11px] text-slate-600">
          Training completions are HMAC-SHA256 attested and logged to the behavioral anomaly engine.
        </p>
      </div>
    </div>
  )
}
