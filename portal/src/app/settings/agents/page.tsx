'use client'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Bot, CheckCircle2, AlertCircle } from 'lucide-react'
import { settingsApi, type AgentConfig } from '@/lib/settingsApi'
import { TopBar } from '@/components/layout/TopBar'
import { z } from 'zod'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'

function Toast({ msg, ok }: { msg: string; ok: boolean }) {
  return (
    <div className={`fixed bottom-6 right-6 flex items-center gap-2 px-4 py-3 rounded-xl border text-sm font-medium shadow-xl z-50 ${
      ok ? 'bg-green-500/10 border-green-500/20 text-green-400' : 'bg-red-500/10 border-red-500/20 text-red-400'
    }`}>
      {ok ? <CheckCircle2 className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
      {msg}
    </div>
  )
}

const agentSchema = z.object({
  high_risk_threshold:      z.coerce.number().min(0).max(1),
  block_threshold:          z.coerce.number().min(0).max(1),
  sova_max_iterations:      z.coerce.number().int().min(1).max(25),
  sova_enabled:             z.boolean(),
  master_agent_enabled:     z.boolean(),
  evolution_engine_enabled: z.boolean(),
  scan_interval_minutes:    z.coerce.number().int().min(1).max(1440),
  causal_arbiter_enabled:   z.boolean(),
  phish_guard_enabled:      z.boolean(),
}).refine(d => d.block_threshold >= d.high_risk_threshold, {
  message: 'BLOCK threshold must be ≥ HIGH threshold',
  path: ['block_threshold'],
})

type AgentForm = z.infer<typeof agentSchema>

function Toggle({ label, desc, name, register }: {
  label: string; desc: string; name: keyof AgentForm
  register: ReturnType<typeof useForm<AgentForm>>['register']
}) {
  return (
    <label className="flex items-center justify-between p-4 rounded-xl cursor-pointer transition-colors hover:bg-white/[0.02]"
           style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
      <div>
        <p className="text-sm font-medium text-white">{label}</p>
        <p className="text-xs text-slate-400 mt-0.5">{desc}</p>
      </div>
      <input {...register(name as any)} type="checkbox" className="sr-only peer" />
      <div className="w-11 h-6 rounded-full relative peer-checked:bg-brand-400 bg-white/10 transition-colors duration-200">
        <div className="absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform duration-200 peer-checked:translate-x-5" />
      </div>
    </label>
  )
}

export default function AgentsPage() {
  const qc = useQueryClient()
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null)

  const { data: config } = useQuery({
    queryKey: ['settings', 'agents'],
    queryFn: settingsApi.getAgentConfig,
  })

  const { register, handleSubmit, watch, formState: { errors, isDirty } } = useForm<AgentForm>({
    resolver: zodResolver(agentSchema),
    values: config as AgentForm,
  })

  const high = watch('high_risk_threshold')
  const block = watch('block_threshold')

  const updateMut = useMutation({
    mutationFn: (d: AgentForm) => settingsApi.updateAgentConfig(d as AgentConfig),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['settings', 'agents'] }); showToast('Agent config saved', true) },
    onError: () => showToast('Failed to save config', false),
  })

  function showToast(msg: string, ok: boolean) {
    setToast({ msg, ok })
    setTimeout(() => setToast(null), 3000)
  }

  return (
    <>
      <TopBar title="Agent Config" />
      <form onSubmit={handleSubmit(d => updateMut.mutateAsync(d))} className="flex-1 p-6 max-w-2xl space-y-5">

        {/* Risk thresholds */}
        <div className="card p-6">
          <div className="flex items-start gap-4 mb-5">
            <div className="w-9 h-9 rounded-xl bg-brand-400/10 flex items-center justify-center shrink-0">
              <Bot className="w-4.5 h-4.5 text-brand-400" />
            </div>
            <div>
              <h2 className="font-semibold text-white">Risk Thresholds</h2>
              <p className="text-sm text-slate-400 mt-0.5">Tune the pipeline's HIGH/BLOCK decision boundaries. Changes hot-reload in &lt;100ms.</p>
            </div>
          </div>

          <div className="space-y-4 max-w-sm">
            <div>
              <label className="label flex justify-between">
                <span>HIGH risk threshold</span>
                <span className="font-mono text-amber-400">{(typeof high === 'number' ? high : 0.72).toFixed(2)}</span>
              </label>
              <input {...register('high_risk_threshold')} type="range" min="0.5" max="0.95" step="0.01" className="w-full" />
            </div>
            <div>
              <label className="label flex justify-between">
                <span>BLOCK threshold</span>
                <span className="font-mono text-red-400">{(typeof block === 'number' ? block : 0.90).toFixed(2)}</span>
              </label>
              <input {...register('block_threshold')} type="range" min="0.5" max="1.0" step="0.01" className="w-full" />
              {errors.block_threshold && <p className="text-red-400 text-xs mt-1">{errors.block_threshold.message}</p>}
            </div>
            <div>
              <label className="label">SOVA max iterations</label>
              <input {...register('sova_max_iterations')} type="number" min={1} max={25} className="input w-28" />
            </div>
            <div>
              <label className="label">Scan interval (minutes)</label>
              <input {...register('scan_interval_minutes')} type="number" min={1} max={1440} className="input w-28" />
            </div>
          </div>
        </div>

        {/* Module toggles */}
        <div className="card p-6">
          <h2 className="font-semibold text-white mb-4">Agent Modules</h2>
          <div className="space-y-2">
            {[
              { name: 'sova_enabled',             label: 'SOVA Agent',          desc: 'Autonomous operator — 30 tools, cron jobs, Redis memory' },
              { name: 'master_agent_enabled',     label: 'MasterAgent',         desc: 'Multi-agent SOC coordinator (Pro+)' },
              { name: 'evolution_engine_enabled', label: 'Evolution Engine',    desc: 'Auto-generates detection rules from blocked attacks via Claude Opus' },
              { name: 'causal_arbiter_enabled',   label: 'Causal Arbiter',      desc: 'Bayesian DAG for gray-zone decisions (Pearl do-calculus)' },
              { name: 'phish_guard_enabled',      label: 'PhishGuard',          desc: 'URL phishing + social engineering detection' },
            ].map(item => (
              <Toggle key={item.name} {...item as any} register={register} />
            ))}
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button type="submit" disabled={!isDirty || updateMut.isPending} className="btn-primary">
            {updateMut.isPending ? <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : 'Save Changes'}
          </button>
          {!isDirty && <p className="text-xs text-slate-500">No unsaved changes</p>}
        </div>

        {toast && <Toast {...toast} />}
      </form>
    </>
  )
}
