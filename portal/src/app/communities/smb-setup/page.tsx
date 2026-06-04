'use client'
import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import {
  Building2, AlertTriangle, BookMarked, GraduationCap, DollarSign,
  ShieldAlert, Brain, CheckCircle2, ChevronRight, Loader2, Package,
  ArrowLeft, ArrowRight, Sparkles, Info,
} from 'lucide-react'
import clsx from 'clsx'
import { TopBar } from '@/components/layout/TopBar'
import { api } from '@/lib/api'

// ── Module definitions ─────────────────────────────────────────────────────────

const MODULES = [
  {
    key: 'vendor_governance',
    label: 'Vendor Governance',
    icon: Building2,
    color: 'text-violet-400',
    bg: 'bg-violet-500/10',
    border: 'border-violet-500/20',
    desc: 'Track AI vendors, DPA agreements, and risk tiers with automated expiry alerts.',
    controls: ['Vendor register', 'DPA lifecycle', 'Risk scoring'],
  },
  {
    key: 'incident_register',
    label: 'Incident Register',
    icon: AlertTriangle,
    color: 'text-red-400',
    bg: 'bg-red-500/10',
    border: 'border-red-500/20',
    desc: 'Log and track AI incidents with STIX 2.1 tamper-evident audit trail integration.',
    controls: ['Severity triage', 'STIX audit chain', 'Status tracking'],
  },
  {
    key: 'prompt_library',
    label: 'Prompt Library',
    icon: BookMarked,
    color: 'text-blue-400',
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/20',
    desc: 'Share vetted prompts with injection screening before community publishing.',
    controls: ['Injection screening', 'UECIID provenance', 'Usage analytics'],
  },
  {
    key: 'training_records',
    label: 'Training Records',
    icon: GraduationCap,
    color: 'text-green-400',
    bg: 'bg-green-500/10',
    border: 'border-green-500/20',
    desc: 'HMAC-SHA256 attested employee AI training completion with behavioral hooks.',
    controls: ['Cryptographic attestation', 'Compliance reporting', 'Expiry alerts'],
  },
  {
    key: 'cost_allocation',
    label: 'Cost Allocation',
    icon: DollarSign,
    color: 'text-amber-400',
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/20',
    desc: 'Per-department and per-vendor AI spend tracking with monthly summaries and budget caps.',
    controls: ['Dept/vendor breakdown', 'Budget alerts', 'Monthly reports'],
  },
  {
    key: 'supplier_risk',
    label: 'Supplier Risk',
    icon: ShieldAlert,
    color: 'text-orange-400',
    bg: 'bg-orange-500/10',
    border: 'border-orange-500/20',
    desc: 'Composite risk scoring for AI suppliers based on transfer history and DPA coverage.',
    controls: ['5-criteria scoring', 'Peering-based data', 'Risk labels'],
  },
  {
    key: 'business_intelligence',
    label: 'Business Intelligence',
    icon: Brain,
    color: 'text-purple-400',
    bg: 'bg-purple-500/10',
    border: 'border-purple-500/20',
    desc: '8-category analytics with OLS predictions, community benchmarks, and downloadable reports.',
    controls: ['8-tab analytics', 'Predictive OLS', 'Benchmarks'],
  },
]

// ── Step indicators ────────────────────────────────────────────────────────────

const STEPS = ['Configure', 'Select Modules', 'Review', 'Complete']

function StepBar({ current }: { current: number }) {
  return (
    <div className="flex items-center gap-0 mb-8">
      {STEPS.map((label, i) => (
        <div key={label} className="flex items-center flex-1 last:flex-none">
          <div className="flex flex-col items-center gap-1.5">
            <div className={clsx(
              'w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition-all',
              i < current  ? 'bg-brand-400 text-white'
              : i === current ? 'bg-brand-400/20 border-2 border-brand-400 text-brand-400'
              : 'bg-dark-700 border border-white/[0.06] text-slate-500',
            )}>
              {i < current ? <CheckCircle2 className="w-4 h-4" /> : i + 1}
            </div>
            <span className={clsx('text-[11px] font-medium whitespace-nowrap hidden sm:block',
              i === current ? 'text-brand-400' : i < current ? 'text-slate-300' : 'text-slate-600')}>
              {label}
            </span>
          </div>
          {i < STEPS.length - 1 && (
            <div className={clsx('flex-1 h-0.5 mx-2 rounded-full transition-all',
              i < current ? 'bg-brand-400' : 'bg-dark-700')} />
          )}
        </div>
      ))}
    </div>
  )
}

// ── Step 0: Configure ──────────────────────────────────────────────────────────

function StepConfigure({
  tenantId, setTenantId, communityId, setCommunityId, budget, setBudget,
}: {
  tenantId: string; setTenantId: (v: string) => void
  communityId: string; setCommunityId: (v: string) => void
  budget: string; setBudget: (v: string) => void
}) {
  return (
    <div className="space-y-6 max-w-lg">
      <div>
        <h3 className="text-base font-semibold text-white mb-1">Organization details</h3>
        <p className="text-sm text-slate-400">These identifiers scope all 7 modules to your organization.</p>
      </div>

      <div className="space-y-4">
        <div>
          <label className="label">Tenant ID <span className="text-red-400">*</span></label>
          <input
            className="input"
            placeholder="e.g. acme-corp"
            value={tenantId}
            onChange={e => setTenantId(e.target.value)}
            autoFocus
          />
          <p className="text-[11px] text-slate-500 mt-1">Used for billing, incident logs, and compliance reports.</p>
        </div>

        <div>
          <label className="label">Community ID <span className="text-red-400">*</span></label>
          <input
            className="input"
            placeholder="e.g. acme-ai-community"
            value={communityId}
            onChange={e => setCommunityId(e.target.value)}
          />
          <p className="text-[11px] text-slate-500 mt-1">Scopes prompt library, training records, and supplier risk.</p>
        </div>

        <div>
          <label className="label">Monthly AI Budget (USD)</label>
          <div className="relative">
            <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400 text-sm">$</span>
            <input
              className="input pl-7"
              type="number"
              placeholder="500"
              value={budget}
              onChange={e => setBudget(e.target.value)}
            />
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Budget Guardian alerts when spend exceeds threshold.</p>
        </div>
      </div>

      <div className="flex items-start gap-2 p-3 rounded-xl bg-blue-500/10 border border-blue-500/20 text-xs text-blue-300">
        <Info className="w-4 h-4 shrink-0 mt-0.5" />
        All modules share these credentials. You can update them individually after provisioning via the respective pages.
      </div>
    </div>
  )
}

// ── Step 1: Select modules ─────────────────────────────────────────────────────

function StepModules({
  selected, onToggle,
}: {
  selected: Set<string>; onToggle: (key: string) => void
}) {
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-base font-semibold text-white">Select modules to provision</h3>
        <span className="text-xs text-brand-400 font-medium">{selected.size}/{MODULES.length} selected</span>
      </div>
      {MODULES.map(mod => {
        const Icon = mod.icon
        const on = selected.has(mod.key)
        return (
          <button
            key={mod.key}
            onClick={() => onToggle(mod.key)}
            className={clsx(
              'w-full text-left card p-4 flex items-start gap-4 transition-all',
              on ? `${mod.border} border-2` : 'border border-white/[0.06] hover:border-white/10',
            )}
          >
            <div className={clsx('w-10 h-10 rounded-xl flex items-center justify-center shrink-0 mt-0.5', mod.bg)}>
              <Icon className={clsx('w-4.5 h-4.5', mod.color)} />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-sm font-semibold text-white">{mod.label}</span>
                <div className="flex gap-1">
                  {mod.controls.slice(0, 2).map(c => (
                    <span key={c} className="text-[10px] px-1.5 py-0.5 rounded bg-white/[0.06] text-slate-400">{c}</span>
                  ))}
                </div>
              </div>
              <p className="text-xs text-slate-400">{mod.desc}</p>
            </div>
            <div className={clsx(
              'w-5 h-5 rounded-full border-2 shrink-0 mt-1 flex items-center justify-center transition-all',
              on ? 'bg-brand-400 border-brand-400' : 'border-slate-600',
            )}>
              {on && <CheckCircle2 className="w-3 h-3 text-white" />}
            </div>
          </button>
        )
      })}
    </div>
  )
}

// ── Step 2: Review ─────────────────────────────────────────────────────────────

function StepReview({
  tenantId, communityId, budget, selected,
}: {
  tenantId: string; communityId: string; budget: string; selected: Set<string>
}) {
  const mods = MODULES.filter(m => selected.has(m.key))
  return (
    <div className="space-y-5 max-w-lg">
      <h3 className="text-base font-semibold text-white">Review configuration</h3>

      <div className="card p-4 space-y-3">
        <p className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Configuration</p>
        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-slate-400">Tenant ID</span>
            <span className="text-white font-mono">{tenantId}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-400">Community ID</span>
            <span className="text-white font-mono">{communityId}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-400">Monthly Budget</span>
            <span className="text-white">${budget || '—'}/mo</span>
          </div>
        </div>
      </div>

      <div className="card p-4 space-y-3">
        <div className="flex items-center justify-between">
          <p className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Modules</p>
          <span className="badge bg-brand-400/15 text-brand-400">{mods.length} of {MODULES.length}</span>
        </div>
        <div className="space-y-2">
          {mods.map(m => {
            const Icon = m.icon
            return (
              <div key={m.key} className="flex items-center gap-3">
                <Icon className={clsx('w-4 h-4 shrink-0', m.color)} />
                <span className="text-sm text-slate-200">{m.label}</span>
                <CheckCircle2 className="w-3.5 h-3.5 text-green-400 ml-auto" />
              </div>
            )
          })}
        </div>
      </div>

      <div className="flex items-start gap-2 p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 text-xs text-amber-300">
        <Info className="w-4 h-4 shrink-0 mt-0.5" />
        Provisioning is idempotent — safe to run multiple times. Existing data is never overwritten.
      </div>
    </div>
  )
}

// ── Step 3: Complete ───────────────────────────────────────────────────────────

function StepComplete({
  result, error, tenantId,
}: {
  result: Record<string, unknown> | null; error: string | null; tenantId: string
}) {
  if (error) {
    return (
      <div className="space-y-4 max-w-lg">
        <div className="flex items-center gap-3 p-4 rounded-xl bg-red-500/10 border border-red-500/20">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
          <div>
            <p className="text-sm font-semibold text-red-300">Provisioning failed</p>
            <p className="text-xs text-red-400 mt-0.5">{error}</p>
          </div>
        </div>
        <p className="text-xs text-slate-500">Check that the API is reachable and the tenant ID is valid.</p>
      </div>
    )
  }

  const modules = (result?.modules ?? MODULES.map(m => ({ key: m.key, status: 'provisioned' }))) as Array<{ key: string; status: string }>

  return (
    <div className="space-y-5 max-w-lg">
      <div className="flex items-center gap-3 p-4 rounded-xl bg-green-500/10 border border-green-500/20">
        <Sparkles className="w-5 h-5 text-green-400 shrink-0" />
        <div>
          <p className="text-sm font-semibold text-green-300">SMB Suite provisioned successfully</p>
          <p className="text-xs text-slate-400 mt-0.5">All selected modules are active for tenant <code className="font-mono">{tenantId}</code></p>
        </div>
      </div>

      <div className="card p-4 space-y-2">
        <p className="text-xs text-slate-400 uppercase tracking-wider font-semibold mb-3">Module status</p>
        {modules.map((m: { key: string; status: string }) => {
          const mod = MODULES.find(x => x.key === m.key)
          const Icon = mod?.icon ?? Package
          const ok = m.status === 'provisioned' || m.status === 'ok' || m.status === 'healthy'
          return (
            <div key={m.key} className="flex items-center gap-3 py-1">
              <Icon className={clsx('w-4 h-4 shrink-0', mod?.color ?? 'text-slate-400')} />
              <span className="text-sm text-slate-200 flex-1">{mod?.label ?? m.key}</span>
              <span className={clsx(
                'text-[11px] font-semibold px-2 py-0.5 rounded-full',
                ok ? 'bg-green-500/15 text-green-400' : 'bg-amber-500/15 text-amber-400',
              )}>
                {m.status}
              </span>
            </div>
          )
        })}
      </div>

      <div className="card p-4 text-xs text-slate-400 space-y-1">
        <p className="font-semibold text-white text-sm mb-2">Next steps</p>
        <p>→ Visit <strong className="text-white">Business Intelligence</strong> to view analytics</p>
        <p>→ Open <strong className="text-white">Vendor Governance</strong> to add your first vendor</p>
        <p>→ Log your first incident in <strong className="text-white">Incident Register</strong></p>
        <p>→ Review the budget cap in <strong className="text-white">Cost Allocation</strong></p>
      </div>
    </div>
  )
}

// ── Main wizard ────────────────────────────────────────────────────────────────

export default function SmbSetupPage() {
  const [step, setStep] = useState(0)
  const [tenantId, setTenantId]       = useState('')
  const [communityId, setCommunityId] = useState('')
  const [budget, setBudget]           = useState('500')
  const [selected, setSelected]       = useState<Set<string>>(new Set(MODULES.map(m => m.key)))
  const [provisionResult, setProvisionResult] = useState<Record<string, unknown> | null>(null)
  const [provisionError, setProvisionError]   = useState<string | null>(null)

  function toggleModule(key: string) {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const provision = useMutation({
    mutationFn: () => api.post('/smb-suite/provision', {
      tenant_id: tenantId,
      community_id: communityId,
      monthly_budget_usd: budget ? Number(budget) : undefined,
    }).then(r => r.data),
    onSuccess: (data) => {
      setProvisionResult(data as Record<string, unknown>)
      setProvisionError(null)
      setStep(3)
    },
    onError: (err: unknown) => {
      setProvisionError((err as { message?: string })?.message ?? 'Provisioning failed')
      setStep(3)
    },
  })

  function handleNext() {
    if (step === 2) {
      provision.mutate()
    } else {
      setStep(s => s + 1)
    }
  }

  function handleBack() {
    setStep(s => Math.max(0, s - 1))
  }

  const canProceed =
    step === 0 ? !!tenantId && !!communityId :
    step === 1 ? selected.size > 0 :
    step === 2 ? true : false

  return (
    <div className="flex flex-col h-screen">
      <TopBar title="SMB Suite Wizard" />

      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-2xl mx-auto">
          {/* Header */}
          <div className="flex items-center gap-3 mb-6">
            <div className="w-10 h-10 rounded-2xl bg-brand-gradient flex items-center justify-center shrink-0">
              <Package className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">SMB AI Governance Suite</h1>
              <p className="text-xs text-slate-400 mt-0.5">Provision all 7 governance modules in one step</p>
            </div>
          </div>

          <StepBar current={step} />

          {/* Step content */}
          <div className="min-h-64">
            {step === 0 && (
              <StepConfigure
                tenantId={tenantId} setTenantId={setTenantId}
                communityId={communityId} setCommunityId={setCommunityId}
                budget={budget} setBudget={setBudget}
              />
            )}
            {step === 1 && <StepModules selected={selected} onToggle={toggleModule} />}
            {step === 2 && (
              <StepReview tenantId={tenantId} communityId={communityId} budget={budget} selected={selected} />
            )}
            {step === 3 && (
              <StepComplete result={provisionResult} error={provisionError} tenantId={tenantId} />
            )}
          </div>

          {/* Navigation */}
          {step < 3 && (
            <div className="flex items-center justify-between mt-8 pt-5 border-t border-white/[0.06]">
              <button
                onClick={handleBack}
                disabled={step === 0}
                className="btn-secondary flex items-center gap-2 disabled:opacity-40"
              >
                <ArrowLeft className="w-4 h-4" /> Back
              </button>

              <div className="flex items-center gap-2 text-xs text-slate-500">
                {selected.size} module{selected.size !== 1 ? 's' : ''} selected
              </div>

              <button
                onClick={handleNext}
                disabled={!canProceed || provision.isPending}
                className="btn-primary flex items-center gap-2 disabled:opacity-50"
              >
                {provision.isPending ? (
                  <><Loader2 className="w-4 h-4 animate-spin" /> Provisioning…</>
                ) : step === 2 ? (
                  <><Sparkles className="w-4 h-4" /> Provision Suite</>
                ) : (
                  <>Next <ArrowRight className="w-4 h-4" /></>
                )}
              </button>
            </div>
          )}

          {step === 3 && (
            <div className="mt-8 pt-5 border-t border-white/[0.06]">
              {provisionError ? (
                <button
                  onClick={() => { setStep(2); setProvisionError(null) }}
                  className="btn-secondary flex items-center gap-2"
                >
                  <ArrowLeft className="w-4 h-4" /> Go back and retry
                </button>
              ) : (
                <button
                  onClick={() => { setStep(0); setTenantId(''); setCommunityId(''); setProvisionResult(null) }}
                  className="btn-secondary flex items-center gap-2"
                >
                  <Package className="w-4 h-4" /> Provision another tenant
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
