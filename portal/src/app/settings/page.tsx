'use client'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { TopBar } from '@/components/layout/TopBar'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import {
  User, Bell, Lock, CreditCard, CheckCircle2, AlertCircle, Copy, Check,
  Shield, Database, DollarSign, Package, Trash2,
} from 'lucide-react'

// ── Section wrapper ───────────────────────────────────────────────────────────
function Section({ title, description, icon: Icon, children }: {
  title: string; description: string; icon: React.ElementType; children: React.ReactNode
}) {
  return (
    <div className="card p-6">
      <div className="flex items-start gap-4 mb-5">
        <div className="w-9 h-9 rounded-xl bg-brand-400/10 flex items-center justify-center shrink-0">
          <Icon className="w-4.5 h-4.5 text-brand-400" />
        </div>
        <div>
          <h2 className="font-semibold text-white">{title}</h2>
          <p className="text-sm text-slate-400 mt-0.5">{description}</p>
        </div>
      </div>
      {children}
    </div>
  )
}

// ── Toast ─────────────────────────────────────────────────────────────────────
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

// ── Profile section ───────────────────────────────────────────────────────────
const profileSchema = z.object({ display_name: z.string().max(80) })
type ProfileForm = z.infer<typeof profileSchema>

function ProfileSection() {
  const qc = useQueryClient()
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null)
  const { data: me } = useQuery({ queryKey: ['me'], queryFn: () => api.get('/me').then(r => r.data) })
  const { register, handleSubmit, formState: { isSubmitting } } = useForm<ProfileForm>({
    resolver: zodResolver(profileSchema),
    values: { display_name: me?.display_name || '' },
  })
  const mut = useMutation({
    mutationFn: (d: ProfileForm) => api.patch('/me', d),
    onSuccess:  () => { qc.invalidateQueries({ queryKey: ['me'] }); showToast('Profile updated', true) },
    onError:    () => showToast('Failed to update profile', false),
  })
  function showToast(msg: string, ok: boolean) {
    setToast({ msg, ok })
    setTimeout(() => setToast(null), 3000)
  }

  return (
    <Section title="Profile" description="Your account details" icon={User}>
      <form onSubmit={handleSubmit(d => mut.mutateAsync(d))} className="space-y-4 max-w-sm">
        <div>
          <label className="label">Email</label>
          <input value={me?.email || ''} readOnly className="input opacity-60 cursor-not-allowed" />
        </div>
        <div>
          <label className="label">Display name</label>
          <input {...register('display_name')} className="input" placeholder="Your name" />
        </div>
        <div>
          <label className="label">Tenant ID</label>
          <TenantIdField value={me?.tenant_id || ''} />
        </div>
        <button type="submit" disabled={isSubmitting || mut.isPending} className="btn-primary">
          {(isSubmitting || mut.isPending)
            ? <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            : 'Save Changes'}
        </button>
      </form>
      {toast && <Toast {...toast} />}
    </Section>
  )
}

function TenantIdField({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="relative">
      <input value={value} readOnly className="input opacity-60 cursor-not-allowed pr-10 font-mono text-xs" />
      <button
        type="button"
        onClick={() => { navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
      >
        {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
      </button>
    </div>
  )
}

// ── Notifications section ─────────────────────────────────────────────────────
function NotificationsSection() {
  const qc = useQueryClient()
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null)
  const { data: me } = useQuery({ queryKey: ['me'], queryFn: () => api.get('/me').then(r => r.data) })
  const mut = useMutation({
    mutationFn: (d: { notify_high?: boolean; notify_block?: boolean }) => api.patch('/me', d),
    onSuccess:  () => { qc.invalidateQueries({ queryKey: ['me'] }); showToast('Saved', true) },
    onError:    () => showToast('Failed to save', false),
  })
  function showToast(msg: string, ok: boolean) {
    setToast({ msg, ok })
    setTimeout(() => setToast(null), 2500)
  }

  function Toggle({ label, desc, checked, field }: {
    label: string; desc: string; checked: boolean
    field: 'notify_high' | 'notify_block'
  }) {
    return (
      <label className="flex items-center justify-between p-4 rounded-xl bg-white/[0.03] border border-white/[0.06] cursor-pointer hover:bg-white/[0.05] transition-colors">
        <div>
          <p className="text-sm font-medium text-white">{label}</p>
          <p className="text-xs text-slate-400 mt-0.5">{desc}</p>
        </div>
        <div
          onClick={() => mut.mutate({ [field]: !checked })}
          className={`w-11 h-6 rounded-full transition-colors duration-200 relative cursor-pointer ${checked ? 'bg-brand-400' : 'bg-white/10'}`}
        >
          <div className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform duration-200 ${checked ? 'translate-x-5' : 'translate-x-0'}`} />
        </div>
      </label>
    )
  }

  return (
    <Section title="Notifications" description="Choose when to receive alerts" icon={Bell}>
      <div className="space-y-3 max-w-sm">
        <Toggle label="High-risk alerts"  desc="Notify when HIGH risk signals are detected" checked={me?.notify_high  ?? true} field="notify_high"  />
        <Toggle label="Block-level alerts" desc="Notify when requests are fully blocked"     checked={me?.notify_block ?? true} field="notify_block" />
      </div>
      {toast && <Toast {...toast} />}
    </Section>
  )
}

// ── Password section ──────────────────────────────────────────────────────────
const pwSchema = z.object({
  current_password: z.string().min(1, 'Required'),
  new_password:     z.string().min(8, 'Min 8 characters'),
  confirm:          z.string(),
}).refine(d => d.new_password === d.confirm, { message: "Passwords don't match", path: ['confirm'] })
type PwForm = z.infer<typeof pwSchema>

function PasswordSection() {
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null)
  const { register, handleSubmit, reset, formState: { errors, isSubmitting } } = useForm<PwForm>({
    resolver: zodResolver(pwSchema),
  })
  const mut = useMutation({
    mutationFn: (d: PwForm) => api.post('/me/change-password', {
      current_password: d.current_password, new_password: d.new_password,
    }),
    onSuccess: () => { reset(); showToast('Password changed', true) },
    onError:   (e: unknown) => {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      showToast(msg || 'Failed to change password', false)
    },
  })
  function showToast(msg: string, ok: boolean) {
    setToast({ msg, ok })
    setTimeout(() => setToast(null), 3500)
  }

  return (
    <Section title="Password" description="Change your login password" icon={Lock}>
      <form onSubmit={handleSubmit(d => mut.mutateAsync(d))} className="space-y-4 max-w-sm">
        <div>
          <label className="label">Current password</label>
          <input {...register('current_password')} type="password" className="input" placeholder="••••••••" />
          {errors.current_password && <p className="text-red-400 text-xs mt-1">{errors.current_password.message}</p>}
        </div>
        <div>
          <label className="label">New password</label>
          <input {...register('new_password')} type="password" className="input" placeholder="Min. 8 characters" />
          {errors.new_password && <p className="text-red-400 text-xs mt-1">{errors.new_password.message}</p>}
        </div>
        <div>
          <label className="label">Confirm new password</label>
          <input {...register('confirm')} type="password" className="input" placeholder="Repeat new password" />
          {errors.confirm && <p className="text-red-400 text-xs mt-1">{errors.confirm.message}</p>}
        </div>
        <button type="submit" disabled={isSubmitting || mut.isPending} className="btn-primary">
          {(isSubmitting || mut.isPending)
            ? <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            : 'Change Password'}
        </button>
      </form>
      {toast && <Toast {...toast} />}
    </Section>
  )
}

// ── Billing section ───────────────────────────────────────────────────────────
function BillingSection() {
  const { data: billing } = useQuery({
    queryKey: ['billing'],
    queryFn:  () => api.get('/billing').then(r => r.data),
  })
  const used  = billing?.requests_used  ?? 0
  const quota = billing?.requests_quota ?? 10000
  const pct   = Math.min(100, Math.round((used / quota) * 100))

  return (
    <Section title="Billing" description="Your current plan and usage" icon={CreditCard}>
      <div className="space-y-4 max-w-sm">
        <div className="flex items-center justify-between">
          <span className="text-sm text-slate-400">Plan</span>
          <span className="badge badge-active">{billing?.plan ?? 'Starter'}</span>
        </div>
        <div>
          <div className="flex justify-between text-sm mb-2">
            <span className="text-slate-400">Requests this month</span>
            <span className="text-white font-medium">{used.toLocaleString()} / {quota.toLocaleString()}</span>
          </div>
          <div className="h-2 bg-white/[0.05] rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-700 ${pct > 80 ? 'bg-amber-500' : 'bg-brand-400'}`}
              style={{ width: `${pct}%` }}
            />
          </div>
          <p className="text-xs text-slate-500 mt-1.5">{pct}% of monthly quota used</p>
        </div>
        <div className="pt-2">
          <button className="btn-secondary w-full" disabled>
            Upgrade Plan — Coming Soon
          </button>
        </div>
      </div>
    </Section>
  )
}

// ── Security Engine section ───────────────────────────────────────────────────
function SecuritySection() {
  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn:  () => api.get('/health').then(r => r.data),
    refetchInterval: 30_000,
  })

  const strategies = [
    { key: 'gaslight', label: 'Gaslight', desc: 'Prompt injection — returns convincing fake response', color: 'text-amber-400' },
    { key: 'delay',    label: 'Delay',    desc: 'Bot / credential stuffing — adds async delay cost',  color: 'text-amber-400' },
    { key: 'standard', label: 'Standard', desc: 'All other threats — immediate block response',        color: 'text-slate-400' },
  ]

  const strict = health?.strict ?? false
  const evolution = health?.evolution ?? false
  const failStrategy = health?.fail_strategy ?? '—'

  return (
    <Section title="Security Engine" description="Live status of detection pipeline layers" icon={Shield}>
      <div className="space-y-3 max-w-lg">
        {/* Status chips */}
        <div className="grid grid-cols-3 gap-2 text-center">
          {[
            { label: 'Strict Mode',      active: strict,    on: 'On', off: 'Off' },
            { label: 'Evolution Engine', active: evolution, on: 'Active', off: 'Air-gapped' },
            { label: 'Fail Strategy',    active: failStrategy === 'closed', on: 'Closed', off: failStrategy || 'Open' },
          ].map(({ label, active, on, off }) => (
            <div key={label} className="rounded-xl bg-white/[0.03] border border-white/[0.06] p-3">
              <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">{label}</p>
              <span className={`text-xs font-semibold ${active ? 'text-amber-400' : 'text-green-400'}`}>
                {active ? on : off}
              </span>
            </div>
          ))}
        </div>

        {/* Shadow ban strategies */}
        <div className="rounded-xl bg-white/[0.03] border border-white/[0.06] overflow-hidden">
          <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider px-4 py-2.5 border-b border-white/[0.06]">
            Shadow Ban Strategies
          </p>
          {strategies.map(s => (
            <div key={s.key} className="flex items-center justify-between px-4 py-3 border-b border-white/[0.04] last:border-0">
              <div>
                <p className="text-sm font-medium text-white">{s.label}</p>
                <p className="text-xs text-slate-500 mt-0.5">{s.desc}</p>
              </div>
              <span className={`text-xs font-mono ${s.color}`}>{s.key}</span>
            </div>
          ))}
        </div>

        <p className="text-xs text-slate-500">
          Configure thresholds via environment variables — see <span className="text-brand-400">Settings → Detection</span> in the admin panel.
        </p>
      </div>
    </Section>
  )
}

// ── Storage section ───────────────────────────────────────────────────────────
function StorageSection() {
  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn:  () => api.get('/health').then(r => r.data),
  })

  const s3Enabled = health?.s3_enabled ?? false

  return (
    <Section title="Object Storage" description="MinIO / S3 evidence vault and log shipping status" icon={Database}>
      <div className="space-y-3 max-w-lg">
        <div className="flex items-center justify-between p-4 rounded-xl bg-white/[0.03] border border-white/[0.06]">
          <div>
            <p className="text-sm font-medium text-white">S3 Storage</p>
            <p className="text-xs text-slate-400 mt-0.5">
              {s3Enabled
                ? 'Evidence bundles and analytics logs shipping to object storage'
                : 'Disabled — set S3_ENABLED=true and restart to activate'}
            </p>
          </div>
          <span className={`text-xs font-semibold px-2.5 py-1 rounded-full border ${
            s3Enabled
              ? 'text-green-400 bg-green-400/10 border-green-400/20'
              : 'text-slate-400 bg-white/5 border-white/10'
          }`}>
            {s3Enabled ? 'Active' : 'Disabled'}
          </span>
        </div>

        {[
          { label: 'Evidence Vault',  val: 'warden-evidence/bundles/<session>.json', desc: 'SHA-256 signed per session' },
          { label: 'Analytics Logs',  val: 'warden-logs/logs/<date>/<req>.json',     desc: 'NDJSON, GDPR-compliant metadata only' },
        ].map(({ label, val, desc }) => (
          <div key={label} className="px-4 py-3 rounded-xl bg-white/[0.03] border border-white/[0.06]">
            <p className="text-sm font-medium text-white mb-0.5">{label}</p>
            <p className="font-mono text-xs text-brand-400">{val}</p>
            <p className="text-xs text-slate-500 mt-0.5">{desc}</p>
          </div>
        ))}

        <p className="text-xs text-slate-500">
          Storage errors are fail-open — never block the filter pipeline. Background <span className="font-mono text-slate-400">ThreadPoolExecutor(max_workers=2)</span>.
        </p>
      </div>
    </Section>
  )
}

// ── Financial section ─────────────────────────────────────────────────────────
function FinancialSection() {
  const MULTIPLIERS: Record<string, number> = {
    generic: 1.0, finance: 2.4, healthcare: 3.2, tech: 1.8,
    retail: 1.5, government: 1.9, legal: 2.1,
  }
  const [industry, setIndustry] = useState('generic')
  const [requests, setRequests] = useState(100_000)

  const mul       = MULTIPLIERS[industry] ?? 1.0
  const incident  = Math.round(4_880_000 * mul * 0.012)
  const inference = Math.round(requests * 0.015 * 0.0008 * 12)
  const secops    = Math.round(Math.max(1, Math.round(requests / 50_000)) * 2.5 * 85 * 12)
  const annual    = incident + inference + secops
  const fmt = (v: number) => '$' + v.toLocaleString('en-US', { maximumFractionDigits: 0 })

  return (
    <Section title="Dollar Impact" description="Estimated annual value delivered — IBM 2024 benchmarks" icon={DollarSign}>
      <div className="space-y-4 max-w-lg">
        {/* Controls */}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="label">Industry</label>
            <select
              value={industry}
              onChange={e => setIndustry(e.target.value)}
              className="input"
            >
              <option value="generic">Generic</option>
              <option value="finance">Finance / Banking</option>
              <option value="healthcare">Healthcare</option>
              <option value="tech">Technology</option>
              <option value="retail">Retail</option>
              <option value="government">Government</option>
              <option value="legal">Legal / Professional</option>
            </select>
          </div>
          <div>
            <label className="label">Monthly requests</label>
            <input
              type="number"
              value={requests}
              min={100}
              step={1000}
              onChange={e => setRequests(Number(e.target.value))}
              className="input"
            />
          </div>
        </div>

        {/* Results */}
        <div className="rounded-xl overflow-hidden border border-white/[0.06]">
          {[
            { label: 'Incident Prevention',  value: fmt(incident),  sub: `IBM $4.88M × ${mul}× industry × 1.2% rate` },
            { label: 'Inference Savings',    value: fmt(inference), sub: 'Shadow-banned requests × $0.0008 avg cost × 12mo' },
            { label: 'SecOps Efficiency',    value: fmt(secops),    sub: '2.5h triage × $85/hr × incidents/yr' },
          ].map(({ label, value, sub }) => (
            <div key={label} className="flex items-center justify-between px-4 py-3 border-b border-white/[0.04] last:border-0 bg-white/[0.02]">
              <div>
                <p className="text-sm font-medium text-white">{label}</p>
                <p className="text-xs text-slate-500 mt-0.5">{sub}</p>
              </div>
              <span className="text-sm font-semibold text-green-400 font-mono">{value}</span>
            </div>
          ))}
          <div className="flex items-center justify-between px-4 py-3.5 bg-green-500/5 border-t border-green-500/20">
            <p className="text-sm font-bold text-white">Annual Value Delivered</p>
            <span className="text-base font-bold text-green-400 font-mono">{fmt(annual)}</span>
          </div>
        </div>

        <p className="text-xs text-slate-500">
          Live data available via <span className="font-mono text-brand-400">GET /financial/impact</span> — reads from logs.json, Redis ERS, and Prometheus.
        </p>
      </div>
    </Section>
  )
}

// ── Install / Uninstall section ───────────────────────────────────────────────
function CodeBlock({ children }: { children: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="relative group">
      <pre className="bg-black/40 border border-white/[0.07] rounded-xl p-4 text-xs font-mono text-slate-300 overflow-x-auto leading-relaxed whitespace-pre">{children}</pre>
      <button
        onClick={() => { navigator.clipboard.writeText(children); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
        className="absolute top-3 right-3 opacity-0 group-hover:opacity-100 transition-opacity text-xs px-2 py-1 rounded-lg bg-white/10 border border-white/10 text-slate-300 hover:text-white"
      >
        {copied ? '✓ Copied' : 'Copy'}
      </button>
    </div>
  )
}

function InstallSection() {
  const services = [
    { name: 'proxy',      port: '80/443',   desc: 'Caddy v2 — TLS, QUIC/H3, HSTS, hostname routing' },
    { name: 'warden',     port: '8001',     desc: 'FastAPI gateway — /filter, agents, all API routes' },
    { name: 'app',        port: '8000',     desc: 'Application server' },
    { name: 'analytics',  port: '8002',     desc: 'Streamlit — Settings, Enterprise, Community, Secrets' },
    { name: 'dashboard',  port: '8501',     desc: 'Streamlit security dashboard' },
    { name: 'postgres',   port: '5432',     desc: 'TimescaleDB — probe hypertable, 30-day retention' },
    { name: 'redis',      port: '6379',     desc: 'Cache, ERS, SOVA memory, rate-limit' },
    { name: 'prometheus', port: '9090',     desc: 'Metrics scrape' },
    { name: 'grafana',    port: '3000',     desc: 'SLO alerts + dashboards' },
    { name: 'minio',      port: '9000/9001',desc: 'On-prem S3 — Evidence Vault + screencasts' },
    { name: 'minio-init', port: '—',        desc: 'Bucket bootstrap sidecar (exits after init)' },
  ]

  return (
    <Section title="Install / Uninstall" description="Shadow Warden AI v4.10 — Docker Compose, 11 services, single command" icon={Package}>
      <div className="space-y-5 max-w-xl">

        {/* Quick Start */}
        <div>
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Quick Start</p>
          <CodeBlock>{`# 1. Clone
git clone https://github.com/zborrman/Shadow-Warden-AI.git
cd Shadow-Warden-AI

# 2. Configure
cp .env.example .env
# Edit: SECRET_KEY  WARDEN_API_KEY  POSTGRES_PASS
# Optional: ANTHROPIC_API_KEY  SLACK_WEBHOOK_URL

# 3. Start all 11 services
docker compose up --build -d

# 4. Verify
python scripts/warden_doctor.py \\
  --url http://localhost --key $WARDEN_API_KEY`}</CodeBlock>
          <p className="text-xs text-slate-500 mt-2">First run downloads PyTorch CPU wheels (~200 MB) and <span className="font-mono text-slate-400">all-MiniLM-L6-v2</span> (~80 MB). Cached on rebuild.</p>
        </div>

        {/* One-click SMB */}
        <div>
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">One-Click SMB Installer</p>
          <CodeBlock>{`bash <(curl -fsSL https://install.shadow-warden-ai.com/smb)`}</CodeBlock>
          <p className="text-xs text-slate-500 mt-1.5">Handles Docker detection, .env keygen, MinIO bucket init, health checks, and smoke test.</p>
        </div>

        {/* Services */}
        <div>
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Services (11)</p>
          <div className="rounded-xl border border-white/[0.06] overflow-hidden text-xs">
            {services.map((s, i) => (
              <div key={s.name} className={`flex items-start gap-3 px-4 py-2.5 ${i < services.length - 1 ? 'border-b border-white/[0.04]' : ''}`}>
                <span className="font-mono text-brand-400 w-20 flex-shrink-0 pt-0.5">{s.name}</span>
                <span className="font-mono text-slate-500 w-16 flex-shrink-0 pt-0.5">{s.port}</span>
                <span className="text-slate-400">{s.desc}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Update */}
        <div>
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Update to Latest</p>
          <CodeBlock>{`git pull origin main
docker compose pull
docker compose up --build -d`}</CodeBlock>
        </div>

        {/* Uninstall */}
        <div className="rounded-xl border border-red-500/20 bg-red-500/[0.03] p-4">
          <div className="flex items-center gap-2 mb-3">
            <Trash2 className="w-4 h-4 text-red-400" />
            <p className="text-sm font-semibold text-red-400">Uninstall</p>
          </div>
          <div className="space-y-2">
            <div>
              <p className="text-xs text-slate-400 mb-1.5">Stop containers — keep volumes (data safe)</p>
              <CodeBlock>{`docker compose down`}</CodeBlock>
            </div>
            <div>
              <p className="text-xs text-slate-400 mb-1.5">Full wipe — removes ALL data volumes (irreversible)</p>
              <CodeBlock>{`docker compose down -v --rmi all`}</CodeBlock>
            </div>
            <div>
              <p className="text-xs text-slate-400 mb-1.5">Remove named model volume only</p>
              <CodeBlock>{`docker volume rm shadow-warden-ai_warden-models`}</CodeBlock>
            </div>
          </div>
          <p className="text-xs text-red-400/70 mt-3">⚠ Back up your MinIO evidence vault before running the full wipe. <code>-v</code> permanently deletes all database data and logs.</p>
        </div>

      </div>
    </Section>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function SettingsPage() {
  return (
    <>
      <TopBar title="Settings" />
      <div className="flex-1 p-6">
        <div className="max-w-2xl space-y-5">
          <ProfileSection />
          <NotificationsSection />
          <SecuritySection />
          <StorageSection />
          <FinancialSection />
          <PasswordSection />
          <BillingSection />
          <InstallSection />
        </div>
      </div>
    </>
  )
}
