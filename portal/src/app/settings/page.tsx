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

// ── Main page ─────────────────────────────────────────────────────────────────
export default function SettingsPage() {
  return (
    <>
      <TopBar title="Settings" />
      <div className="flex-1 p-6">
        <div className="max-w-2xl space-y-5">
          <ProfileSection />
          <NotificationsSection />
          <PasswordSection />
          <BillingSection />
        </div>
      </div>
    </>
  )
}
