'use client'
// Settings: a section list on the left, one panel of labelled rows on the right.
// Every control here is backed by a working endpoint or by this device's own
// storage; nothing is shown that does not do something.
import { useEffect, useState } from 'react'
import Link from 'next/link'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { QRCodeSVG } from 'qrcode.react'
import clsx from 'clsx'
import { Check, Copy, CreditCard, ExternalLink, Key, Lock, ShieldCheck, User } from 'lucide-react'
import { api } from '@/lib/api'
import { TopBar } from '@/components/layout/TopBar'
import { useTheme } from '@/components/ui/ThemeProvider'
import { browserTimeZone, formatWhen, usePrefs } from '@/lib/prefs'

type SectionId = 'details' | 'security' | 'billing'
type NavItem = { id: SectionId; label: string; icon: React.ElementType } | { href: string; label: string; icon: React.ElementType }

const NAV: { group: string; items: NavItem[] }[] = [
  { group: 'Account', items: [
    { id: 'details',  label: 'Account Details', icon: User },
    { id: 'security', label: 'Security',        icon: Lock },
  ] },
  { group: 'Organization', items: [
    { id: 'billing',     label: 'Plan & Usage', icon: CreditCard },
    { href: '/api-keys/', label: 'API Keys',    icon: Key },
  ] },
]
const SECTION_IDS: SectionId[] = ['details', 'security', 'billing']

interface Me {
  user_id: string; email: string; display_name: string | null; tenant_id: string; role: string
  created_at: string | null; last_login_at: string | null
}

const detail = (e: unknown, fallback: string) =>
  (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || fallback

// ── Layout primitives ────────────────────────────────────────────────────────

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="card overflow-hidden">
      <h2 className="border-b border-white/[0.06] px-5 py-3 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
        {title}
      </h2>
      <div className="divide-y divide-white/[0.06]">{children}</div>
    </section>
  )
}

function Row({ label, help, htmlFor, children }: {
  label: string; help?: React.ReactNode; htmlFor?: string; children: React.ReactNode
}) {
  return (
    <div className="grid gap-3 px-5 py-4 sm:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)] sm:items-center sm:gap-6">
      <div>
        {htmlFor ? <label htmlFor={htmlFor} className="text-sm font-medium text-slate-100">{label}</label>
                 : <p className="text-sm font-medium text-slate-100">{label}</p>}
        {help && <p className="mt-0.5 text-xs text-slate-400">{help}</p>}
      </div>
      <div className="min-w-0">{children}</div>
    </div>
  )
}

function Switch({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button type="button" role="switch" aria-checked={checked} aria-label={label} onClick={() => onChange(!checked)}
            className={clsx('relative h-6 w-11 rounded-full transition-colors',
              checked ? 'bg-brand-400' : 'bg-white/10')}>
      <span className={clsx('absolute left-0.5 top-0.5 h-5 w-5 rounded-full bg-white shadow transition-transform',
        checked && 'translate-x-5')} />
    </button>
  )
}

function CopyField({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="relative">
      <input value={value} readOnly aria-label={label} className="input pr-10 font-mono text-xs opacity-70" />
      <button type="button" aria-label={`Copy ${label}`}
              onClick={() => { navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200">
        {copied ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
      </button>
    </div>
  )
}

// ── Account Details ──────────────────────────────────────────────────────────

function AccountDetails() {
  const qc = useQueryClient()
  const me = useQuery({ queryKey: ['me'], queryFn: () => api.get<Me>('/me').then(r => r.data) })
  const [name, setName] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: (display_name: string) => api.patch('/me', { display_name }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['me'] }); setName(null); toast.success('Name saved') },
    onError: e => toast.error(detail(e, 'Could not save the name')),
  })
  const { theme, toggle } = useTheme()
  const [prefs, setPrefs] = usePrefs()
  const [zones, setZones] = useState<string[]>([])
  useEffect(() => {
    const all = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf
    setZones(all ? all('timeZone') : [browserTimeZone()])
  }, [])
  const m = me.data

  return (
    <div className="space-y-5">
      <Panel title="Account">
        <Row label="Name" help="Shown in the portal and to your team." htmlFor="set-name">
          <form className="flex gap-2" onSubmit={e => { e.preventDefault(); if (name !== null) save.mutate(name.trim()) }}>
            <input id="set-name" className="input" maxLength={80} placeholder="Your name"
                   value={name ?? m?.display_name ?? ''} onChange={e => setName(e.target.value)} />
            <button type="submit" className="btn-secondary shrink-0" disabled={name === null || save.isPending}>Save</button>
          </form>
        </Row>
        <Row label="Email" help="Your sign-in address. It cannot be changed here.">
          <input value={m?.email ?? ''} readOnly aria-label="Email" className="input opacity-70" />
        </Row>
        <Row label="Tenant ID" help="Identifies your organization in API calls and support requests.">
          <CopyField value={m?.tenant_id ?? ''} label="Tenant ID" />
        </Row>
        <Row label="Member since">
          <p className="text-sm text-slate-300">
            {m?.created_at ? formatWhen(m.created_at, false, prefs) : '—'}
            {m?.last_login_at && <span className="text-slate-500"> · last sign-in {formatWhen(m.last_login_at, true, prefs)}</span>}
          </p>
        </Row>
      </Panel>

      <Panel title="Preferences">
        <Row label="Theme" help="Light or dark interface." htmlFor="set-theme">
          <select id="set-theme" className="input" value={theme}
                  onChange={e => { if (e.target.value !== theme) toggle() }}>
            <option value="dark">Dark</option>
            <option value="light">Light</option>
          </select>
        </Row>
        <Row label="Timezone" help="Dates in the portal are shown in this zone." htmlFor="set-tz">
          <select id="set-tz" className="input" value={prefs.timeZone}
                  onChange={e => setPrefs({ timeZone: e.target.value })}>
            <option value="">Browser default ({browserTimeZone()})</option>
            {zones.map(z => <option key={z} value={z}>{z.replace(/_/g, ' ')}</option>)}
          </select>
        </Row>
        <Row label="Use a 24-hour clock" help={`Now: ${formatWhen(new Date().toISOString(), true, prefs)}`}>
          <Switch checked={!prefs.hour12} onChange={v => setPrefs({ hour12: !v })} label="Use a 24-hour clock" />
        </Row>
        <p className="px-5 py-3 text-xs text-slate-500">Preferences are saved on this device.</p>
      </Panel>
    </div>
  )
}

// ── Security ─────────────────────────────────────────────────────────────────

function PasswordPanel() {
  const [cur, setCur] = useState('')
  const [next, setNext] = useState('')
  const [again, setAgain] = useState('')
  const mismatch = again !== '' && next !== again
  const valid = cur !== '' && next.length >= 8 && next === again
  const change = useMutation({
    mutationFn: () => api.post('/me/change-password', { current_password: cur, new_password: next }),
    onSuccess: () => { setCur(''); setNext(''); setAgain(''); toast.success('Password changed') },
    onError: e => toast.error(detail(e, 'Could not change the password')),
  })
  return (
    <Panel title="Password">
      <form onSubmit={e => { e.preventDefault(); if (valid) change.mutate() }}>
        <Row label="Current password" htmlFor="pw-cur">
          <input id="pw-cur" type="password" autoComplete="current-password" className="input"
                 value={cur} onChange={e => setCur(e.target.value)} />
        </Row>
        <Row label="New password" help="At least 8 characters." htmlFor="pw-new">
          <input id="pw-new" type="password" autoComplete="new-password" className="input"
                 value={next} onChange={e => setNext(e.target.value)} />
        </Row>
        <Row label="Confirm new password" htmlFor="pw-again"
             help={mismatch ? <span className="text-red-400">The passwords do not match.</span> : undefined}>
          <input id="pw-again" type="password" autoComplete="new-password" className="input"
                 value={again} onChange={e => setAgain(e.target.value)} />
        </Row>
        <div className="flex justify-end px-5 py-3">
          <button type="submit" className="btn-primary" disabled={!valid || change.isPending}>Change password</button>
        </div>
      </form>
    </Panel>
  )
}

function TwoFactorPanel() {
  const qc = useQueryClient()
  const status = useQuery({
    queryKey: ['totp-status'],
    queryFn: () => api.get<{ totp_enabled: boolean }>('/auth/totp/status').then(r => r.data),
  })
  const [setup, setSetup] = useState<{ secret: string; otpauth_uri: string } | null>(null)
  const [code, setCode] = useState('')
  const [disabling, setDisabling] = useState(false)
  const done = (msg: string) => {
    setSetup(null); setCode(''); setDisabling(false)
    qc.invalidateQueries({ queryKey: ['totp-status'] })
    toast.success(msg)
  }
  const start = useMutation({
    mutationFn: () => api.post<{ secret: string; otpauth_uri: string }>('/auth/totp/setup').then(r => r.data),
    onSuccess: setSetup,
    onError: e => toast.error(detail(e, 'Could not start the setup')),
  })
  const confirm = useMutation({
    mutationFn: () => api.post('/auth/totp/confirm', { code }),
    onSuccess: () => done('Two-factor authentication is on'),
    onError: e => toast.error(detail(e, 'That code did not work')),
  })
  const disable = useMutation({
    mutationFn: () => api.post('/auth/totp/disable', { code }),
    onSuccess: () => done('Two-factor authentication is off'),
    onError: e => toast.error(detail(e, 'That code did not work')),
  })
  const codeInput = (id: string) => (
    <input id={id} value={code} onChange={e => setCode(e.target.value.replace(/[^0-9]/g, '').slice(0, 6))}
           inputMode="numeric" autoComplete="one-time-code" placeholder="123456"
           className="input w-32 font-mono tracking-[0.25em]" />
  )
  const on = status.data?.totp_enabled

  return (
    <Panel title="Two-factor authentication">
      <Row label="Authenticator app"
           help="After your password, sign-in asks for a 6-digit code from an app such as Google Authenticator, 1Password or Authy.">
        {status.isLoading ? <p className="text-sm text-slate-400">Checking…</p>
          : on ? (
            <div className="flex flex-wrap items-center gap-3">
              <span className="inline-flex items-center gap-1.5 text-sm text-green-400"><ShieldCheck className="h-4 w-4" /> On</span>
              {!disabling && <button type="button" className="btn-secondary" onClick={() => setDisabling(true)}>Turn off</button>}
            </div>
          ) : !setup ? (
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-sm text-slate-400">Off</span>
              <button type="button" className="btn-primary" disabled={start.isPending} onClick={() => start.mutate()}>
                Set up
              </button>
            </div>
          ) : null}
      </Row>

      {setup && (
        <form onSubmit={e => { e.preventDefault(); if (code.length === 6) confirm.mutate() }}>
          <Row label="1. Scan this code" help="Or, on the phone, type the key below into the app.">
            <div className="space-y-3">
              <div className="inline-block rounded-lg bg-white p-3">
                <QRCodeSVG value={setup.otpauth_uri} size={152} aria-label="QR code for the authenticator app" />
              </div>
              <CopyField value={setup.secret.replace(/(.{4})/g, '$1 ').trim()} label="Setup key" />
            </div>
          </Row>
          <Row label="2. Enter the code it shows" htmlFor="totp-confirm">
            <div className="flex flex-wrap gap-2">
              {codeInput('totp-confirm')}
              <button type="submit" className="btn-primary" disabled={code.length !== 6 || confirm.isPending}>Turn on</button>
              <button type="button" className="btn-secondary" onClick={() => { setSetup(null); setCode('') }}>Cancel</button>
            </div>
          </Row>
        </form>
      )}

      {on && disabling && (
        <form onSubmit={e => { e.preventDefault(); if (code.length === 6) disable.mutate() }}>
          <Row label="Confirm with a current code" help="Turning it off makes your password the only thing protecting the account."
               htmlFor="totp-disable">
            <div className="flex flex-wrap gap-2">
              {codeInput('totp-disable')}
              <button type="submit" className="btn-secondary text-red-300" disabled={code.length !== 6 || disable.isPending}>
                Turn off
              </button>
              <button type="button" className="btn-secondary" onClick={() => { setDisabling(false); setCode('') }}>Cancel</button>
            </div>
          </Row>
        </form>
      )}
    </Panel>
  )
}

// ── Plan & Usage ─────────────────────────────────────────────────────────────

function PlanUsage() {
  const billing = useQuery({
    queryKey: ['billing'],
    queryFn: () => api.get<{ plan?: string; requests_used?: number; requests_quota?: number }>('/billing').then(r => r.data),
  })
  const used = billing.data?.requests_used ?? 0
  const quota = billing.data?.requests_quota ?? 0
  const pct = quota > 0 ? Math.min(100, Math.round((used / quota) * 100)) : 0
  return (
    <Panel title="Subscription">
      <Row label="Plan">
        <span className="badge badge-active">{billing.data?.plan ?? '—'}</span>
      </Row>
      <Row label="API requests this month" help={quota > 0 ? `${pct}% of the monthly allowance` : undefined}>
        <div className="space-y-2">
          <p className="text-sm text-slate-100">{used.toLocaleString()}{quota > 0 && ` / ${quota.toLocaleString()}`}</p>
          {quota > 0 && (
            <div className="h-2 overflow-hidden rounded-full bg-white/[0.06]" role="progressbar"
                 aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label="Monthly allowance used">
              <div className={clsx('h-full rounded-full', pct > 80 ? 'bg-amber-500' : 'bg-brand-400')} style={{ width: `${pct}%` }} />
            </div>
          )}
        </div>
      </Row>
      <Row label="Plans and prices">
        <a href="https://www.shadow-warden-ai.com/price" target="_blank" rel="noreferrer"
           className="inline-flex items-center gap-1.5 text-sm text-brand-400 hover:underline">
          Compare plans <ExternalLink className="h-3.5 w-3.5" />
        </a>
      </Row>
    </Panel>
  )
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function SettingsPage() {
  const [section, setSection] = useState<SectionId>('details')
  useEffect(() => {
    const read = () => {
      const h = window.location.hash.slice(1) as SectionId
      if (SECTION_IDS.includes(h)) setSection(h)
    }
    read()
    window.addEventListener('hashchange', read)
    return () => window.removeEventListener('hashchange', read)
  }, [])
  const title = NAV.flatMap(g => g.items).find(i => 'id' in i && i.id === section)?.label ?? 'Settings'

  return (
    <>
      <TopBar title="Settings" />
      <div className="flex flex-1 flex-col gap-6 p-6 md:flex-row">
        <nav aria-label="Settings sections" className="shrink-0 md:w-52">
          {NAV.map(g => (
            <div key={g.group} className="mb-4">
              <p className="mb-1 px-3 text-[11px] font-semibold uppercase tracking-wider text-slate-500">{g.group}</p>
              <ul className="space-y-0.5">
                {g.items.map(item => {
                  const Icon = item.icon
                  const cls = 'flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors'
                  return (
                    <li key={item.label}>
                      {'id' in item ? (
                        <a href={`#${item.id}`} aria-current={section === item.id ? 'page' : undefined}
                           className={clsx(cls, section === item.id
                             ? 'bg-brand-400/10 font-medium text-slate-100'
                             : 'text-slate-400 hover:bg-white/[0.04] hover:text-slate-200')}>
                          <Icon className="h-4 w-4" aria-hidden /> {item.label}
                        </a>
                      ) : (
                        <Link href={item.href} className={clsx(cls, 'text-slate-400 hover:bg-white/[0.04] hover:text-slate-200')}>
                          <Icon className="h-4 w-4" aria-hidden /> {item.label}
                        </Link>
                      )}
                    </li>
                  )
                })}
              </ul>
            </div>
          ))}
        </nav>

        <div className="min-w-0 max-w-3xl flex-1 space-y-5">
          <h1 className="text-lg font-semibold text-slate-100">{title}</h1>
          {section === 'details' && <AccountDetails />}
          {section === 'security' && <div className="space-y-5"><PasswordPanel /><TwoFactorPanel /></div>}
          {section === 'billing' && <PlanUsage />}
        </div>
      </div>
    </>
  )
}
