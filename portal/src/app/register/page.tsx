'use client'
import { useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Eye, EyeOff, AlertCircle, CheckCircle2, ShieldCheck, Users, Brain } from 'lucide-react'
import { register as registerUser, login } from '@/lib/auth'

const schema = z.object({
  display_name: z.string().max(80).optional(),
  email:        z.string().email('Invalid email'),
  password:     z.string().min(8, 'Password must be at least 8 characters'),
  confirm:      z.string(),
}).refine(d => d.password === d.confirm, {
  message: "Passwords don't match",
  path: ['confirm'],
})
type Form = z.infer<typeof schema>

const PERKS = [
  { icon: ShieldCheck, label: '1,000 req / month free',   desc: 'Full 9-layer pipeline' },
  { icon: Brain,       label: 'No credit card required',  desc: '14-day Pro trial included' },
  { icon: Users,       label: 'GDPR & SOC 2 compliant',   desc: 'ISO 27001 ready' },
]

const TIERS = [
  { name: 'Starter',  price: 'Free',   color: '#64748b' },
  { name: 'Pro',      price: '$69/mo', color: '#6366f1', popular: true },
  { name: 'Business', price: '$19/mo', color: '#8b5cf6' },
]

export default function RegisterPage() {
  const router  = useRouter()
  const [showPw, setShowPw] = useState(false)
  const [error, setError]   = useState('')
  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<Form>({
    resolver: zodResolver(schema),
  })

  async function onSubmit(data: Form) {
    setError('')
    try {
      await registerUser(data.email, data.password, data.display_name)
      await login(data.email, data.password)
      router.replace('/dashboard/')
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Registration failed. Please try again.')
    }
  }

  return (
    <div className="min-h-screen flex">

      {/* ── Left panel (hero) ── */}
      <div className="hidden lg:flex flex-col justify-between w-[46%] relative overflow-hidden px-12 py-12"
           style={{
             background: 'linear-gradient(160deg,#05091a 0%,#0b1228 55%,#0d1035 100%)',
             borderRight: '1px solid rgba(255,255,255,0.06)',
           }}>

        <div className="absolute inset-0 pointer-events-none" style={{
          background: 'radial-gradient(ellipse 600px 500px at -10% 50%,rgba(129,140,248,0.09) 0%,transparent 70%)',
        }} />
        <div className="absolute inset-0 pointer-events-none" style={{
          background: 'radial-gradient(ellipse 400px 400px at 110% 20%,rgba(56,189,248,0.07) 0%,transparent 70%)',
        }} />

        {/* Brand */}
        <div className="relative z-10 flex items-center gap-3">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/logo.png" alt="Shadow Warden AI" className="w-9 h-9 rounded-xl object-contain" />
          <div>
            <div className="text-[13px] font-bold tracking-tight text-white leading-none">Shadow Warden AI</div>
            <div className="text-[10px] font-semibold tracking-widest mt-0.5"
                 style={{ color: '#818cf8' }}>ZERO-TRUST AI GATEWAY</div>
          </div>
        </div>

        {/* Center content */}
        <div className="relative z-10 space-y-8">
          <div>
            <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold tracking-widest mb-4"
                 style={{ color: '#818cf8', background: 'rgba(129,140,248,0.1)', border: '1px solid rgba(129,140,248,0.2)' }}>
              ◇ VERSION 5.2 — LATEST RELEASE
            </div>
            <h2 className="text-[28px] font-black leading-tight text-white mb-3">
              Protect your AI<br />
              <span style={{ background: 'linear-gradient(135deg,#818cf8,#38bdf8)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }}>
                in 60 seconds.
              </span>
            </h2>
            <p className="text-[13px] leading-relaxed" style={{ color: '#64748b' }}>
              Drop Shadow Warden in front of any LLM. Get real-time<br />
              jailbreak detection, PII redaction, and SOC 2 audit logs.
            </p>
          </div>

          {/* Perks */}
          <div className="space-y-3">
            {PERKS.map(({ icon: Icon, label, desc }) => (
              <div key={label} className="flex items-start gap-3 rounded-xl px-4 py-3"
                   style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
                <div className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0 mt-0.5"
                     style={{ background: 'rgba(129,140,248,0.12)', border: '1px solid rgba(129,140,248,0.2)' }}>
                  <Icon size={13} style={{ color: '#818cf8' }} />
                </div>
                <div>
                  <div className="text-[12px] font-semibold text-white">{label}</div>
                  <div className="text-[11px]" style={{ color: '#475569' }}>{desc}</div>
                </div>
              </div>
            ))}
          </div>

          {/* Tier chips */}
          <div>
            <div className="text-[10px] font-semibold tracking-widest mb-2" style={{ color: '#334155' }}>
              AVAILABLE PLANS
            </div>
            <div className="flex flex-wrap gap-2">
              {TIERS.map(t => (
                <div key={t.name}
                     className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-semibold"
                     style={{ color: t.color, background: t.color + '14', border: `1px solid ${t.color}30`,
                              boxShadow: t.popular ? `0 0 0 1px ${t.color}40` : 'none' }}>
                  {t.popular && <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: t.color }} />}
                  {t.name}
                  <span className="font-normal opacity-70">{t.price}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="relative z-10 text-[11px]" style={{ color: '#334155' }}>
          SOC 2 · GDPR Art. 35 DPIA · OWASP LLM Top 10
        </div>
      </div>

      {/* ── Right panel (form) ── */}
      <div className="flex-1 flex items-center justify-center p-6 lg:p-12"
           style={{ background: '#050a13' }}>
        <div className="w-full max-w-sm">

          {/* Logo — mobile only */}
          <div className="flex lg:hidden items-center gap-2.5 mb-8">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src="/logo.png" alt="Shadow Warden AI" className="w-8 h-8 rounded-lg object-contain" />
            <span className="text-[13px] font-bold text-white">Shadow Warden AI</span>
          </div>

          {/* Heading */}
          <div className="mb-8">
            <h1 className="text-[24px] font-black text-white mb-1">Create your account</h1>
            <p className="text-[13px]" style={{ color: '#64748b' }}>
              Start protecting your AI in minutes — free forever
            </p>
          </div>

          {/* Form card */}
          <div className="rounded-2xl p-6 space-y-4"
               style={{ background: '#0b1220', border: '1px solid rgba(255,255,255,0.07)' }}>

            {error && (
              <div className="flex items-center gap-2 rounded-xl px-3 py-2.5 text-[12px]"
                   style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', color: '#f87171' }}>
                <AlertCircle size={13} className="shrink-0" />
                {error}
              </div>
            )}

            <div>
              <label className="label">
                Name <span className="font-normal" style={{ color: '#475569' }}>(optional)</span>
              </label>
              <input {...register('display_name')} type="text" placeholder="Jane Smith" className="input" />
            </div>

            <div>
              <label className="label">Work email</label>
              <input {...register('email')} type="email" autoComplete="email"
                     placeholder="you@company.com" className="input" />
              {errors.email && <p className="text-red-400 text-xs mt-1">{errors.email.message}</p>}
            </div>

            <div>
              <label className="label">Password</label>
              <div className="relative">
                <input
                  {...register('password')}
                  type={showPw ? 'text' : 'password'}
                  autoComplete="new-password"
                  placeholder="Min. 8 characters"
                  className="input pr-11"
                />
                <button type="button" onClick={() => setShowPw(!showPw)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 transition-colors"
                        style={{ color: '#475569' }}
                        onMouseOver={e => (e.currentTarget.style.color = '#94a3b8')}
                        onMouseOut={e  => (e.currentTarget.style.color = '#475569')}>
                  {showPw ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
              {errors.password && <p className="text-red-400 text-xs mt-1">{errors.password.message}</p>}
            </div>

            <div>
              <label className="label">Confirm password</label>
              <input
                {...register('confirm')}
                type={showPw ? 'text' : 'password'}
                autoComplete="new-password"
                placeholder="Repeat password"
                className="input"
              />
              {errors.confirm && <p className="text-red-400 text-xs mt-1">{errors.confirm.message}</p>}
            </div>

            <button type="button" onClick={handleSubmit(onSubmit)} disabled={isSubmitting}
                    className="btn-primary w-full mt-1">
              {isSubmitting
                ? <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                : 'Create Account →'}
            </button>

            {/* Inline benefit chips */}
            <div className="flex flex-wrap gap-1.5 pt-1">
              {['Free tier', 'No card needed', 'GDPR'].map(chip => (
                <div key={chip} className="flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-md"
                     style={{ color: '#22c55e', background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.15)' }}>
                  <CheckCircle2 size={9} />
                  {chip}
                </div>
              ))}
            </div>
          </div>

          <p className="text-center text-[12px] mt-5" style={{ color: '#475569' }}>
            Already have an account?{' '}
            <Link href="/login/"
                  className="font-semibold hover:opacity-80 transition-opacity"
                  style={{ color: '#38bdf8' }}>
              Sign in
            </Link>
          </p>

          <p className="text-center text-[10px] mt-8" style={{ color: '#1e293b' }}>
            Shadow Warden AI v5.2 · All systems operational
          </p>
        </div>
      </div>
    </div>
  )
}
