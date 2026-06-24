'use client'
import { useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Eye, EyeOff, AlertCircle, ShieldCheck, Zap, Lock } from 'lucide-react'
import { login } from '@/lib/auth'

const schema = z.object({
  email:    z.string().email('Invalid email'),
  password: z.string().min(1, 'Password required'),
})
type Form = z.infer<typeof schema>

const STATS = [
  { value: '< 2ms',  label: 'Filter latency' },
  { value: '15',     label: 'Defense layers' },
  { value: '99.9%',  label: 'Uptime SLA' },
]

const FEATURES = [
  { icon: ShieldCheck, text: '9-layer AI security pipeline' },
  { icon: Zap,         text: 'Real-time jailbreak detection' },
  { icon: Lock,        text: 'Post-Quantum Cryptography (v6.8)' },
]

export default function LoginPage() {
  const router = useRouter()
  const [showPw, setShowPw] = useState(false)
  const [error, setError]   = useState('')
  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<Form>({
    resolver: zodResolver(schema),
  })

  async function onSubmit(data: Form) {
    setError('')
    try {
      await login(data.email, data.password)
      router.replace('/dashboard/')
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Login failed. Please try again.')
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

        {/* Background glow */}
        <div className="absolute inset-0 pointer-events-none" style={{
          background: 'radial-gradient(ellipse 600px 500px at -10% 50%,rgba(56,189,248,0.09) 0%,transparent 70%)',
        }} />
        <div className="absolute inset-0 pointer-events-none" style={{
          background: 'radial-gradient(ellipse 400px 400px at 110% 80%,rgba(129,140,248,0.07) 0%,transparent 70%)',
        }} />

        {/* Brand */}
        <div className="relative z-10 flex items-center gap-3">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/logo.png" alt="Shadow Warden AI" className="w-9 h-9 rounded-xl object-contain" />
          <div>
            <div className="text-[13px] font-bold tracking-tight text-white leading-none">Shadow Warden AI</div>
            <div className="text-[10px] font-semibold tracking-widest mt-0.5"
                 style={{ color: '#38bdf8' }}>ZERO-TRUST AI GATEWAY</div>
          </div>
        </div>

        {/* Center content */}
        <div className="relative z-10 space-y-8">
          <div>
            <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold tracking-widest mb-4"
                 style={{ color: '#38bdf8', background: 'rgba(56,189,248,0.1)', border: '1px solid rgba(56,189,248,0.2)' }}>
              ◇ VERSION 5.2 — LATEST
            </div>
            <h2 className="text-[28px] font-black leading-tight text-white mb-3">
              Your AI<br />
              <span style={{ background: 'linear-gradient(135deg,#38bdf8,#818cf8)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }}>
                stays safe.
              </span>
            </h2>
            <p className="text-[13px] leading-relaxed" style={{ color: '#64748b' }}>
              15-layer real-time security gateway. Blocks jailbreaks, strips PII,<br />
              enforces compliance — all in under 2ms.
            </p>
          </div>

          {/* Stats row */}
          <div className="grid grid-cols-3 gap-3">
            {STATS.map(s => (
              <div key={s.label} className="rounded-xl px-3 py-3 text-center"
                   style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
                <div className="text-[18px] font-black text-white leading-none mb-1">{s.value}</div>
                <div className="text-[10px] font-medium" style={{ color: '#475569' }}>{s.label}</div>
              </div>
            ))}
          </div>

          {/* Feature bullets */}
          <div className="space-y-2.5">
            {FEATURES.map(({ icon: Icon, text }) => (
              <div key={text} className="flex items-center gap-2.5">
                <div className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0"
                     style={{ background: 'rgba(56,189,248,0.1)', border: '1px solid rgba(56,189,248,0.15)' }}>
                  <Icon size={13} style={{ color: '#38bdf8' }} />
                </div>
                <span className="text-[12px] font-medium" style={{ color: '#94a3b8' }}>{text}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Footer note */}
        <div className="relative z-10 text-[11px]" style={{ color: '#334155' }}>
          SOC 2 · GDPR · OWASP LLM Top 10
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
            <h1 className="text-[24px] font-black text-white mb-1">Welcome back</h1>
            <p className="text-[13px]" style={{ color: '#64748b' }}>Sign in to your portal</p>
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
              <label className="label">Email</label>
              <input
                {...register('email')}
                type="email"
                autoComplete="email"
                placeholder="you@company.com"
                className="input"
              />
              {errors.email && <p className="text-red-400 text-xs mt-1">{errors.email.message}</p>}
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="label mb-0">Password</label>
                <Link href="/forgot-password/"
                      className="text-[11px] font-medium hover:opacity-80 transition-opacity"
                      style={{ color: '#38bdf8' }}>
                  Forgot password?
                </Link>
              </div>
              <div className="relative">
                <input
                  {...register('password')}
                  type={showPw ? 'text' : 'password'}
                  autoComplete="current-password"
                  placeholder="••••••••"
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

            <button type="button" onClick={handleSubmit(onSubmit)} disabled={isSubmitting}
                    className="btn-primary w-full mt-1">
              {isSubmitting
                ? <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                : 'Sign In →'}
            </button>
          </div>

          <p className="text-center text-[12px] mt-5" style={{ color: '#475569' }}>
            Don&apos;t have an account?{' '}
            <Link href="/register/"
                  className="font-semibold hover:opacity-80 transition-opacity"
                  style={{ color: '#38bdf8' }}>
              Create account free
            </Link>
          </p>

          <p className="text-center text-[10px] mt-8" style={{ color: '#1e293b' }}>
            Shadow Warden AI v6.8 · GDPR compliant · All systems operational
          </p>
        </div>
      </div>
    </div>
  )
}
