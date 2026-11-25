'use client'
import { useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { QRCodeSVG } from 'qrcode.react'
import { api } from '@/lib/api'
import { login, register as registerUser } from '@/lib/auth'
import { passwordRules } from '@/lib/password'
import { AuthShell, ErrorNote, Spinner, detailOf, field, labelCls, primary, textLink } from '@/components/auth/AuthShell'
import { PasswordField } from '@/components/auth/PasswordField'

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/

type Setup = { secret: string; otpauth_uri: string }

export default function RegisterPage() {
  const router = useRouter()
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [terms, setTerms] = useState(false)
  const [setup, setSetup] = useState<Setup | null>(null)
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const strong = passwordRules(password, email).every(r => r.ok)
  const emailOk = EMAIL.test(email.trim())
  const match = confirm.length > 0 && password === confirm
  const ready = emailOk && strong && match && terms

  async function onCreate(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    if (!ready) {
      return setError(!emailOk ? 'Enter a valid work email.' : !strong ? 'The password does not meet every rule yet.'
        : !match ? 'The two passwords differ.' : 'Accept the Terms to continue.')
    }
    setBusy(true)
    try {
      await registerUser(email.trim(), password, name.trim() || undefined)
      const r = await login(email.trim(), password)
      if ('requires_totp' in r) { router.replace('/login/'); return }
      const { data } = await api.post<Setup>('/auth/totp/setup')
      setPassword(''); setConfirm('')
      setSetup(data)
    } catch (err) {
      setError(detailOf(err, 'Registration failed. Please try again.'))
    } finally {
      setBusy(false)
    }
  }

  async function onEnable(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    if (code.length !== 6) return setError('Enter the 6-digit code your app shows.')
    setBusy(true)
    try {
      await api.post('/auth/totp/confirm', { code })
      router.replace('/dashboard/')
    } catch (err) {
      setError(detailOf(err, 'That code did not work. Try the current one.'))
    } finally {
      setBusy(false)
    }
  }

  if (setup) {
    return (
      <AuthShell step="Step 2 of 2" title="Protect your account"
                 lead="Two-step verification is required. Link an authenticator app, then enter the code it shows.">
        {error && <ErrorNote>{error}</ErrorNote>}
        <form onSubmit={onEnable} className="flex flex-col gap-4">
          <div className="flex gap-4 items-center p-4 rounded-lg border border-[#232c38] bg-[#151b23]">
            <div className="shrink-0 bg-white p-2 rounded">
              <QRCodeSVG value={setup.otpauth_uri} size={112} aria-label="QR code for your authenticator app" />
            </div>
            <div className="flex flex-col gap-1.5 min-w-0">
              <span className="text-[14px] font-semibold">Scan with an authenticator app</span>
              <span className="text-[13px] leading-[18px] text-[#8b98a8]">Or type this key by hand:</span>
              <code className="font-mono text-[13px] tracking-[0.06em] break-all">{setup.secret.replace(/(.{4})/g, '$1 ').trim()}</code>
            </div>
          </div>
          <label className={labelCls}>6-digit code from the app
            <input value={code} onChange={e => setCode(e.target.value.replace(/[^0-9]/g, '').slice(0, 6))}
                   inputMode="numeric" autoComplete="one-time-code" autoFocus placeholder="000000"
                   className={`${field} min-h-[56px] font-mono text-[24px] tracking-[0.4em] text-center`} />
          </label>
          <button type="submit" disabled={busy || code.length !== 6} className={primary}>
            {busy ? <Spinner /> : 'Turn on two-step verification'}
          </button>
        </form>
      </AuthShell>
    )
  }

  return (
    <AuthShell step="Step 1 of 2" title="Create your account"
               lead="One account per seller business. A strong password is required."
               footer={<p className="m-0 text-[14px] text-[#8b98a8]">Already have an account? <Link href="/login/" className={textLink}>Sign in</Link></p>}>
      <nav aria-label="Account" className="grid grid-cols-2 gap-1 p-1 rounded-lg border border-[#232c38] bg-[#151b23]">
        <Link href="/login/" className="min-h-[40px] rounded-md text-[14px] font-semibold text-[#8b98a8] flex items-center justify-center no-underline hover:text-[#e6edf3]">Sign in</Link>
        <span aria-current="page" className="min-h-[40px] rounded-md bg-[#0d1117] text-[14px] font-semibold flex items-center justify-center shadow-sm">Create account</span>
      </nav>
      {error && <ErrorNote>{error}</ErrorNote>}
      <form onSubmit={onCreate} className="flex flex-col gap-4" noValidate>
        <label className={labelCls}><span>Your name <span className="text-[13px] font-normal text-[#8b98a8]">(optional)</span></span>
          <input autoComplete="name" value={name} onChange={e => setName(e.target.value)} maxLength={80} className={field} />
        </label>
        <label className={labelCls}>Work email
          <input type="email" autoComplete="username" value={email} onChange={e => setEmail(e.target.value)}
                 placeholder="you@company.com" className={field} />
        </label>
        <PasswordField label="Password" value={password} onChange={setPassword} autoComplete="new-password" email={email} rules id="pw-new" />
        <div className="flex flex-col gap-1.5">
          <PasswordField label="Confirm password" value={confirm} onChange={setConfirm} autoComplete="new-password" id="pw-confirm" />
          {confirm.length > 0 && !match && <span className="text-[13px] text-[#ff8a8a]">The two passwords differ.</span>}
        </div>
        <label className="flex items-start gap-2.5 text-[14px] leading-5 text-[#8b98a8]">
          <input type="checkbox" checked={terms} onChange={e => setTerms(e.target.checked)}
                 className="w-[18px] h-[18px] mt-px shrink-0 accent-[#00c2ff]" />
          <span>I agree to the <a href="https://shadow-warden-ai.com/terms" className={textLink}>Terms</a> and the <a href="https://shadow-warden-ai.com/privacy" className={textLink}>Privacy Notice</a>.</span>
        </label>
        <button type="submit" disabled={busy || !ready} className={primary}>{busy ? <Spinner /> : 'Create account'}</button>
        <p className="m-0 text-[13px] leading-[18px] text-[#8b98a8]">Next you will set up two-step verification. It is required for every new account.</p>
      </form>
    </AuthShell>
  )
}
