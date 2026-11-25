'use client'
import { useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { completeTotp, login } from '@/lib/auth'
import { AuthShell, ErrorNote, Spinner, detailOf, field, labelCls, primary, secondary, textLink } from '@/components/auth/AuthShell'
import { PasswordField } from '@/components/auth/PasswordField'

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [totpSession, setTotpSession] = useState('')
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function onSignin(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    if (!EMAIL.test(email.trim())) return setError('Enter a valid work email.')
    if (!password) return setError('Enter your password.')
    setBusy(true)
    try {
      const r = await login(email.trim(), password)
      if ('requires_totp' in r) { setTotpSession(r.totp_session); setPassword(''); return }
      router.replace('/dashboard/')
    } catch (err) {
      setError(detailOf(err, 'Sign-in failed. Please try again.'))
    } finally {
      setBusy(false)
    }
  }

  async function onCode(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    if (code.length !== 6) return setError('Enter all 6 digits.')
    setBusy(true)
    try {
      await completeTotp(totpSession, code)
      router.replace('/dashboard/')
    } catch (err) {
      const msg = detailOf(err, 'That code did not work. Try the current one.')
      setError(msg)
      // An expired step-one session cannot be retried with another code.
      if (msg.includes('expired')) { setTotpSession(''); setCode('') }
    } finally {
      setBusy(false)
    }
  }

  if (totpSession) {
    return (
      <AuthShell step="Step 2 of 2" title="Two-step verification"
                 lead="Open your authenticator app and enter the current code for Shadow Warden.">
        {error && <ErrorNote>{error}</ErrorNote>}
        <form onSubmit={onCode} className="flex flex-col gap-4">
          <label className={labelCls}>6-digit code from your authenticator app
            <input value={code} onChange={e => setCode(e.target.value.replace(/[^0-9]/g, '').slice(0, 6))}
                   inputMode="numeric" autoComplete="one-time-code" autoFocus placeholder="000000"
                   className={`${field} min-h-[56px] font-mono text-[24px] tracking-[0.4em] text-center`} />
          </label>
          <button type="submit" disabled={busy || code.length !== 6} className={primary}>
            {busy ? <Spinner /> : 'Verify and sign in'}
          </button>
          <button type="button" onClick={() => { setTotpSession(''); setCode(''); setError('') }} className={secondary}>
            Use a different account
          </button>
        </form>
      </AuthShell>
    )
  }

  return (
    <AuthShell step="Step 1 of 2" title="Sign in"
               lead="Use your work email. A code from your authenticator app comes next."
               footer={<p className="m-0 text-[14px] text-[#8b98a8]">New here? <Link href="/register/" className={textLink}>Create an account</Link></p>}>
      <nav aria-label="Account" className="grid grid-cols-2 gap-1 p-1 rounded-lg border border-[#232c38] bg-[#151b23]">
        <span aria-current="page" className="min-h-[40px] rounded-md bg-[#0d1117] text-[14px] font-semibold flex items-center justify-center shadow-sm">Sign in</span>
        <Link href="/register/" className="min-h-[40px] rounded-md text-[14px] font-semibold text-[#8b98a8] flex items-center justify-center no-underline hover:text-[#e6edf3]">Create account</Link>
      </nav>
      {error && <ErrorNote>{error}</ErrorNote>}
      <form onSubmit={onSignin} className="flex flex-col gap-4" noValidate>
        <label className={labelCls}>Work email
          <input type="email" name="email" autoComplete="username" value={email} onChange={e => setEmail(e.target.value)}
                 placeholder="you@company.com" className={field} />
        </label>
        <div className="flex flex-col gap-1">
          <PasswordField label="Password" value={password} onChange={setPassword} autoComplete="current-password" id="pw-in" name="password" />
          <Link href="/forgot-password/" className={`${textLink} text-[13px] self-end mt-1`}>Forgot password?</Link>
        </div>
        <button type="submit" disabled={busy} className={primary}>{busy ? <Spinner /> : 'Continue'}</button>
      </form>
    </AuthShell>
  )
}
