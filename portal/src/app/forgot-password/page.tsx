'use client'
import { useState } from 'react'
import Link from 'next/link'
import { forgotPassword } from '@/lib/auth'
import { AuthShell, ErrorNote, Spinner, field, labelCls, primary, textLink } from '@/components/auth/AuthShell'

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('')
  const [sent, setSent] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    if (!EMAIL.test(email.trim())) return setError('Enter a valid work email.')
    setBusy(true)
    // The answer is the same whether or not the address has an account.
    await forgotPassword(email.trim()).catch(() => {})
    setBusy(false)
    setSent(true)
  }

  const back = <Link href="/login/" className={`${textLink} text-[14px]`}>← Back to sign in</Link>

  if (sent) {
    return (
      <AuthShell step="Password reset" title="Check your email"
                 lead="If that address has an account, a reset link is on its way. It works once and expires soon."
                 footer={back}>
        <div aria-hidden="true" className="w-14 h-14 rounded-full bg-[#0f2a1f] text-[#3ddc97] flex items-center justify-center">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 6h16v12H4zM4 7l8 6 8-6" /></svg>
        </div>
        <p className="m-0 text-[14px] leading-5 text-[#8b98a8]">No email after a few minutes? Check spam, or <button type="button" onClick={() => setSent(false)} className={`${textLink} bg-transparent border-0 p-0 cursor-pointer text-[14px]`}>send it again</button>.</p>
      </AuthShell>
    )
  }

  return (
    <AuthShell step="Password reset" title="Forgot your password?"
               lead="Enter your work email and we send a link to choose a new one."
               footer={back}>
      {error && <ErrorNote>{error}</ErrorNote>}
      <form onSubmit={onSubmit} className="flex flex-col gap-4" noValidate>
        <label className={labelCls}>Work email
          <input type="email" autoComplete="username" value={email} onChange={e => setEmail(e.target.value)}
                 placeholder="you@company.com" autoFocus className={field} />
        </label>
        <button type="submit" disabled={busy} className={primary}>{busy ? <Spinner /> : 'Send reset link'}</button>
      </form>
    </AuthShell>
  )
}
