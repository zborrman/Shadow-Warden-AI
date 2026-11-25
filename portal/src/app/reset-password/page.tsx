'use client'
import { Suspense, useState } from 'react'
import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import { resetPassword } from '@/lib/auth'
import { passwordRules } from '@/lib/password'
import { AuthShell, ErrorNote, Spinner, detailOf, primary, textLink } from '@/components/auth/AuthShell'
import { PasswordField } from '@/components/auth/PasswordField'

function ResetForm() {
  const token = useSearchParams().get('token') ?? ''
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [done, setDone] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const strong = passwordRules(password).every(r => r.ok)
  const match = confirm.length > 0 && password === confirm
  const back = <Link href="/login/" className={`${textLink} text-[14px]`}>← Back to sign in</Link>

  if (!token) {
    return (
      <AuthShell step="Password reset" title="This link is incomplete"
                 lead="It is missing its reset token. Ask for a new link and open it straight from the email."
                 footer={back}>
        <Link href="/forgot-password/" className={`${primary} no-underline`}>Send a new link</Link>
      </AuthShell>
    )
  }

  if (done) {
    return (
      <AuthShell step="All set" title="Password changed" lead="Sign in with your new password.">
        <Link href="/login/" className={`${primary} no-underline`}>Sign in</Link>
      </AuthShell>
    )
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    if (!strong) return setError('The new password does not meet every rule yet.')
    if (!match) return setError('The two passwords differ.')
    setBusy(true)
    try {
      await resetPassword(token, password)
      setDone(true)
    } catch (err) {
      setError(detailOf(err, 'This link is invalid or has expired. Ask for a new one.'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <AuthShell step="Password reset" title="Choose a new password" lead="It must be strong: every rule below has to pass."
               footer={back}>
      {error && <ErrorNote>{error}</ErrorNote>}
      <form onSubmit={onSubmit} className="flex flex-col gap-4" noValidate>
        <PasswordField label="New password" value={password} onChange={setPassword} autoComplete="new-password" rules id="pw-reset" />
        <div className="flex flex-col gap-1.5">
          <PasswordField label="Confirm new password" value={confirm} onChange={setConfirm} autoComplete="new-password" id="pw-reset-confirm" />
          {confirm.length > 0 && !match && <span className="text-[13px] text-[#ff8a8a]">The two passwords differ.</span>}
        </div>
        <button type="submit" disabled={busy || !strong || !match} className={primary}>{busy ? <Spinner /> : 'Set new password'}</button>
      </form>
    </AuthShell>
  )
}

export default function ResetPasswordPage() {
  return (
    <Suspense>
      <ResetForm />
    </Suspense>
  )
}
