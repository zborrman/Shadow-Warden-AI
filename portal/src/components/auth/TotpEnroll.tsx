'use client'
// Required authenticator enrolment (2026-11-27). Every account signs in with two
// steps; one without an authenticator gets a setup_session from /auth/login that
// opens only /auth/totp/enroll/*. The session itself is issued after the first
// code is confirmed. Used by sign-up and by sign-in.
import { useEffect, useState } from 'react'
import { QRCodeSVG } from 'qrcode.react'
import { enrollFinish, enrollStart } from '@/lib/auth'
import { AuthShell, ErrorNote, Spinner, detailOf, field, labelCls, primary } from '@/components/auth/AuthShell'

type Setup = { secret: string; otpauth_uri: string }

export function TotpEnroll({ setupSession, step, lead, onDone }: {
  setupSession: string; step: string; lead: string; onDone: () => void
}) {
  const [setup, setSetup] = useState<Setup | null>(null)
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    enrollStart(setupSession).then(setSetup)
      .catch(err => setError(detailOf(err, 'Could not start the setup. Sign in again.')))
  }, [setupSession])

  async function onEnable(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    if (code.length !== 6) return setError('Enter the 6-digit code your app shows.')
    setBusy(true)
    try {
      await enrollFinish(setupSession, code)
      onDone()
    } catch (err) {
      setCode('')
      setError(detailOf(err, 'That code did not work. Try the current one.'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <AuthShell step={step} title="Protect your account" lead={lead}>
      {error && <ErrorNote>{error}</ErrorNote>}
      <form onSubmit={onEnable} className="flex flex-col gap-4">
        <div className="flex gap-4 items-center p-4 rounded-lg border border-[#232c38] bg-[#151b23] min-h-[146px]">
          {setup ? (
            <>
              <div className="shrink-0 bg-white p-2 rounded">
                <QRCodeSVG value={setup.otpauth_uri} size={112} aria-label="QR code for your authenticator app" />
              </div>
              <div className="flex flex-col gap-1.5 min-w-0">
                <span className="text-[14px] font-semibold">Scan with an authenticator app</span>
                <span className="text-[13px] leading-[18px] text-[#8b98a8]">Or type this key by hand:</span>
                <code className="font-mono text-[13px] tracking-[0.06em] break-all">{setup.secret.replace(/(.{4})/g, '$1 ').trim()}</code>
              </div>
            </>
          ) : !error && <span className="flex items-center gap-2 text-[14px] text-[#8b98a8]"><Spinner /> Preparing your key…</span>}
        </div>
        <label className={labelCls}>6-digit code from the app
          <input value={code} onChange={e => setCode(e.target.value.replace(/[^0-9]/g, '').slice(0, 6))}
                 inputMode="numeric" autoComplete="one-time-code" autoFocus placeholder="000000"
                 className={`${field} min-h-[56px] font-mono text-[24px] tracking-[0.4em] text-center`} />
        </label>
        <button type="submit" disabled={busy || !setup || code.length !== 6} className={primary}>
          {busy ? <Spinner /> : 'Turn on two-step verification'}
        </button>
      </form>
    </AuthShell>
  )
}
