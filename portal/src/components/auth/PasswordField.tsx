'use client'
import { useId, useState } from 'react'
import { passwordLevel, passwordRules } from '@/lib/password'

const LEVEL = ['—', 'Weak', 'Fair', 'Good', 'Strong'] as const
const LEVEL_COLOR = ['#5c6b7e', '#ff8a8a', '#ffb020', '#e3c454', '#3ddc97']

/** Password input with show/hide. With `rules`, it also draws the strength meter and checklist. */
export function PasswordField({ label, value, onChange, autoComplete, email = '', rules = false, id }: {
  label: string
  value: string
  onChange: (v: string) => void
  autoComplete: string
  email?: string
  rules?: boolean
  id?: string
}) {
  const [show, setShow] = useState(false)
  const auto = useId()
  const inputId = id ?? auto
  const list = passwordRules(value, email)
  const level = passwordLevel(list, value)
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={inputId} className="text-[14px] font-medium">{label}</label>
      <div className="flex rounded-lg border border-[#5c6b7e] bg-[#07090c] overflow-hidden focus-within:border-[#00c2ff] focus-within:ring-2 focus-within:ring-[#00c2ff]/30">
        <input id={inputId} type={show ? 'text' : 'password'} autoComplete={autoComplete} value={value}
               onChange={e => onChange(e.target.value)}
               aria-describedby={rules ? `${inputId}-rules` : undefined}
               className="flex-1 min-w-0 min-h-[44px] px-3.5 border-0 bg-transparent text-[15px] text-[#e6edf3] focus:outline-none" />
        <button type="button" onClick={() => setShow(!show)} aria-label={show ? 'Hide password' : 'Show password'}
                className="min-w-[64px] px-3.5 border-0 border-l border-[#232c38] bg-transparent text-[13px] font-semibold text-[#8b98a8] cursor-pointer">
          {show ? 'Hide' : 'Show'}
        </button>
      </div>
      {rules && (
        <>
          <div aria-hidden="true" className="grid grid-cols-4 gap-1 mt-1">
            {[1, 2, 3, 4].map(i => (
              <span key={i} className="h-1 rounded-sm" style={{ background: i <= level ? LEVEL_COLOR[level] : '#232c38' }} />
            ))}
          </div>
          <p className="m-0 text-[13px] text-[#8b98a8]" aria-live="polite">
            Strength: <strong style={{ color: level ? LEVEL_COLOR[level] : '#8b98a8' }}>{LEVEL[level]}</strong>
          </p>
          <ul id={`${inputId}-rules`} className="list-none m-0 mt-1 p-0 grid grid-cols-2 gap-x-3 gap-y-1">
            {list.map(r => (
              <li key={r.label} className="flex gap-1.5 items-center text-[13px] leading-[18px]"
                  style={{ color: r.ok ? '#3ddc97' : '#8b98a8' }}>
                <span aria-hidden="true" className="font-mono w-3">{r.ok ? '✓' : '·'}</span>
                <span>{r.label}<span className="sr-only">{r.ok ? ' — met' : ' — not met'}</span></span>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  )
}
