// Sign-in, sign-up and password pages share one frame (design: canvas
// "вход и регистрация", variant 5 "Pulse"): the sales-detector preview on the
// left, the form on the right. The preview is sample data and says so.
import type { ReactNode } from 'react'
import Link from 'next/link'

const BARS = [58, 70, 80, 62, 48, 32, 24, 20, 28, 44, 64, 82, 90, 84, 76, 80, 86, 92, 98, 90, 74, 60, 42, 30,
  24, 20, 26, 40, 60, 78, 88, 92, 86, 82, 90, 94, 96, 88]
const LOW = [24, 20, 16, 18, 14, 16]

const FEED = [
  { t: '14:00', text: 'Afternoon orders 71% under the usual Tuesday. Stock on the top seller reads 0.', tag: 'FLAG', fg: '#ff8a8a', bg: '#2a1015' },
  { t: '09:00', text: 'New offer on 2 of your listings priced 9% below yours.', tag: 'WATCH', fg: '#ffb020', bg: '#2a1f05' },
  { t: 'Mon', text: 'Sales inside the normal range for all 38 listings.', tag: 'OK', fg: '#3ddc97', bg: '#0f2a1f' },
]

function PulseArt() {
  return (
    <section aria-label="Amazon Sales Detector preview"
             className="hidden lg:flex flex-col gap-8 flex-1 min-w-0 px-16 py-14 border-r border-[#232c38]">
      <div className="flex flex-col gap-3 max-w-[580px]">
        <span className="flex items-center gap-2 font-mono text-[12px] font-medium tracking-[0.12em] uppercase text-[#00c2ff]">
          <span aria-hidden="true" className="w-2 h-2 rounded-full bg-[#3ddc97] shadow-[0_0_0_4px_rgba(61,220,151,.18)]" />
          Amazon Sales Detector · watching
        </span>
        <h2 className="m-0 text-[44px] leading-[50px] font-semibold tracking-[-0.02em] text-[#e6edf3]">
          Your store&apos;s pulse, read every hour.
        </h2>
      </div>

      <svg viewBox="0 0 600 120" role="img" className="w-full h-auto block"
           aria-label="Hourly sales pulse for the last 44 hours; the last six hours are low and marked">
        <g fill="#00c2ff">
          {BARS.map((h, i) => <rect key={i} x={i * 12} y={120 - h} width={8} height={h} rx={1} />)}
        </g>
        <g fill="#ff8a8a">
          {LOW.map((h, i) => <rect key={i} x={(BARS.length + i) * 12} y={120 - h} width={8} height={h} rx={1} />)}
        </g>
        <rect x={BARS.length * 12 - 4} y={0} width={LOW.length * 12 + 4} height={120} fill="#ff8a8a" fillOpacity={0.07} />
      </svg>

      <ol aria-label="Detector feed" className="list-none m-0 p-0 flex flex-col rounded-lg border border-[#232c38] bg-[#0d1117]">
        {FEED.map((f, i) => (
          <li key={f.t} className={`grid grid-cols-[64px_1fr_auto] gap-4 items-center px-4 py-3.5 ${i < FEED.length - 1 ? 'border-b border-[#232c38]' : ''}`}>
            <span className="font-mono text-[12px] text-[#8b98a8]">{f.t}</span>
            <span className="text-[14px] leading-5 text-[#e6edf3]">{f.text}</span>
            <span className="font-mono text-[11px] tracking-[0.06em] px-2 py-0.5 rounded-sm" style={{ color: f.fg, background: f.bg }}>{f.tag}</span>
          </li>
        ))}
      </ol>

      <p className="mt-auto mb-0 text-[13px] leading-5 text-[#8b98a8]">
        Sample data. Flags are estimates from the reports you upload, not Amazon&apos;s decision.
      </p>
    </section>
  )
}

export function AuthShell({ step, title, lead, children, footer }: {
  step: string; title: string; lead?: ReactNode; children: ReactNode; footer?: ReactNode
}) {
  return (
    <div translate="no" className="min-h-screen flex bg-[#07090c] text-[#e6edf3] font-sans">
      <PulseArt />
      <main className="flex-1 lg:flex-none lg:w-[520px] flex flex-col justify-center bg-[#0d1117] px-6 sm:px-10 py-12">
        <div className="w-full max-w-[400px] mx-auto flex flex-col gap-6">
          <Link href="/" className="flex items-center gap-2.5 no-underline text-[#e6edf3]">
            <span aria-hidden="true" className="w-[22px] h-[22px] rounded-[3px] bg-[#00c2ff] inline-block" />
            <span className="font-mono font-bold text-[17px]">Shadow Warden</span>
          </Link>
          <div>
            <p className="m-0 mb-1.5 font-mono text-[12px] font-medium tracking-[0.08em] uppercase text-[#8b98a8]">{step}</p>
            <h1 className="m-0 text-[28px] leading-9 font-semibold tracking-[-0.01em]">{title}</h1>
            {lead && <p className="mt-2 mb-0 text-[15px] leading-[22px] text-[#8b98a8]">{lead}</p>}
          </div>
          {children}
          {footer}
          <p className="m-0 pt-4 border-t border-[#232c38] text-[12px] leading-[18px] text-[#8b98a8]">
            Shadow Warden never asks for your Amazon password. Your data stays in the EU.
          </p>
        </div>
      </main>
    </div>
  )
}

export const field =
  'w-full box-border min-h-[46px] px-3.5 rounded-lg border border-[#5c6b7e] bg-[#07090c] text-[15px] text-[#e6edf3] ' +
  'placeholder:text-[#5c6b7e] focus:outline-none focus:border-[#00c2ff] focus:ring-2 focus:ring-[#00c2ff]/30'
export const labelCls = 'flex flex-col gap-1.5 text-[14px] font-medium'
export const primary =
  'w-full min-h-[48px] rounded-lg border border-[#00c2ff] bg-[#00c2ff] text-[#0b1220] text-[15px] font-semibold cursor-pointer ' +
  'disabled:cursor-not-allowed disabled:bg-[#232c38] disabled:border-[#232c38] disabled:text-[#8b98a8] ' +
  'flex items-center justify-center'
export const secondary =
  'w-full min-h-[44px] rounded-lg border border-[#5c6b7e] bg-transparent text-[#e6edf3] text-[14px] font-semibold cursor-pointer'
export const textLink = 'font-semibold text-[#7fd3ff] hover:underline'

export function ErrorNote({ children }: { children: ReactNode }) {
  return (
    <p role="alert" className="m-0 px-3 py-2.5 rounded-lg border border-[#c8102e] bg-[#2a1015] text-[#ff8a8a] text-[14px] leading-5">
      {children}
    </p>
  )
}

export function Spinner() {
  return <span aria-hidden="true" className="w-4 h-4 border-2 border-[#0b1220]/30 border-t-[#0b1220] rounded-full animate-spin" />
}

/** A server error message, whatever shape FastAPI gave it. */
export function detailOf(e: unknown, fallback: string): string {
  const d = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof d === 'string') return d
  if (Array.isArray(d) && d[0] && typeof (d[0] as { msg?: unknown }).msg === 'string') return (d[0] as { msg: string }).msg
  return fallback
}
