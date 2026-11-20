'use client'
// The portal's settings layout: a panel with an uppercase header and labelled
// rows (label + help on the left, control on the right). Used by Settings and
// the Store Builder so every configuration screen reads the same way.
import { useState } from 'react'
import clsx from 'clsx'
import { Check, Copy } from 'lucide-react'

export function Panel({ title, tone, children }: {
  title: string; tone?: 'danger'; children: React.ReactNode
}) {
  return (
    <section className={clsx('card overflow-hidden', tone === 'danger' && '!border-red-500/25')}>
      <h2 className={clsx('border-b px-5 py-3 text-[11px] font-semibold uppercase tracking-wider',
        tone === 'danger' ? 'border-red-500/20 text-red-300' : 'border-white/[0.06] text-slate-400')}>
        {title}
      </h2>
      <div className="divide-y divide-white/[0.06]">{children}</div>
    </section>
  )
}

export function Row({ label, help, htmlFor, children }: {
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

/** A footer strip for a panel's form: the save button sits on the right. */
export function PanelActions({ children }: { children: React.ReactNode }) {
  return <div className="flex justify-end gap-2 px-5 py-3">{children}</div>
}

export function Switch({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button type="button" role="switch" aria-checked={checked} aria-label={label} onClick={() => onChange(!checked)}
            className={clsx('relative h-6 w-11 rounded-full transition-colors', checked ? 'bg-brand-400' : 'bg-white/10')}>
      <span className={clsx('absolute left-0.5 top-0.5 h-5 w-5 rounded-full bg-white shadow transition-transform',
        checked && 'translate-x-5')} />
    </button>
  )
}

export function CopyField({ value, label }: { value: string; label: string }) {
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

/** Left-hand section list, grouped under uppercase headings (stacks on top on small screens). */
export function SectionNav<T extends string>({ label, groups, current, onSelect }: {
  label: string
  groups: { group: string; items: { id: T; label: string; icon: React.ElementType }[] }[]
  current: T
  onSelect: (id: T) => void
}) {
  return (
    <nav aria-label={label} className="shrink-0 md:w-48">
      <div className="flex gap-4 overflow-x-auto md:block">
        {groups.map(g => (
          <div key={g.group} className="md:mb-4">
            <p className="mb-1 px-3 text-[11px] font-semibold uppercase tracking-wider text-slate-500">{g.group}</p>
            <ul className="flex gap-0.5 md:block md:space-y-0.5">
              {g.items.map(({ id, label: text, icon: Icon }) => (
                <li key={id}>
                  <button type="button" onClick={() => onSelect(id)} aria-current={current === id ? 'page' : undefined}
                          className={clsx('flex w-full items-center gap-2.5 whitespace-nowrap rounded-lg px-3 py-2 text-sm transition-colors',
                            current === id ? 'bg-brand-400/10 font-medium text-slate-100'
                                           : 'text-slate-400 hover:bg-white/[0.04] hover:text-slate-200')}>
                    <Icon className="h-4 w-4" aria-hidden /> {text}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </nav>
  )
}
