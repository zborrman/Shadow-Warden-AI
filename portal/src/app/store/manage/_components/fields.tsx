'use client'
import { useId } from 'react'
import type { InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from 'react'
import clsx from 'clsx'

const control =
  'w-full rounded-lg bg-dark-800 border border-white/10 px-3 py-2 text-sm text-slate-100 ' +
  'placeholder:text-slate-600 focus:outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 ' +
  'transition-[border-color,box-shadow] disabled:opacity-50'

export function Field({ label, hint, error, children, id }: {
  label: string; hint?: string; error?: string; children: (id: string) => ReactNode; id?: string
}) {
  const auto = useId()
  const fid = id ?? auto
  return (
    <div className="space-y-1.5">
      <label htmlFor={fid} className="block text-xs font-semibold text-slate-400">{label}</label>
      {children(fid)}
      {error
        ? <p className="text-xs text-red-400" role="alert">{error}</p>
        : hint ? <p className="text-xs text-slate-500">{hint}</p> : null}
    </div>
  )
}

export function TextInput({ label, hint, error, ...props }:
  InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string; error?: string }) {
  return (
    <Field label={label} hint={hint} error={error}>
      {id => <input id={id} aria-invalid={Boolean(error) || undefined} className={control} {...props} />}
    </Field>
  )
}

export function TextArea({ label, hint, ...props }:
  TextareaHTMLAttributes<HTMLTextAreaElement> & { label: string; hint?: string }) {
  return (
    <Field label={label} hint={hint}>
      {id => <textarea id={id} rows={3} className={clsx(control, 'resize-y')} {...props} />}
    </Field>
  )
}

export function SelectInput({ label, hint, children, ...props }:
  SelectHTMLAttributes<HTMLSelectElement> & { label: string; hint?: string }) {
  return (
    <Field label={label} hint={hint}>
      {id => <select id={id} className={control} {...props}>{children}</select>}
    </Field>
  )
}

/** A set of toggle chips (currencies, locales). `locked` values cannot be removed. */
export function ChipSet({ legend, options, value, onChange, locked = [] }: {
  legend: string
  options: { value: string; label: string }[]
  value: string[]
  onChange: (next: string[]) => void
  locked?: string[]
}) {
  return (
    <fieldset className="space-y-1.5">
      <legend className="text-xs font-semibold text-slate-400 mb-1.5">{legend}</legend>
      <div className="flex flex-wrap gap-2">
        {options.map(o => {
          const on = value.includes(o.value)
          const fixed = locked.includes(o.value)
          return (
            <button
              key={o.value}
              type="button"
              aria-pressed={on}
              disabled={fixed}
              title={fixed ? 'Required' : undefined}
              onClick={() => onChange(on ? value.filter(v => v !== o.value) : [...value, o.value])}
              className={clsx(
                'rounded-lg border px-3 py-1.5 text-xs font-medium transition-[border-color,background-color,color]',
                on ? 'border-brand-500/60 bg-brand-500/10 text-brand-300'
                   : 'border-white/10 text-slate-400 hover:border-white/20 hover:text-slate-200',
                fixed && 'cursor-default opacity-80',
              )}
            >
              {o.label}
            </button>
          )
        })}
      </div>
    </fieldset>
  )
}

export function EmptyState({ title, body, action }: { title: string; body: string; action?: ReactNode }) {
  return (
    <div className="rounded-xl border border-dashed border-white/10 px-6 py-10 text-center">
      <p className="text-sm font-semibold text-slate-200">{title}</p>
      <p className="mt-1 text-sm text-slate-500">{body}</p>
      {action && <div className="mt-4 flex justify-center">{action}</div>}
    </div>
  )
}
