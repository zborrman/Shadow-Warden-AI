'use client'
import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { Loader2, Send } from 'lucide-react'
import {
  buyerTimezone, OrderRequestError, placeOrderRequest, type OrderError,
} from '@/lib/storefront/orders'
import type { Dict } from '@/lib/storefront/i18n'
import { useStorefront } from './StorefrontProvider'

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/

export function errorText(t: Dict, kind: OrderError): string {
  switch (kind) {
    case 'tooMany': return t.errTooMany
    case 'conflict': return t.errConflict
    case 'invalid': return t.errInvalid
    case 'unavailable': return t.errUnavailable
    case 'notFound': return t.storeClosed
    default: return t.loadFailed
  }
}

const EMPTY = {
  name: '', email: '', phone: '', address_line1: '', address_line2: '',
  city: '', postal_code: '', region: '', note: '',
}
type Fields = typeof EMPTY

/**
 * The buyer's details for an order request. Nothing is charged: the seller
 * answers the request and arranges payment (owner decision, until stage M7).
 */
export function CheckoutForm(
  { items, country, onPlaced }: {
    items: { product_id: string; qty: number }[]
    country: string
    onPlaced: () => void
  },
) {
  const { t, store, currency, locale, base } = useStorefront()
  const router = useRouter()
  const [f, setF] = useState<Fields>(EMPTY)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<OrderError | null>(null)

  const set = (k: keyof Fields) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setF(prev => ({ ...prev, [k]: e.target.value }))
  const valid = f.name.trim() && EMAIL_RE.test(f.email.trim()) && f.address_line1.trim() && f.city.trim()

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!valid || busy) return
    setBusy(true)
    setError(null)
    const { note, ...contact } = f
    try {
      const placed = await placeOrderRequest(store.slug, {
        items, currency, country, locale, timezone: buyerTimezone(),
        note: note.trim(),
        contact: Object.fromEntries(
          Object.entries(contact).map(([k, v]) => [k, v.trim()]),
        ) as typeof contact,
      })
      // The fragment is never sent to a server; the page reads the token from it.
      router.push(`${base}/order/${placed.id}#t=${placed.buyer_token}`)
      onPlaced()
    } catch (err) {
      setError(err instanceof OrderRequestError ? err.kind : 'failed')
      setBusy(false)
    }
  }

  const input = `mt-1 h-10 w-full rounded-lg border border-white/10 bg-dark-900 px-3 text-sm text-slate-100
                 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-400`
  const label = 'block text-xs font-semibold text-slate-400'
  const opt = <span className="font-normal text-slate-500"> ({t.optional})</span>

  return (
    <form onSubmit={submit} className="space-y-3">
      <h2 className="text-sm font-bold text-slate-100">{t.yourDetails}</h2>
      <label className={label}>{t.fullName}
        <input className={input} value={f.name} onChange={set('name')} maxLength={120} required autoComplete="name" />
      </label>
      <label className={label}>{t.email}
        <input className={input} type="email" value={f.email} onChange={set('email')} maxLength={254} required
               autoComplete="email" spellCheck={false} />
      </label>
      <label className={label}>{t.phone}{opt}
        <input className={input} type="tel" value={f.phone} onChange={set('phone')} maxLength={40} autoComplete="tel" />
      </label>
      <label className={label}>{t.address1}
        <input className={input} value={f.address_line1} onChange={set('address_line1')} maxLength={200} required
               autoComplete="address-line1" />
      </label>
      <label className={label}>{t.address2}{opt}
        <input className={input} value={f.address_line2} onChange={set('address_line2')} maxLength={200}
               autoComplete="address-line2" />
      </label>
      <div className="grid grid-cols-2 gap-2">
        <label className={label}>{t.postalCode}{opt}
          <input className={input} value={f.postal_code} onChange={set('postal_code')} maxLength={20}
                 autoComplete="postal-code" />
        </label>
        <label className={label}>{t.city}
          <input className={input} value={f.city} onChange={set('city')} maxLength={100} required
                 autoComplete="address-level2" />
        </label>
      </div>
      <label className={label}>{t.region}{opt}
        <input className={input} value={f.region} onChange={set('region')} maxLength={100}
               autoComplete="address-level1" />
      </label>
      <label className={label}>{t.noteToSeller}{opt}
        <textarea value={f.note} onChange={set('note')} maxLength={1000} rows={3}
                  className={`${input} h-auto py-2`} />
      </label>

      <p className="text-xs text-slate-500">{t.requestIntro}</p>
      <button type="submit" disabled={!valid || busy}
              className="flex h-10 w-full items-center justify-center gap-2 rounded-lg bg-brand-500 text-sm
                         font-bold text-dark-950 hover:brightness-110 disabled:opacity-40">
        {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <Send className="h-4 w-4" aria-hidden />}
        {t.sendRequest}
      </button>
      <div aria-live="polite" className="text-xs">
        {error && <p className="text-red-400" role="alert">{errorText(t, error)}</p>}
      </div>
    </form>
  )
}
