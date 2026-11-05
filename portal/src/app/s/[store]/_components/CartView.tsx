'use client'
import { useEffect, useState } from 'react'
import Link from 'next/link'
import { Loader2, Package, Trash2, Truck } from 'lucide-react'
import { MAX_QTY, useCart } from '@/lib/storefront/cart'
import { fmt } from '@/lib/storefront/i18n'
import type { Feed, ShippingQuote } from '@/lib/storefront/types'
import { CheckoutForm } from './CheckoutForm'
import { imageSrc, PUBLIC_API } from './Price'
import { useStorefront } from './StorefrontProvider'

type QuoteState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'none' }
  | { kind: 'error' }
  | { kind: 'ok'; quote: ShippingQuote; country: string }

export function CartView({ feed }: { feed: Feed }) {
  const { t, base, store, currency, money, nameOf, country: initialCountry } = useStorefront()
  const cart = useCart(store.slug)
  const [country, setCountry] = useState(initialCountry)
  const [quote, setQuote] = useState<QuoteState>({ kind: 'idle' })
  // Set once a request is placed: the cart empties while the page navigates away.
  const [leaving, setLeaving] = useState(false)

  const byId = new Map(feed.products.map(p => [p.id, p]))
  const lines = cart.lines.flatMap(l => {
    const p = byId.get(l.id)
    if (!p) return []
    const price = p.prices.find(x => x.currency === currency)
    return [{ ...l, product: p, unitMinor: price?.amount_minor ?? null }]
  })
  const priced = lines.every(l => l.unitMinor !== null)
  const subtotal = priced ? lines.reduce((s, l) => s + (l.unitMinor ?? 0) * l.qty, 0) : null
  const countryOk = /^[A-Za-z]{2}$/.test(country.trim())

  // A quote is for one subtotal, currency and country; any change makes it stale.
  useEffect(() => { setQuote({ kind: 'idle' }) }, [subtotal, currency, country])

  async function calculate() {
    if (subtotal === null || !countryOk) return
    setQuote({ kind: 'loading' })
    const dest = country.trim().toUpperCase()
    const qs = new URLSearchParams({ country: dest, currency, subtotal_minor: String(subtotal) })
    try {
      const res = await fetch(`${PUBLIC_API}/m2m-store/storefront/${store.slug}/shipping/quote?${qs}`)
      if (res.status === 404) return setQuote({ kind: 'none' })
      if (!res.ok) return setQuote({ kind: 'error' })
      setQuote({ kind: 'ok', quote: await res.json(), country: dest })
    } catch {
      setQuote({ kind: 'error' })
    }
  }

  if (leaving) {
    return (
      <div className="flex justify-center py-16" role="status">
        <Loader2 className="h-6 w-6 animate-spin text-slate-400" aria-hidden />
      </div>
    )
  }

  if (lines.length === 0) {
    return (
      <div className="mx-auto max-w-xl space-y-4 py-10 text-center">
        <h1 className="text-xl font-bold text-slate-100">{t.cart}</h1>
        <p className="text-sm text-slate-400">{t.cartEmpty}</p>
        <Link href={`${base}/`} className="inline-flex h-10 items-center rounded-lg bg-brand-500 px-5 text-sm
                                          font-bold text-dark-950 hover:brightness-110">
          {t.continueShopping}
        </Link>
      </div>
    )
  }

  const q = quote.kind === 'ok' ? quote.quote : null
  return (
    <div className="space-y-5">
      <h1 className="text-xl font-bold text-slate-100">{t.cart}</h1>
      <div className="grid gap-6 lg:grid-cols-[1fr_340px]">
        <ul className="divide-y divide-white/[0.06] rounded-xl border border-white/10 bg-dark-800">
          {lines.map(l => {
            const name = nameOf(l.product)
            const img = l.product.images[0]
            const max = Math.min(l.product.available, MAX_QTY)
            return (
              <li key={l.id} className="flex flex-wrap items-center gap-3 p-3 sm:flex-nowrap">
                <div className="h-16 w-16 shrink-0 overflow-hidden rounded-lg bg-dark-700">
                  {img
                    // eslint-disable-next-line @next/next/no-img-element
                    ? <img src={imageSrc(img.url)} alt="" loading="lazy" className="h-full w-full object-cover" />
                    : <div className="flex h-full items-center justify-center text-slate-400"><Package className="h-6 w-6" aria-hidden /></div>}
                </div>
                <div className="min-w-0 flex-1">
                  <Link href={`${base}/p/${l.id}/`} className="block truncate text-sm font-semibold text-slate-100 hover:underline">
                    {name}
                  </Link>
                  <p className="text-xs text-slate-400">
                    {l.unitMinor !== null
                      ? `${money(l.unitMinor, currency)}${l.product.unit ? ` ${fmt(t.perUnit, { unit: l.product.unit })}` : ''}`
                      : <span className="text-amber-400">{fmt(t.missingCurrency, { cur: currency })}</span>}
                  </p>
                </div>
                <label className="text-xs text-slate-400">
                  <span className="sr-only">{t.quantity}: {name}</span>
                  <input type="number" min={1} max={Math.max(max, 1)} value={l.qty}
                         onChange={e => cart.set(l.id, Math.max(1, Math.min(Number(e.target.value) || 1, Math.max(max, 1))))}
                         className="h-9 w-20 rounded-lg border border-white/10 bg-dark-900 px-2 font-mono text-sm
                                    text-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-400" />
                </label>
                <span className="w-24 text-right font-mono text-sm text-slate-100">
                  {l.unitMinor !== null ? money(l.unitMinor * l.qty, currency) : '—'}
                </span>
                <button type="button" onClick={() => cart.remove(l.id)} aria-label={`${t.remove}: ${name}`}
                        className="flex h-9 w-9 items-center justify-center rounded-lg text-slate-400
                                   hover:bg-white/[0.05] hover:text-red-400">
                  <Trash2 className="h-4 w-4" />
                </button>
              </li>
            )
          })}
        </ul>

        <aside className="space-y-4 self-start rounded-xl border border-white/10 bg-dark-800 p-4">
          {subtotal === null ? (
            <p className="text-sm text-amber-400" role="status">{fmt(t.missingCurrency, { cur: currency })}</p>
          ) : (
            <>
              <dl className="space-y-2 text-sm">
                <div className="flex justify-between"><dt className="text-slate-400">{t.subtotal}</dt>
                  <dd className="font-mono text-slate-100">{money(subtotal, currency)}</dd></div>
                {q && (
                  <>
                    <div className="flex justify-between"><dt className="text-slate-400">{t.shipping}</dt>
                      <dd className="font-mono text-slate-100">
                        {q.shipping_minor === 0 ? t.free : money(q.shipping_minor, currency)}
                      </dd></div>
                    <div className="flex justify-between border-t border-white/[0.06] pt-2 font-semibold">
                      <dt className="text-slate-200">{t.total}</dt>
                      <dd className="font-mono text-slate-100">{money(subtotal + q.shipping_minor, currency)}</dd></div>
                    {q.duty_estimate_minor > 0 && (
                      <div className="flex justify-between text-xs"><dt className="text-slate-400">{t.dutyEstimate}</dt>
                        <dd className="font-mono text-slate-400">≈ {money(q.duty_estimate_minor, currency)}</dd></div>
                    )}
                  </>
                )}
              </dl>

              <form className="space-y-2" onSubmit={e => { e.preventDefault(); calculate() }}>
                <label className="block text-xs font-semibold text-slate-400">
                  {t.country}
                  <input value={country} onChange={e => setCountry(e.target.value.slice(0, 2))} maxLength={2}
                         autoComplete="country" spellCheck={false} placeholder="DE"
                         className="mt-1 h-10 w-full rounded-lg border border-white/10 bg-dark-900 px-3 font-mono
                                    text-sm uppercase text-slate-100 focus:outline-none
                                    focus-visible:ring-2 focus-visible:ring-brand-400" />
                  <span className="mt-1 block font-normal text-slate-400">{t.countryHint}</span>
                </label>
                <button type="submit" disabled={!countryOk || quote.kind === 'loading'}
                        className="flex h-10 w-full items-center justify-center gap-2 rounded-lg border
                                   border-brand-400/40 text-sm font-semibold text-brand-300
                                   hover:bg-brand-500/10 disabled:opacity-40">
                  {quote.kind === 'loading' ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
                                            : <Truck className="h-4 w-4" aria-hidden />}
                  {t.calculateShipping}
                </button>
                <div aria-live="polite" className="text-xs">
                  {quote.kind === 'none' && <p className="text-amber-400">{fmt(t.noZone, { cur: currency })}</p>}
                  {quote.kind === 'error' && <p className="text-red-400">{t.loadFailed}</p>}
                  {q && <p className="text-slate-400">{fmt(t.delivery, { min: q.min_days, max: q.max_days })}</p>}
                  {q && q.duty_estimate_minor > 0 && (
                    <p className="mt-1 text-slate-400">{t.dutyExcluded} {t.dutyNote}</p>
                  )}
                </div>
              </form>
            </>
          )}

          <div className="border-t border-white/[0.06] pt-4">
            {quote.kind === 'ok' && subtotal !== null ? (
              <CheckoutForm items={lines.map(l => ({ product_id: l.id, qty: l.qty }))}
                            country={quote.country}
                            onPlaced={() => { setLeaving(true); cart.clear() }} />
            ) : (
              <p className="text-xs text-slate-400">{t.quoteFirst}</p>
            )}
          </div>
        </aside>
      </div>
    </div>
  )
}
