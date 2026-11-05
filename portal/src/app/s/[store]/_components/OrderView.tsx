'use client'
import { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import { Check, Copy, Loader2, XCircle } from 'lucide-react'
import {
  cancelOrderRequest, formatAt, getOrderRequest, OrderRequestError, tokenFromHash, type OrderError,
} from '@/lib/storefront/orders'
import type { OrderRequestStatus, OrderRequestView } from '@/lib/storefront/types'
import { errorText } from './CheckoutForm'
import { useStorefront } from './StorefrontProvider'

const TONE: Record<OrderRequestStatus, string> = {
  PENDING_MERCHANT: 'border-amber-400/30 bg-amber-400/10 text-amber-300',
  ACCEPTED: 'border-brand-400/30 bg-brand-500/10 text-brand-300',
  SHIPPED: 'border-cyan-400/30 bg-cyan-400/10 text-cyan-300',
  COMPLETED: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300',
  REJECTED: 'border-red-400/30 bg-red-400/10 text-red-300',
  CANCELLED: 'border-white/10 bg-white/[0.04] text-slate-400',
}

type State =
  | { kind: 'loading' }
  | { kind: 'error'; error: OrderError }
  | { kind: 'ok'; order: OrderRequestView }

export function OrderView({ id }: { id: string }) {
  const { t, store, base, locale, money } = useStorefront()
  const [token, setToken] = useState<string | null>(null)
  const [state, setState] = useState<State>({ kind: 'loading' })
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState<OrderError | null>(null)
  const [copied, setCopied] = useState(false)

  // The token is in the fragment, so it is only readable in the browser.
  useEffect(() => { setToken(tokenFromHash(window.location.hash)) }, [])

  const load = useCallback(async (tok: string) => {
    try {
      setState({ kind: 'ok', order: await getOrderRequest(store.slug, id, tok) })
    } catch (err) {
      setState({ kind: 'error', error: err instanceof OrderRequestError ? err.kind : 'failed' })
    }
  }, [store.slug, id])

  useEffect(() => {
    if (token === null) return
    if (!token) { setState({ kind: 'error', error: 'notFound' }); return }
    load(token)
  }, [token, load])

  async function cancel() {
    if (!token || busy || !window.confirm(t.cancelConfirm)) return
    setBusy(true)
    setActionError(null)
    try {
      setState({ kind: 'ok', order: await cancelOrderRequest(store.slug, id, token) })
    } catch (err) {
      const kind = err instanceof OrderRequestError ? err.kind : 'failed'
      setActionError(kind)
      // The seller answered meanwhile: show what they did.
      if (kind === 'invalid') load(token)
    } finally {
      setBusy(false)
    }
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(window.location.href)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch { /* clipboard blocked: the address bar still holds the link */ }
  }

  if (state.kind === 'loading') {
    return (
      <div className="flex justify-center py-16" role="status">
        <Loader2 className="h-6 w-6 animate-spin text-slate-400" aria-hidden />
      </div>
    )
  }
  if (state.kind === 'error') {
    return (
      <div className="mx-auto max-w-xl space-y-4 py-10 text-center">
        <h1 className="text-xl font-bold text-slate-100">{t.orderRequest}</h1>
        <p className="text-sm text-slate-400" role="alert">
          {state.error === 'notFound' ? t.orderNotFound : errorText(t, state.error)}
        </p>
        <Link href={`${base}/`} className="inline-flex h-10 items-center rounded-lg bg-brand-500 px-5 text-sm
                                          font-bold text-dark-950 hover:brightness-110">
          {t.continueShopping}
        </Link>
      </div>
    )
  }

  const o = state.order
  const at = (iso: string) => formatAt(iso, locale, o.buyer_tz)
  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-bold text-slate-100">{t.orderRequest}</h1>
        <span className="font-mono text-xs text-slate-400">{o.id}</span>
        <span className={`rounded-md border px-2 py-0.5 text-xs font-semibold ${TONE[o.status]}`}>
          {t.statuses[o.status]}
        </span>
      </div>

      {o.status === 'PENDING_MERCHANT' && (
        <div className="flex flex-wrap items-center gap-3 rounded-xl border border-emerald-400/25 bg-emerald-400/[0.06] p-3">
          <p className="min-w-0 flex-1 text-sm text-emerald-200">{t.requestSent}</p>
          <button type="button" onClick={copy}
                  className="inline-flex h-9 items-center gap-2 rounded-lg border border-white/10 px-3 text-sm
                             text-slate-200 hover:bg-white/[0.05]">
            {copied ? <Check className="h-4 w-4" aria-hidden /> : <Copy className="h-4 w-4" aria-hidden />}
            {copied ? t.linkCopied : t.copyLink}
          </button>
        </div>
      )}

      <div className="grid gap-5 lg:grid-cols-[1fr_300px]">
        <section aria-labelledby="items-h" className="rounded-xl border border-white/10 bg-dark-800">
          <h2 id="items-h" className="border-b border-white/[0.06] px-4 py-3 text-sm font-bold text-slate-100">
            {t.items}
          </h2>
          <ul className="divide-y divide-white/[0.06]">
            {o.items.map(i => (
              <li key={i.product_id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3 text-sm">
                <span className="min-w-0 flex-1 truncate text-slate-100">{i.name}</span>
                <span className="font-mono text-xs text-slate-400">
                  {i.qty} × {money(i.unit_minor, o.currency)}{i.unit ? ` / ${i.unit}` : ''}
                </span>
                <span className="w-24 text-right font-mono text-slate-100">{money(i.line_minor, o.currency)}</span>
              </li>
            ))}
          </ul>
          <dl className="space-y-2 border-t border-white/[0.06] p-4 text-sm">
            <div className="flex justify-between"><dt className="text-slate-400">{t.subtotal}</dt>
              <dd className="font-mono text-slate-100">{money(o.subtotal_minor, o.currency)}</dd></div>
            <div className="flex justify-between"><dt className="text-slate-400">{t.shipping} ({o.country})</dt>
              <dd className="font-mono text-slate-100">
                {o.shipping_minor === 0 ? t.free : money(o.shipping_minor, o.currency)}
              </dd></div>
            <div className="flex justify-between border-t border-white/[0.06] pt-2 font-semibold">
              <dt className="text-slate-200">{t.total}</dt>
              <dd className="font-mono text-slate-100">{money(o.total_minor, o.currency)}</dd></div>
            {o.duty_estimate_minor > 0 && (
              <>
                <div className="flex justify-between text-xs"><dt className="text-slate-400">{t.dutyEstimate}</dt>
                  <dd className="font-mono text-slate-400">≈ {money(o.duty_estimate_minor, o.currency)}</dd></div>
                <p className="text-xs text-slate-400">{t.dutyExcluded} {t.dutyNote}</p>
              </>
            )}
          </dl>
        </section>

        <aside className="space-y-4 self-start rounded-xl border border-white/10 bg-dark-800 p-4">
          <h2 className="text-sm font-bold text-slate-100">{t.history}</h2>
          <ol className="space-y-3">
            {o.history.map((h, n) => (
              <li key={`${h.at}-${n}`} className="border-l-2 border-white/10 pl-3 text-sm">
                <p className="font-semibold text-slate-200">{t.statuses[h.status]}</p>
                <p className="text-xs text-slate-400">
                  <time dateTime={h.at}>{at(h.at)}</time> · {h.by === 'buyer' ? t.byBuyer : t.bySeller}
                </p>
                {h.note && <p className="mt-1 whitespace-pre-line text-xs text-slate-400">{h.note}</p>}
              </li>
            ))}
          </ol>
          <p className="font-mono text-xs text-slate-400">{o.buyer_tz}</p>
          {o.status === 'PENDING_MERCHANT' && (
            <button type="button" onClick={cancel} disabled={busy}
                    className="flex h-10 w-full items-center justify-center gap-2 rounded-lg border border-red-400/30
                               text-sm font-semibold text-red-300 hover:bg-red-400/10 disabled:opacity-40">
              {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
                    : <XCircle className="h-4 w-4" aria-hidden />}
              {t.cancelRequest}
            </button>
          )}
          <div aria-live="polite" className="text-xs">
            {actionError && <p className="text-red-400" role="alert">{errorText(t, actionError)}</p>}
          </div>
        </aside>
      </div>
    </div>
  )
}
