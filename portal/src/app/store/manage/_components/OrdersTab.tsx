'use client'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import clsx from 'clsx'
import { ChevronDown, Loader2, Mail, Phone, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui'
import {
  errorMessage, formatMoney, SELLER_MOVES, storeApi,
  type OrderRequestStatus, type SellerOrderRequest, type Store,
} from '@/lib/storeApi'
import { EmptyState } from './fields'

const LABEL: Record<OrderRequestStatus, string> = {
  PENDING_MERCHANT: 'Awaiting you',
  ACCEPTED: 'Accepted',
  REJECTED: 'Declined',
  SHIPPED: 'Shipped',
  COMPLETED: 'Completed',
  CANCELLED: 'Cancelled',
}

const TONE: Record<OrderRequestStatus, string> = {
  PENDING_MERCHANT: 'border-amber-400/30 bg-amber-400/10 text-amber-300',
  ACCEPTED: 'border-brand-400/30 bg-brand-500/10 text-brand-300',
  SHIPPED: 'border-cyan-400/30 bg-cyan-400/10 text-cyan-300',
  COMPLETED: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300',
  REJECTED: 'border-red-400/30 bg-red-400/10 text-red-300',
  CANCELLED: 'border-white/10 bg-white/[0.04] text-slate-400',
}

// The button for each move, phrased as what it does.
const ACTION: Partial<Record<OrderRequestStatus, { label: string; variant: 'primary' | 'outline' | 'destructive' }>> = {
  ACCEPTED: { label: 'Accept', variant: 'primary' },
  REJECTED: { label: 'Decline', variant: 'outline' },
  SHIPPED: { label: 'Mark shipped', variant: 'primary' },
  CANCELLED: { label: 'Cancel order', variant: 'outline' },
  COMPLETED: { label: 'Mark completed', variant: 'primary' },
}

const FILTERS: { value: '' | OrderRequestStatus; label: string }[] = [
  { value: '', label: 'All' },
  { value: 'PENDING_MERCHANT', label: 'Awaiting you' },
  { value: 'ACCEPTED', label: 'Accepted' },
  { value: 'SHIPPED', label: 'Shipped' },
  { value: 'COMPLETED', label: 'Completed' },
]

const when = (iso: string) => {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso
    : new Intl.DateTimeFormat('en-GB', { dateStyle: 'medium', timeStyle: 'short' }).format(d)
}

export function OrdersTab({ store }: { store: Store }) {
  const [status, setStatus] = useState<'' | OrderRequestStatus>('')
  const orders = useQuery({
    queryKey: ['m2m-order-requests', store.id, status],
    queryFn: () => storeApi.orderRequests(store.id, status),
    refetchInterval: 60_000,
  })
  // Lines carry the name in the buyer's language; the seller also sees their own.
  const products = useQuery({ queryKey: ['m2m-products', store.id], queryFn: () => storeApi.products(store.id) })
  const ownName = new Map((products.data ?? []).map(p => [p.id, p.name]))

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <div role="group" aria-label="Filter by status" className="flex flex-wrap gap-1">
          {FILTERS.map(f => (
            <button key={f.value || 'all'} type="button" aria-pressed={status === f.value}
                    onClick={() => setStatus(f.value)}
                    className={clsx(
                      'h-8 rounded-md border px-3 text-xs font-medium transition-colors',
                      status === f.value
                        ? 'border-brand-500/50 bg-brand-500/10 text-slate-100'
                        : 'border-white/10 text-slate-400 hover:text-slate-200',
                    )}>
              {f.label}
            </button>
          ))}
        </div>
        <Button variant="ghost" size="sm" className="ml-auto" onClick={() => orders.refetch()}
                disabled={orders.isFetching}>
          <RefreshCw className={clsx(orders.isFetching && 'animate-spin')} /> Refresh
        </Button>
      </div>

      <p className="text-xs text-slate-500">
        Buyers send order requests from your storefront. Nothing has been paid: accept a request, then arrange
        payment with the buyer directly. Accepting takes the items out of stock.
      </p>

      {orders.isLoading ? (
        <div className="flex justify-center py-10"><Loader2 className="h-5 w-5 animate-spin text-slate-500" /></div>
      ) : orders.isError ? (
        <p className="text-sm text-red-400" role="alert">{errorMessage(orders.error)}</p>
      ) : !orders.data?.length ? (
        <EmptyState
          title={status ? `No ${LABEL[status].toLowerCase()} requests` : 'No order requests yet'}
          body={`Requests appear here when a buyer sends one from /s/${store.slug}.`}
        />
      ) : (
        <ul className="space-y-3">
          {orders.data.map(o => <OrderCard key={o.id} order={o} storeId={store.id} ownName={ownName} />)}
        </ul>
      )}
    </div>
  )
}

function OrderCard({ order: o, storeId, ownName }: {
  order: SellerOrderRequest; storeId: string; ownName: Map<string, string>
}) {
  const qc = useQueryClient()
  const [open, setOpen] = useState(o.status === 'PENDING_MERCHANT')
  const [note, setNote] = useState('')
  const moves = SELLER_MOVES[o.status] ?? []
  const c = o.contact

  const answer = useMutation({
    mutationFn: (next: OrderRequestStatus) => storeApi.answerOrderRequest(o.id, { status: next, note: note.trim() }),
    onSuccess: updated => {
      setNote('')
      qc.invalidateQueries({ queryKey: ['m2m-order-requests', storeId] })
      toast.success(`Request ${LABEL[updated.status].toLowerCase()}`)
    },
    onError: e => {
      // 409/422: the buyer cancelled or stock ran out meanwhile; show the current state.
      qc.invalidateQueries({ queryKey: ['m2m-order-requests', storeId] })
      toast.error(errorMessage(e))
    },
  })

  const panel = `order-${o.id}`
  return (
    <li className="rounded-xl border border-white/10 bg-dark-800">
      <button type="button" onClick={() => setOpen(v => !v)} aria-expanded={open} aria-controls={panel}
              className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 p-4 text-left">
        <span className={clsx('rounded-md border px-2 py-0.5 text-xs font-semibold', TONE[o.status])}>
          {LABEL[o.status]}
        </span>
        <span className="min-w-0 flex-1 truncate text-sm font-semibold text-slate-100">{c.name}</span>
        <span className="font-mono text-sm text-slate-100">{formatMoney(o.total_minor, o.currency)}</span>
        <span className="w-full text-xs text-slate-500 sm:w-auto">
          {when(o.created_at)} · {o.items.reduce((n, i) => n + i.qty, 0)} items · {o.country}
        </span>
        <ChevronDown className={clsx('h-4 w-4 text-slate-500 transition-transform', open && 'rotate-180')} aria-hidden />
      </button>

      {open && (
        <div id={panel} className="grid gap-4 border-t border-white/[0.06] p-4 md:grid-cols-2">
          <div className="space-y-3">
            <table className="w-full text-sm">
              <caption className="sr-only">Items</caption>
              <tbody className="divide-y divide-white/[0.06]">
                {o.items.map(i => (
                  <tr key={i.product_id}>
                    <td className="py-1.5 pr-2 text-slate-200">
                      {ownName.get(i.product_id) ?? i.name}
                      {ownName.has(i.product_id) && ownName.get(i.product_id) !== i.name && (
                        <span className="block text-xs text-slate-500">{i.name}</span>
                      )}
                    </td>
                    <td className="py-1.5 pr-2 text-right font-mono text-xs text-slate-500">
                      {i.qty} × {formatMoney(i.unit_minor, o.currency)}{i.unit ? ` / ${i.unit}` : ''}
                    </td>
                    <td className="py-1.5 text-right font-mono text-slate-100">{formatMoney(i.line_minor, o.currency)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <dl className="space-y-1 text-sm">
              <div className="flex justify-between"><dt className="text-slate-400">Subtotal</dt>
                <dd className="font-mono">{formatMoney(o.subtotal_minor, o.currency)}</dd></div>
              <div className="flex justify-between"><dt className="text-slate-400">Shipping</dt>
                <dd className="font-mono">{formatMoney(o.shipping_minor, o.currency)}</dd></div>
              <div className="flex justify-between border-t border-white/[0.06] pt-1 font-semibold">
                <dt>Total</dt><dd className="font-mono">{formatMoney(o.total_minor, o.currency)}</dd></div>
              {o.duty_estimate_minor > 0 && (
                <div className="flex justify-between text-xs text-slate-500">
                  <dt>Import duty estimate (buyer pays, not in total)</dt>
                  <dd className="font-mono">≈ {formatMoney(o.duty_estimate_minor, o.currency)}</dd></div>
              )}
            </dl>
            <ol className="space-y-1 text-xs text-slate-500">
              {o.history.map((h, n) => (
                <li key={`${h.at}-${n}`}>
                  <span className="text-slate-300">{LABEL[h.status]}</span> · {when(h.at)} · {h.by}
                  {h.note && <span className="block whitespace-pre-line text-slate-400">{h.note}</span>}
                </li>
              ))}
            </ol>
          </div>

          <div className="space-y-3">
            <address className="space-y-0.5 text-sm not-italic text-slate-300">
              <p className="font-semibold text-slate-100">{c.name}</p>
              <p>{c.address_line1}</p>
              {c.address_line2 && <p>{c.address_line2}</p>}
              <p>{[c.postal_code, c.city].filter(Boolean).join(' ')}</p>
              {c.region && <p>{c.region}</p>}
              <p>{o.country}</p>
              <p className="flex items-center gap-1.5 pt-1">
                <Mail className="h-3.5 w-3.5 text-slate-500" aria-hidden />
                <a href={`mailto:${c.email}`} className="text-brand-400 hover:underline">{c.email}</a>
              </p>
              {c.phone && (
                <p className="flex items-center gap-1.5">
                  <Phone className="h-3.5 w-3.5 text-slate-500" aria-hidden />
                  <a href={`tel:${c.phone.replace(/[^\d+]/g, '')}`} className="hover:underline">{c.phone}</a>
                </p>
              )}
              <p className="pt-1 text-xs text-slate-500">Buyer time zone: {o.buyer_tz} · language: {o.locale}</p>
            </address>
            {o.note && (
              <blockquote className="whitespace-pre-line rounded-lg border border-white/10 bg-dark-900 p-3 text-sm text-slate-300">
                {o.note}
              </blockquote>
            )}

            {moves.length > 0 && (
              <div className="space-y-2 border-t border-white/[0.06] pt-3">
                <label className="block text-xs font-semibold text-slate-400" htmlFor={`${panel}-note`}>
                  Note to the buyer (optional, shown on their request page)
                </label>
                <textarea id={`${panel}-note`} value={note} onChange={e => setNote(e.target.value)} maxLength={500}
                          rows={2}
                          className="w-full rounded-lg border border-white/10 bg-dark-900 px-3 py-2 text-sm
                                     text-slate-100 focus:border-brand-500 focus:outline-none" />
                <div className="flex flex-wrap gap-2">
                  {moves.map(m => {
                    const a = ACTION[m] ?? { label: LABEL[m], variant: 'outline' as const }
                    return (
                      <Button key={m} size="sm" variant={a.variant} disabled={answer.isPending}
                              onClick={() => answer.mutate(m)}>
                        {answer.isPending && answer.variables === m && <Loader2 className="animate-spin" />}
                        {a.label}
                      </Button>
                    )
                  })}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </li>
  )
}
