'use client'
import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import clsx from 'clsx'
import { ChevronDown, Download, Loader2, Mail, Phone, Search, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui'
import {
  errorMessage, formatMoney, storeApi,
  type CustomerSummary, type Store,
} from '@/lib/storeApi'
import { formatWhen } from '@/lib/prefs'
import { EmptyState } from './fields'
import { JournalPanel } from './JournalPanel'

const when = (iso: string) => formatWhen(iso)

const spent = (m: Record<string, number>) =>
  Object.entries(m).map(([cur, v]) => formatMoney(v, cur)).join(' · ') || '—'

export function CustomersTab({ store }: { store: Store }) {
  const [q, setQ] = useState('')
  const [term, setTerm] = useState('')
  // Search on pause, not on every key.
  useEffect(() => {
    const t = setTimeout(() => setTerm(q.trim()), 300)
    return () => clearTimeout(t)
  }, [q])

  const customers = useQuery({
    queryKey: ['m2m-customers', store.id, term],
    queryFn: () => storeApi.customers(store.id, term),
  })

  return (
    <div className="space-y-4">
      <div className="relative max-w-sm">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" aria-hidden />
        <label htmlFor="customer-search" className="sr-only">Search customers</label>
        <input id="customer-search" type="search" value={q} onChange={e => setQ(e.target.value)}
               placeholder="Name, email or tag"
               className="h-9 w-full rounded-md border border-white/10 bg-dark-800 pl-9 pr-3 text-sm text-slate-100 placeholder:text-slate-500 focus:border-brand-500/50 focus:outline-none" />
      </div>

      <p className="text-xs text-slate-500">
        Everyone who sent an order request from your storefront, one entry per email address. Spend counts only
        orders you accepted. Notes and tags are private to you. You can export or erase a customer&apos;s data
        when they ask; erasing removes the customer entry, while the order requests stay as your sales record.
      </p>

      {customers.isLoading ? (
        <div className="flex justify-center py-10"><Loader2 className="h-5 w-5 animate-spin text-slate-500" /></div>
      ) : customers.isError ? (
        <p className="text-sm text-red-400" role="alert">{errorMessage(customers.error)}</p>
      ) : !customers.data?.length ? (
        <EmptyState
          title={term ? 'No customers match' : 'No customers yet'}
          body={term ? 'Try a different name, email or tag.'
                     : `Customers appear here when a buyer sends an order request from /s/${store.slug}.`}
        />
      ) : (
        <ul className="space-y-3">
          {customers.data.map(c => <CustomerCard key={c.id} customer={c} storeId={store.id} />)}
        </ul>
      )}
    </div>
  )
}

function CustomerCard({ customer: c, storeId }: { customer: CustomerSummary; storeId: string }) {
  const [open, setOpen] = useState(false)
  const panel = `customer-${c.id}`
  return (
    <li className="rounded-xl border border-white/10 bg-dark-800">
      <button type="button" onClick={() => setOpen(v => !v)} aria-expanded={open} aria-controls={panel}
              className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 p-4 text-left">
        <span className="min-w-0 flex-1 truncate text-sm font-semibold text-slate-100">{c.name}</span>
        <span className="font-mono text-sm text-slate-100">{spent(c.spent_minor)}</span>
        <span className="w-full text-xs text-slate-400 sm:w-auto">
          {c.orders} {c.orders === 1 ? 'request' : 'requests'} · {c.country} · last {when(c.last_seen_at)}
        </span>
        {c.tags.length > 0 && (
          <span className="flex w-full flex-wrap gap-1 sm:w-auto">
            {c.tags.map(t => (
              <span key={t} className="rounded border border-white/10 px-1.5 py-0.5 text-[11px] text-slate-300">{t}</span>
            ))}
          </span>
        )}
        <ChevronDown className={clsx('h-4 w-4 text-slate-500 transition-transform', open && 'rotate-180')} aria-hidden />
      </button>
      {open && <CustomerDetail id={c.id} storeId={storeId} panel={panel} />}
    </li>
  )
}

function CustomerDetail({ id, storeId, panel }: { id: string; storeId: string; panel: string }) {
  const qc = useQueryClient()
  const card = useQuery({ queryKey: ['m2m-customer', storeId, id], queryFn: () => storeApi.customer(storeId, id) })
  const [notes, setNotes] = useState<string | null>(null)
  const [tags, setTags] = useState<string | null>(null)

  const save = useMutation({
    mutationFn: () => storeApi.updateCustomer(storeId, id, {
      ...(notes !== null ? { notes } : {}),
      ...(tags !== null ? { tags: tags.split(',').map(t => t.trim()).filter(Boolean) } : {}),
    }),
    onSuccess: updated => {
      qc.setQueryData(['m2m-customer', storeId, id], updated)
      qc.invalidateQueries({ queryKey: ['m2m-customers', storeId] })
      setNotes(null); setTags(null)
      toast.success('Saved')
    },
    onError: e => toast.error(errorMessage(e)),
  })

  const exportData = useMutation({
    mutationFn: () => storeApi.exportCustomer(storeId, id),
    onSuccess: data => {
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `customer-${id}.json`
      a.click()
      URL.revokeObjectURL(url)
    },
    onError: e => toast.error(errorMessage(e)),
  })

  const erase = useMutation({
    mutationFn: () => storeApi.eraseCustomer(storeId, id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['m2m-customers', storeId] })
      toast.success('Customer erased')
    },
    onError: e => toast.error(errorMessage(e)),
  })

  if (card.isLoading) {
    return <div id={panel} className="flex justify-center border-t border-white/[0.06] py-6">
      <Loader2 className="h-5 w-5 animate-spin text-slate-500" /></div>
  }
  if (card.isError || !card.data) {
    return <p id={panel} className="border-t border-white/[0.06] p-4 text-sm text-red-400" role="alert">
      {errorMessage(card.error)}</p>
  }
  const c = card.data
  const k = c.contact
  const dirty = notes !== null || tags !== null

  return (
    <div id={panel}>
    <div className="grid gap-4 border-t border-white/[0.06] p-4 md:grid-cols-2">
      <div className="space-y-3 text-sm">
        <address className="not-italic text-slate-200">
          {k.name}<br />
          {k.address_line1}{k.address_line2 ? <><br />{k.address_line2}</> : null}<br />
          {[k.postal_code, k.city].filter(Boolean).join(' ')}{k.region ? `, ${k.region}` : ''} · {c.country}
        </address>
        <p className="flex flex-wrap gap-x-4 gap-y-1 text-slate-300">
          <a href={`mailto:${k.email}`} className="inline-flex items-center gap-1 hover:text-slate-100">
            <Mail className="h-3.5 w-3.5" aria-hidden />{k.email}</a>
          {k.phone && <a href={`tel:${k.phone}`} className="inline-flex items-center gap-1 hover:text-slate-100">
            <Phone className="h-3.5 w-3.5" aria-hidden />{k.phone}</a>}
        </p>
        <table className="w-full text-sm">
          <caption className="mb-1 text-left text-xs font-semibold uppercase tracking-wide text-slate-400">
            Order requests
          </caption>
          <tbody className="divide-y divide-white/[0.06]">
            {c.order_requests.map(o => (
              <tr key={o.id}>
                <td className="py-1.5 pr-2 text-slate-400">{when(o.created_at)}</td>
                <td className="py-1.5 pr-2 text-slate-300">{o.status.replace('_', ' ').toLowerCase()}</td>
                <td className="py-1.5 text-right font-mono text-slate-100">{formatMoney(o.total_minor, o.currency)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="space-y-3">
        <div>
          <label htmlFor={`${panel}-notes`} className="mb-1 block text-xs font-medium text-slate-400">Private notes</label>
          <textarea id={`${panel}-notes`} rows={4} maxLength={2000}
                    value={notes ?? c.notes} onChange={e => setNotes(e.target.value)}
                    className="w-full rounded-md border border-white/10 bg-dark-900 p-2 text-sm text-slate-100 focus:border-brand-500/50 focus:outline-none" />
        </div>
        <div>
          <label htmlFor={`${panel}-tags`} className="mb-1 block text-xs font-medium text-slate-400">
            Tags <span className="text-slate-500">(comma-separated, up to 10)</span>
          </label>
          <input id={`${panel}-tags`} value={tags ?? c.tags.join(', ')} onChange={e => setTags(e.target.value)}
                 className="h-9 w-full rounded-md border border-white/10 bg-dark-900 px-2 text-sm text-slate-100 focus:border-brand-500/50 focus:outline-none" />
        </div>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" onClick={() => save.mutate()} disabled={!dirty || save.isPending}>
            {save.isPending && <Loader2 className="animate-spin" />} Save
          </Button>
          <Button size="sm" variant="ghost" onClick={() => exportData.mutate()} disabled={exportData.isPending}>
            <Download /> Export data
          </Button>
          <Button size="sm" variant="ghost" className="ml-auto text-red-300 hover:text-red-200"
                  disabled={erase.isPending}
                  onClick={() => {
                    if (window.confirm(`Erase ${c.name}? Their customer entry, notes and tags are deleted. `
                      + 'Your order requests stay as your sales record. This cannot be undone.')) erase.mutate()
                  }}>
            <Trash2 /> Erase
          </Button>
        </div>
      </div>
    </div>
    <JournalPanel storeId={storeId} customerId={id} email={k.email} panel={panel} />
    </div>
  )
}
