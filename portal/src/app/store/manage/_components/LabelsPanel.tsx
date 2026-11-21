'use client'
import { useMemo, useState } from 'react'
import { FileDown, X } from 'lucide-react'
import { Button } from '@/components/ui'
import { formatMoney, type Store, type StoreProduct } from '@/lib/storeApi'
import { hasNonLatin1, productLabelsPdf, type LabelLayout } from '@/lib/labels'

const LAYOUTS: { id: LabelLayout; label: string; hint: string }[] = [
  { id: 'a4-3x8', label: 'A4 sheet, 24 labels', hint: '63.5 × 33.9 mm (Avery L7159 and compatible)' },
  { id: 'roll-50x25', label: 'Label printer roll', hint: '50 × 25 mm, one label per page' },
]

/** Pick products and copies, download one PDF of barcode labels. */
export function LabelsPanel({ store, products, onClose }: {
  store: Store; products: StoreProduct[]; onClose: () => void
}) {
  // Products with a barcode start at one copy each; the rest start at zero.
  const [copies, setCopies] = useState<Record<string, number>>(
    () => Object.fromEntries(products.map(p => [p.id, p.gtin ? 1 : 0])))
  const [layout, setLayout] = useState<LabelLayout>('a4-3x8')
  const [withPrice, setWithPrice] = useState(true)

  const priceOf = (p: StoreProduct) => {
    const pr = p.prices.find(x => x.currency === store.default_currency) ?? p.prices[0]
    return pr ? formatMoney(pr.amount_minor, pr.currency) : ''
  }
  const chosen = products.filter(p => (copies[p.id] ?? 0) > 0)
  const total = chosen.reduce((s, p) => s + copies[p.id], 0)
  const nonLatin = useMemo(() => chosen.some(p => hasNonLatin1(p.name)), [chosen])

  const download = () => {
    const doc = productLabelsPdf(chosen.map(p => ({
      name: p.name, gtin: p.gtin, copies: copies[p.id], price: withPrice ? priceOf(p) : '',
    })), layout)
    doc.save(`${store.slug}-labels.pdf`)
  }

  return (
    <section className="space-y-4 rounded-xl border border-white/10 bg-dark-800 p-4 sm:p-6" aria-labelledby="labels-title">
      <div className="flex items-center justify-between">
        <h3 id="labels-title" className="text-sm font-bold text-slate-100">Print labels</h3>
        <button type="button" onClick={onClose} className="inline-flex items-center gap-1 text-sm text-slate-400 hover:text-slate-200">
          <X className="h-4 w-4" aria-hidden /> Close
        </button>
      </div>

      <fieldset className="grid gap-2 sm:grid-cols-2">
        <legend className="sr-only">Label size</legend>
        {LAYOUTS.map(l => (
          <label key={l.id} className={`cursor-pointer rounded-lg border p-3 text-sm ${layout === l.id
            ? 'border-brand-500/60 bg-brand-500/10' : 'border-white/10 hover:border-white/20'}`}>
            <input type="radio" name="label-layout" className="sr-only" checked={layout === l.id}
                   onChange={() => setLayout(l.id)} />
            <span className="block font-medium text-slate-100">{l.label}</span>
            <span className="block text-xs text-slate-400">{l.hint}</span>
          </label>
        ))}
      </fieldset>

      <label className="flex items-center gap-2 text-sm text-slate-300">
        <input type="checkbox" checked={withPrice} onChange={e => setWithPrice(e.target.checked)} className="h-4 w-4 accent-sky-500" />
        Print the price ({store.default_currency})
      </label>

      <ul className="divide-y divide-white/[0.06] rounded-lg border border-white/10">
        {products.map(p => (
          <li key={p.id} className="flex items-center gap-3 px-3 py-2 text-sm">
            <span className="min-w-0 flex-1 truncate text-slate-100">{p.name}</span>
            <span className="hidden font-mono text-xs text-slate-400 sm:inline">{p.gtin || 'no barcode'}</span>
            <label className="sr-only" htmlFor={`copies-${p.id}`}>Copies of {p.name}</label>
            <input id={`copies-${p.id}`} type="number" min={0} max={500} value={copies[p.id] ?? 0}
                   onChange={e => setCopies(c => ({ ...c, [p.id]: Math.max(0, Math.min(500, Number(e.target.value) || 0)) }))}
                   className="h-8 w-20 rounded-md border border-white/10 bg-dark-900 px-2 text-right text-sm text-slate-100" />
          </li>
        ))}
      </ul>

      {nonLatin && (
        <p className="text-xs text-amber-300" role="note">
          Some names use letters outside the Latin alphabet; the PDF prints those letters as “?”.
        </p>
      )}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-xs text-slate-400">
          {total} {total === 1 ? 'label' : 'labels'}{layout === 'a4-3x8' && total > 0 ? ` · ${Math.ceil(total / 24)} A4 ${Math.ceil(total / 24) === 1 ? 'sheet' : 'sheets'}` : ''}.
          Products without a barcode print with name and price only.
        </p>
        <Button onClick={download} disabled={total === 0}><FileDown /> Download PDF</Button>
      </div>
    </section>
  )
}
