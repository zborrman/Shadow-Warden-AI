'use client'
import { useMemo, useState } from 'react'
import { FileCode2, FileDown, X } from 'lucide-react'
import { Button } from '@/components/ui'
import { formatMoney, type Store, type StoreProduct } from '@/lib/storeApi'
import {
  hasNonLatin1, productLabelsPdf, productLabelsZpl, type LabelKind, type LabelLayout,
} from '@/lib/labels'

const KINDS: { id: LabelKind; label: string; hint: string }[] = [
  { id: 'gtin', label: 'Product barcode', hint: 'EAN / UPC (GTIN), name and price, for your shelf or shop' },
  { id: 'fnsku', label: 'Amazon FBA (FNSKU)', hint: 'Code 128 of the FNSKU, title and "New", for items you send to FBA' },
]
const LAYOUTS: { id: LabelLayout; label: string; hint: string }[] = [
  { id: 'a4-3x8', label: 'A4 sheet, 24 labels', hint: '63.5 × 33.9 mm (Avery L7159)' },
  { id: 'letter-3x10', label: 'US Letter sheet, 30 labels', hint: '2.625 × 1 in (Avery 5160)' },
  { id: 'roll-50x25', label: 'Label printer roll', hint: '50 × 25 mm, one label per page' },
]

const download = (data: Blob, name: string) => {
  const url = URL.createObjectURL(data)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  URL.revokeObjectURL(url)
}

/** Pick products and copies, download one PDF (or ZPL) of labels. */
export function LabelsPanel({ store, products, onClose }: {
  store: Store; products: StoreProduct[]; onClose: () => void
}) {
  const [kind, setKind] = useState<LabelKind>('gtin')
  const code = (p: StoreProduct) => (kind === 'fnsku' ? p.fnsku : p.gtin)
  // Products that have the code start at one copy; the rest start at zero.
  const [copies, setCopies] = useState<Record<string, number>>({})
  const countOf = (p: StoreProduct) => copies[`${kind}:${p.id}`] ?? (code(p) ? 1 : 0)
  const [layout, setLayout] = useState<LabelLayout>('a4-3x8')
  const [withPrice, setWithPrice] = useState(true)

  const priceOf = (p: StoreProduct) => {
    const pr = p.prices.find(x => x.currency === store.default_currency) ?? p.prices[0]
    return pr ? formatMoney(pr.amount_minor, pr.currency) : ''
  }
  // An FNSKU label without an FNSKU would be a label FBA cannot scan.
  const chosen = products.filter(p => countOf(p) > 0 && (kind === 'gtin' || p.fnsku))
  const total = chosen.reduce((s, p) => s + countOf(p), 0)
  const nonLatin = useMemo(() => chosen.some(p => hasNonLatin1(p.name)), [chosen])
  const items = () => chosen.map(p => ({
    name: p.name, gtin: p.gtin, fnsku: p.fnsku, copies: countOf(p),
    price: withPrice && kind === 'gtin' ? priceOf(p) : '',
  }))

  return (
    <section className="space-y-4 rounded-xl border border-white/10 bg-dark-800 p-4 sm:p-6" aria-labelledby="labels-title">
      <div className="flex items-center justify-between">
        <h3 id="labels-title" className="text-sm font-bold text-slate-100">Print labels</h3>
        <button type="button" onClick={onClose} className="inline-flex items-center gap-1 text-sm text-slate-400 hover:text-slate-200">
          <X className="h-4 w-4" aria-hidden /> Close
        </button>
      </div>

      {[{ name: 'label-kind', options: KINDS, value: kind, set: (v: string) => setKind(v as LabelKind), title: 'Label type' },
        { name: 'label-layout', options: LAYOUTS, value: layout, set: (v: string) => setLayout(v as LabelLayout), title: 'Label size' },
      ].map(group => (
        <fieldset key={group.name} className={`grid gap-2 ${group.options.length === 3 ? 'sm:grid-cols-3' : 'sm:grid-cols-2'}`}>
          <legend className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">{group.title}</legend>
          {group.options.map(o => (
            <label key={o.id} className={`cursor-pointer rounded-lg border p-3 text-sm ${group.value === o.id
              ? 'border-brand-500/60 bg-brand-500/10' : 'border-white/10 hover:border-white/20'}`}>
              <input type="radio" name={group.name} className="sr-only" checked={group.value === o.id}
                     onChange={() => group.set(o.id)} />
              <span className="block font-medium text-slate-100">{o.label}</span>
              <span className="block text-xs text-slate-400">{o.hint}</span>
            </label>
          ))}
        </fieldset>
      ))}

      {kind === 'gtin' && (
        <label className="flex items-center gap-2 text-sm text-slate-300">
          <input type="checkbox" checked={withPrice} onChange={e => setWithPrice(e.target.checked)} className="h-4 w-4 accent-sky-500" />
          Print the price ({store.default_currency})
        </label>
      )}

      <ul className="divide-y divide-white/[0.06] rounded-lg border border-white/10">
        {products.map(p => (
          <li key={p.id} className="flex items-center gap-3 px-3 py-2 text-sm">
            <span className="min-w-0 flex-1 truncate text-slate-100">{p.name}</span>
            <span className="hidden font-mono text-xs text-slate-400 sm:inline">
              {code(p) || (kind === 'fnsku' ? 'no FNSKU' : 'no barcode')}
            </span>
            <label className="sr-only" htmlFor={`copies-${p.id}`}>Copies of {p.name}</label>
            <input id={`copies-${p.id}`} type="number" min={0} max={500} value={countOf(p)}
                   disabled={kind === 'fnsku' && !p.fnsku}
                   onChange={e => setCopies(c => ({ ...c, [`${kind}:${p.id}`]: Math.max(0, Math.min(500, Number(e.target.value) || 0)) }))}
                   className="h-8 w-20 rounded-md border border-white/10 bg-dark-900 px-2 text-right text-sm text-slate-100 disabled:opacity-40" />
          </li>
        ))}
      </ul>

      {kind === 'fnsku' && (
        <p className="text-xs text-slate-400">
          Copy each FNSKU from Seller Central (Inventory → Print item labels) into the product. Since 1 January 2026
          Amazon no longer labels items for you in the US; an unlabelled unit can be refused or lost without reimbursement.
        </p>
      )}
      {nonLatin && (
        <p className="text-xs text-amber-300" role="note">
          Some names use letters outside the Latin alphabet; the label prints those letters as “?”.
        </p>
      )}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-xs text-slate-400">
          {total} {total === 1 ? 'label' : 'labels'}
          {layout !== 'roll-50x25' && total > 0 && (() => {
            const per = layout === 'a4-3x8' ? 24 : 30
            const n = Math.ceil(total / per)
            return ` · ${n} ${n === 1 ? 'sheet' : 'sheets'}`
          })()}.
          {kind === 'gtin' && ' Products without a barcode print with name and price only.'}
        </p>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" disabled={total === 0} title="2 × 1 in, 203 dpi, for Zebra-compatible printers"
                  onClick={() => download(new Blob([productLabelsZpl(items(), kind)], { type: 'text/plain' }), `${store.slug}-${kind}-labels.zpl`)}>
            <FileCode2 /> ZPL
          </Button>
          <Button disabled={total === 0}
                  onClick={() => download(productLabelsPdf(items(), layout, kind).output('blob'), `${store.slug}-${kind}-labels.pdf`)}>
            <FileDown /> Download PDF
          </Button>
        </div>
      </div>
    </section>
  )
}
