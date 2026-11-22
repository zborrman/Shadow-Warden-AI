'use client'
// R8.5d: catalog check. The seller uploads their own listings export (Amazon's
// Active Listings Report, or a Shopify / generic CSV). The file is read in the
// browser; only product names and descriptions are sent to the text check. The
// report holds the seller's own products, never a buyer.
import { useState } from 'react'
import { FileDown, Loader2, Upload } from 'lucide-react'
import { Button } from '@/components/ui'
import { Panel } from '@/components/ui/settings'
import { checkGtin } from '@/lib/gtin'
import { errorMessage, storeApi } from '@/lib/storeApi'

type Row = Record<string, string>
type Issue = { sku: string; name: string; kind: string; detail: string }

/** Tab- or comma-separated text into rows keyed by lower-case header. Handles quoted fields. */
export function parseTable(text: string): Row[] {
  const delim = (text.split('\n', 1)[0].match(/\t/g)?.length ?? 0) > 0 ? '\t' : ','
  const rows: string[][] = []
  let cell = '', row: string[] = [], quoted = false
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { cell += '"'; i++ }
      else if (c === '"') quoted = false
      else cell += c
    } else if (c === '"' && cell === '') quoted = true
    else if (c === delim) { row.push(cell); cell = '' }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++
      row.push(cell); cell = ''
      if (row.some(v => v !== '')) rows.push(row)
      row = []
    } else cell += c
  }
  row.push(cell)
  if (row.some(v => v !== '')) rows.push(row)
  const [head, ...body] = rows
  if (!head) return []
  const keys = head.map(h => h.trim().toLowerCase())
  return body.map(r => Object.fromEntries(keys.map((k, i) => [k, (r[i] ?? '').trim()])))
}

const pick = (r: Row, names: string[]) => names.map(n => r[n]).find(v => v) ?? ''

/** A GTIN to check, when the export carries one (Amazon: product-id with type 3 = UPC, 4 = EAN). */
function gtinOf(r: Row): string {
  if (r['product-id'] && ['3', '4'].includes(r['product-id-type'])) return r['product-id']
  return pick(r, ['barcode', 'variant barcode', 'gtin', 'ean', 'upc'])
}

export function CatalogCheckTab() {
  const [file, setFile] = useState('')
  const [busy, setBusy] = useState(false)
  const [rows, setRows] = useState(0)
  const [issues, setIssues] = useState<Issue[] | null>(null)
  const [error, setError] = useState('')

  async function run(f: File) {
    setFile(f.name); setBusy(true); setError(''); setIssues(null)
    try {
      const data = parseTable(await f.text())
      if (data.length === 0) throw new Error('No rows found. Upload a tab- or comma-separated export with a header row.')
      if (data.length > 2000) throw new Error('Up to 2,000 rows at a time. Split the file and check each part.')
      setRows(data.length)
      const found: Issue[] = []
      const items = data.map(r => ({
        sku: pick(r, ['seller-sku', 'sku', 'variant sku', 'handle']),
        name: pick(r, ['item-name', 'title', 'name', 'product name']),
        description: pick(r, ['item-description', 'description', 'body (html)', 'body']),
        gtin: gtinOf(r),
      }))
      items.forEach(it => {
        if (!it.gtin) return
        const g = checkGtin(it.gtin)
        if (g.error) found.push({ sku: it.sku, name: it.name, kind: 'Barcode', detail: `${it.gtin}: ${g.error}` })
      })
      const lint = await storeApi.lintListings(items.map(i => ({ name: i.name.slice(0, 500), description: i.description.slice(0, 8000) })))
      lint.forEach((row, i) => row.forEach(f => found.push({
        sku: items[i].sku, name: items[i].name, kind: 'Claim',
        detail: `"${f.term}" in the ${f.field} — ${f.basis}${f.suggestion ? ` Try "${f.suggestion}".` : ''}`,
      })))
      setIssues(found)
    } catch (e) {
      setError(e instanceof Error && !('response' in e) ? e.message : errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const download = () => {
    const esc = (v: string) => `"${v.replace(/"/g, '""')}"`
    const csv = ['sku,product,issue,detail', ...(issues ?? []).map(i => [i.sku, i.name, i.kind, i.detail].map(esc).join(','))].join('\n')
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
    const a = document.createElement('a'); a.href = url; a.download = 'catalog-check.csv'; a.click(); URL.revokeObjectURL(url)
  }

  const affected = new Set(issues?.map(i => i.sku || i.name)).size
  return (
    <div className="space-y-5">
      <Panel title="Catalog check">
        <div className="space-y-3 px-5 py-4 text-sm text-slate-300">
          <p>
            Upload your listings export: in Seller Central, <b>Reports → Inventory Reports → Active Listings Report</b>,
            or a product CSV from Shopify or your shop. We check barcodes (GS1 check digit) and flag claims in titles and
            descriptions that need proof or a registration.
          </p>
          <label className="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-white/15 px-4 py-2 text-sm text-slate-100 hover:border-white/30">
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" aria-hidden />}
            {file || 'Choose a .txt, .tsv or .csv file'}
            <input type="file" accept=".txt,.tsv,.csv,text/plain,text/csv" className="sr-only" disabled={busy}
                   onChange={e => { const f = e.target.files?.[0]; if (f) run(f) }} />
          </label>
          <p className="text-xs text-slate-500">
            The file is read in your browser; only titles and descriptions are sent to the text check. Not checked here:
            FNSKU labels, images, and EU product-safety details, which this export does not contain.
          </p>
          {error && <p className="text-sm text-red-400" role="alert">{error}</p>}
        </div>
      </Panel>

      {issues && (
        <Panel title="Result">
          <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4">
            <p className={`text-sm ${issues.length ? 'text-amber-200' : 'text-emerald-300'}`} role="status">
              {rows} {rows === 1 ? 'product' : 'products'} checked ·{' '}
              {issues.length ? `${issues.length} issues in ${affected} ${affected === 1 ? 'product' : 'products'}` : 'no issues found'}
            </p>
            {issues.length > 0 && <Button size="sm" variant="outline" onClick={download}><FileDown /> Download CSV</Button>}
          </div>
          {issues.length > 0 && (
            <ul className="divide-y divide-white/[0.06]">
              {issues.slice(0, 200).map((i, n) => (
                <li key={n} className="px-5 py-3 text-sm">
                  <p className="text-slate-100"><span className="mr-2 rounded bg-white/10 px-1.5 py-0.5 text-[11px]">{i.kind}</span>
                    {i.name || i.sku}{i.sku && i.name ? <span className="text-slate-500"> · {i.sku}</span> : null}</p>
                  <p className="mt-1 text-xs text-slate-400">{i.detail}</p>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      )}
    </div>
  )
}
