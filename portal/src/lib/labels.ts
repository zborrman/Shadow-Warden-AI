'use client'
// R8.4: printable labels, made in the browser. Nothing is sent anywhere: the
// product data is already on the page, and a shipping label carries the
// buyer's address, which should not travel further than it must.
//
// Barcodes are drawn as vector bars, never as a picture: a raster symbol is
// resampled by the printer driver and can blur a bar into its neighbour.
// jsPDF's built-in fonts are WinAnsi only; other letters print as "?" and the
// UI says so.
import { jsPDF } from 'jspdf'
import JsBarcode from 'jsbarcode'
import { barcodeFormat } from '@/lib/gtin'

export type LabelLayout = 'a4-3x8' | 'letter-3x10' | 'roll-50x25'
export type LabelKind = 'gtin' | 'fnsku'

export interface ProductLabel { name: string; price: string; gtin: string; fnsku: string; copies: number }

export interface ShippingLabel {
  from: string
  to: { name: string; line1: string; line2: string; city: string; postal: string; region: string; country: string; phone: string }
  reference: string
  items: string
}

// The standard fonts use WinAnsiEncoding: Latin-1 plus these (€, curly quotes, dashes...).
const WIN_ANSI_EXTRA = new Set(Array.from('€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ'))
const printable = (c: string) => c.charCodeAt(0) <= 0xff || WIN_ANSI_EXTRA.has(c)

/** Printable text, or '?' per missing glyph, so a gap is visible instead of silently mangled. */
const latin1 = (s: string) => Array.from(s).map(c => (printable(c) ? c : '?')).join('')

export const hasNonLatin1 = (s: string) => Array.from(s).some(c => !printable(c))

/** The modules of a symbol ("1" = bar), from jsbarcode's encoder, without drawing anything. */
function modules(text: string, format: string): string | null {
  const out: { encodings?: { data: string }[] } = {}
  try {
    JsBarcode(out, text, { format })
  } catch {
    return null
  }
  return out.encodings?.map(e => e.data).join('') ?? null
}

/** Vector bars in the box, with the human-readable text under them. */
function drawSymbol(doc: jsPDF, text: string, format: string, x: number, y: number, w: number, h: number) {
  const bits = modules(text, format)
  if (!bits) return
  const quiet = 10                       // modules of quiet zone on each side
  const unit = w / (bits.length + 2 * quiet)
  const barH = h - 3.2
  doc.setFillColor(0, 0, 0)
  let run = 0
  for (let i = 0; i <= bits.length; i++) {
    if (bits[i] === '1') { run++; continue }
    if (run) doc.rect(x + (quiet + i - run) * unit, y, run * unit, barH, 'F')
    run = 0
  }
  doc.setFont('courier', 'normal')
  doc.setFontSize(7)
  doc.text(text, x + w / 2, y + h - 0.4, { align: 'center' })
}

/** Shrinks a line until it fits the width, then cuts it with an ellipsis. */
function fit(doc: jsPDF, text: string, width: number, size: number, min = 6): [string, number] {
  let s = size
  doc.setFontSize(s)
  while (doc.getTextWidth(text) > width && s > min) doc.setFontSize(--s)
  let t = text
  while (doc.getTextWidth(t) > width && t.length > 1) t = t.slice(0, -2) + '…'
  return [t, s]
}

function drawProduct(doc: jsPDF, l: ProductLabel, kind: LabelKind, x: number, y: number, w: number, h: number) {
  const pad = 2
  doc.setFont('helvetica', 'bold')
  const [name, size] = fit(doc, latin1(l.name), w - 2 * pad, 8)
  doc.setFontSize(size)
  doc.text(name, x + pad, y + pad + 2.6)
  if (kind === 'fnsku') {
    // Amazon's item label: Code 128 of the FNSKU, then title and condition.
    if (l.fnsku) drawSymbol(doc, l.fnsku, 'CODE128', x + pad, y + pad + 4, w - 2 * pad, h - 2 * pad - 9)
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(7)
    doc.text('New', x + pad, y + h - pad)
    return
  }
  const format = l.gtin ? barcodeFormat(l.gtin) : null
  if (format) {
    const bw = Math.min(w - 2 * pad, (h - 2 * pad - 9) * 2.6)
    drawSymbol(doc, l.gtin, format, x + (w - bw) / 2, y + pad + 4, bw, h - 2 * pad - 9)
  }
  if (l.price) {
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(8)
    doc.text(latin1(l.price), x + w - pad, y + h - pad, { align: 'right' })
  }
}

// Sheet geometry in mm: columns, rows, label w/h, left/top margin, column gap.
const SHEETS = {
  'a4-3x8': { format: 'a4', cols: 3, rows: 8, w: 63.5, h: 33.9, left: 7.2, top: 13.1, gap: 2.5 },
  // Avery 5160 / 30-up US Letter: 2.625 x 1 in.
  'letter-3x10': { format: 'letter', cols: 3, rows: 10, w: 66.675, h: 25.4, left: 4.7625, top: 12.7, gap: 3.175 },
} as const

/** Product labels: sheets (A4 24-up, Letter 30-up) or one label per page on a 50x25 mm roll. */
export function productLabelsPdf(items: ProductLabel[], layout: LabelLayout, kind: LabelKind = 'gtin'): jsPDF {
  const labels = items.flatMap(l => Array.from({ length: Math.max(0, Math.min(l.copies, 500)) }, () => l))
  if (layout === 'roll-50x25') {
    const doc = new jsPDF({ unit: 'mm', format: [50, 25], orientation: 'landscape' })
    labels.forEach((l, i) => { if (i) doc.addPage([50, 25], 'landscape'); drawProduct(doc, l, kind, 0, 0, 50, 25) })
    return doc
  }
  const g = SHEETS[layout]
  const doc = new jsPDF({ unit: 'mm', format: g.format })
  labels.forEach((l, i) => {
    const slot = i % (g.cols * g.rows)
    if (i && slot === 0) doc.addPage()
    drawProduct(doc, l, kind, g.left + (slot % g.cols) * (g.w + g.gap), g.top + Math.floor(slot / g.cols) * g.h, g.w, g.h)
  })
  return doc
}

/** ZPL for a 2 x 1 in label at 203 dpi, one block per copy: for Zebra-compatible thermal printers. */
export function productLabelsZpl(items: ProductLabel[], kind: LabelKind = 'gtin'): string {
  // ZPL field data: ^ and ~ are command prefixes, so they are dropped from text.
  const safe = (s: string) => latin1(s).replace(/[\^~]/g, ' ').slice(0, 40)
  const symbol = (l: ProductLabel) => {
    if (kind === 'fnsku') return l.fnsku ? `^FO30,50^BY2^BCN,90,Y,N,N^FD${l.fnsku}^FS` : ''
    switch (l.gtin.length) {
      case 13: return `^FO50,50^BY2^BEN,90,Y,N^FD${l.gtin.slice(0, 12)}^FS`
      case 12: return `^FO50,50^BY2^BUN,90,Y,N,Y^FD${l.gtin.slice(0, 11)}^FS`
      case 8: return `^FO90,50^BY2^B8N,90,Y,N^FD${l.gtin.slice(0, 7)}^FS`
      case 14: return `^FO20,50^BY2^B2N,90,Y,N,N^FD${l.gtin}^FS`
      default: return ''
    }
  }
  return items.flatMap(l => Array.from({ length: Math.max(0, Math.min(l.copies, 500)) }, () => [
    '^XA^CI28^PW406^LL203',
    `^FO20,15^A0N,24,24^FD${safe(l.name)}^FS`,
    symbol(l),
    kind === 'fnsku' ? '^FO20,175^A0N,20,20^FDNew^FS'
      : l.price ? `^FO250,175^A0N,22,22^FD${safe(l.price)}^FS` : '',
    '^XZ',
  ].filter(Boolean).join('\n'))).join('\n')
}

/** A 100x150 mm shipping label (4x6 in), the size couriers' thermal printers take. */
export function shippingLabelPdf(s: ShippingLabel): jsPDF {
  const doc = new jsPDF({ unit: 'mm', format: [100, 150] })
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(8)
  doc.text('FROM', 6, 9)
  doc.setFontSize(10)
  doc.text(latin1(s.from), 6, 14)
  doc.setLineWidth(0.4)
  doc.line(6, 19, 94, 19)
  doc.setFontSize(8)
  doc.text('TO', 6, 26)
  doc.setFont('helvetica', 'bold')
  const to = s.to
  const lines = [
    to.name, to.line1, to.line2,
    [to.postal, to.city].filter(Boolean).join(' '),
    [to.region, to.country].filter(Boolean).join(', '),
  ].filter(Boolean).map(latin1)
  let y = 34
  for (const line of lines) {
    const [t, size] = fit(doc, line, 88, 15, 9)
    doc.setFontSize(size)
    doc.text(t, 6, y)
    y += size * 0.5 + 2
  }
  doc.setFont('helvetica', 'normal')
  if (to.phone) { doc.setFontSize(10); doc.text(latin1(`Tel. ${to.phone}`), 6, y + 2) }
  doc.line(6, 120, 94, 120)
  doc.setFontSize(9)
  doc.text(latin1(`Order ${s.reference}`), 6, 127)
  const [items] = fit(doc, latin1(s.items), 88, 9)
  doc.text(items, 6, 133)
  return doc
}
