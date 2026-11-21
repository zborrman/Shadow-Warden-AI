'use client'
// R8.4: printable labels, made in the browser. Nothing is sent anywhere: the
// product data is already on the page, and a shipping label carries the
// buyer's address, which should not travel further than it must.
//
// jsPDF's built-in fonts cover Latin-1 only. Text outside it (Cyrillic,
// Hebrew, CJK...) is printed as "?" rather than as garbage, and the UI says so.
import { jsPDF } from 'jspdf'
import JsBarcode from 'jsbarcode'
import { barcodeFormat } from '@/lib/gtin'

export type LabelLayout = 'a4-3x8' | 'roll-50x25'

export interface ProductLabel { name: string; price: string; gtin: string; copies: number }

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

function barcodePng(gtin: string): string | null {
  const format = barcodeFormat(gtin)
  if (!format) return null
  const canvas = document.createElement('canvas')
  try {
    JsBarcode(canvas, gtin, { format, width: 2, height: 60, fontSize: 16, margin: 4, background: '#ffffff' })
    return canvas.toDataURL('image/png')
  } catch {
    return null
  }
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

function drawProduct(doc: jsPDF, l: ProductLabel, x: number, y: number, w: number, h: number) {
  const pad = 2
  doc.setFont('helvetica', 'bold')
  const [name, size] = fit(doc, latin1(l.name), w - 2 * pad, 9)
  doc.setFontSize(size)
  doc.text(name, x + pad, y + pad + 3)
  // Name on top, the symbol (with its digits) in the middle, the price at the bottom.
  const png = l.gtin ? barcodePng(l.gtin) : null
  if (png) {
    const bh = h - pad * 2 - 10
    const bw = Math.min(w - pad * 2, bh * 2.4)
    doc.addImage(png, 'PNG', x + (w - bw) / 2, y + pad + 5, bw, bh)
  }
  if (l.price) {
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(9)
    doc.text(latin1(l.price), x + w - pad, y + h - pad, { align: 'right' })
  }
}

/** Product labels: a sheet of 24 (Avery L7159 / 3x8, 63.5x33.9 mm) or one label per page on a 50x25 mm roll. */
export function productLabelsPdf(items: ProductLabel[], layout: LabelLayout): jsPDF {
  const labels = items.flatMap(l => Array.from({ length: Math.max(0, Math.min(l.copies, 500)) }, () => l))
  if (layout === 'roll-50x25') {
    const doc = new jsPDF({ unit: 'mm', format: [50, 25], orientation: 'landscape' })
    labels.forEach((l, i) => { if (i) doc.addPage([50, 25], 'landscape'); drawProduct(doc, l, 0, 0, 50, 25) })
    return doc
  }
  const doc = new jsPDF({ unit: 'mm', format: 'a4' })
  const [cols, rows, w, h, left, top, gapX] = [3, 8, 63.5, 33.9, 7.2, 13.1, 2.5]
  labels.forEach((l, i) => {
    const slot = i % (cols * rows)
    if (i && slot === 0) doc.addPage()
    const c = slot % cols
    const r = Math.floor(slot / cols)
    drawProduct(doc, l, left + c * (w + gapX), top + r * h, w, h)
  })
  return doc
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
  doc.setFontSize(15)
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
  if (to.phone) { doc.setFontSize(10); doc.text(latin1(`Tel. ${to.phone}`), 6, y + 2); y += 7 }
  doc.line(6, 120, 94, 120)
  doc.setFontSize(9)
  doc.text(latin1(`Order ${s.reference}`), 6, 127)
  const [items] = fit(doc, latin1(s.items), 88, 9)
  doc.text(items, 6, 133)
  return doc
}
