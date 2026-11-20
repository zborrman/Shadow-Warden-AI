'use client'
import { useEffect, useRef } from 'react'
import JsBarcode from 'jsbarcode'
import { barcodeFormat } from '@/lib/gtin'

/** A GTIN drawn as its standard symbol (EAN-13, UPC-A, EAN-8 or ITF-14), black on white. */
export function Barcode({ gtin, height = 60 }: { gtin: string; height?: number }) {
  const ref = useRef<SVGSVGElement>(null)
  const format = barcodeFormat(gtin)
  useEffect(() => {
    if (!ref.current || !format) return
    try {
      JsBarcode(ref.current, gtin, { format, height, width: 2, fontSize: 14, margin: 8, background: '#ffffff' })
    } catch {
      ref.current.innerHTML = ''
    }
  }, [gtin, format, height])
  if (!format) return null
  return <svg ref={ref} role="img" aria-label={`Barcode ${gtin}`} className="max-w-full rounded" />
}
