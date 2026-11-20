// GS1 GTIN checks for the product form, mirroring warden/m2m_store/gtin.py.
// The server is the authority; this only gives the seller an answer while typing.

export const GTIN_LENGTHS = [8, 12, 13, 14]

export function checkDigit(body: string): number {
  let total = 0
  for (let i = 0; i < body.length; i++) {
    const d = Number(body[body.length - 1 - i])
    total += d * (i % 2 === 0 ? 3 : 1)
  }
  return (10 - (total % 10)) % 10
}

/** Digits only ("" for none), or an error message. */
export function checkGtin(raw: string): { value: string; error?: string } {
  const s = raw.replace(/[\s-]/g, '')
  if (!s) return { value: '' }
  if (!/^[0-9]+$/.test(s)) return { value: s, error: 'Digits only' }
  if (!GTIN_LENGTHS.includes(s.length)) return { value: s, error: '8, 12, 13 or 14 digits' }
  if (/^0+$/.test(s)) return { value: s, error: 'Cannot be all zeros' }
  if (checkDigit(s.slice(0, -1)) !== Number(s[s.length - 1])) {
    return { value: s, error: 'The check digit does not match; check the number' }
  }
  return { value: s }
}

/** jsbarcode format for a valid GTIN. */
export function barcodeFormat(gtin: string): 'EAN13' | 'UPC' | 'EAN8' | 'ITF14' | null {
  return ({ 8: 'EAN8', 12: 'UPC', 13: 'EAN13', 14: 'ITF14' } as const)[gtin.length as 8 | 12 | 13 | 14] ?? null
}

/**
 * In-store numbers (EAN-13 starting 2, UPC-A number system 2 or 4): valid, but
 * not unique outside one shop, so marketplaces will not accept them.
 */
export function isRestricted(gtin: string): boolean {
  if (gtin.length !== 12 && gtin.length !== 13) return false
  const g13 = gtin.padStart(13, '0')
  return g13.startsWith('02') || g13.startsWith('04') || g13[0] === '2'
}
