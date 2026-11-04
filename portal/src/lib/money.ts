/**
 * portal/src/lib/money.ts
 * Currencies, locales and money for the store builder and the storefront.
 * Amounts are integers in minor units; nothing here parses money through a float.
 */

export interface Price { currency: string; amount_minor: number }

// ── Constants (mirror warden/m2m_store/models.py) ─────────────────────────────

export const MINOR_DIGITS: Record<string, number> = {
  USD: 2, EUR: 2, GBP: 2, CHF: 2, CAD: 2, AUD: 2, JPY: 0,
}
export const CURRENCIES = Object.keys(MINOR_DIGITS)
export const SETTLEMENT_CURRENCY = 'USD'
/** The settlement currency first, then the rest in their usual order. */
export const orderCurrencies = (codes: string[]) =>
  [...codes].sort((a, b) => Number(b === SETTLEMENT_CURRENCY) - Number(a === SETTLEMENT_CURRENCY) || a.localeCompare(b))
export const LOCALES: { code: string; label: string }[] = [
  { code: 'en', label: 'English' },
  { code: 'fr', label: 'Français' },
  { code: 'de', label: 'Deutsch' },
  { code: 'es', label: 'Español' },
  { code: 'it', label: 'Italiano' },
]
export const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/
export const MAX_IMAGE_BYTES = 2 * 1024 * 1024

// ── Money: decimal strings <-> integer minor units, never through a float ─────

export function toMinor(input: string, currency: string): number | null {
  const digits = MINOR_DIGITS[currency] ?? 2
  const s = input.trim().replace(',', '.')
  const m = digits === 0 ? /^(\d+)$/.exec(s) : new RegExp(`^(\\d+)(?:\\.(\\d{0,${digits}}))?$`).exec(s)
  if (!m) return null
  const frac = (m[2] ?? '').padEnd(digits, '0')
  const n = Number(m[1] + frac)
  return Number.isSafeInteger(n) ? n : null
}

export function fromMinor(amount: number, currency: string): string {
  const digits = MINOR_DIGITS[currency] ?? 2
  if (digits === 0) return String(amount)
  const s = String(amount).padStart(digits + 1, '0')
  return `${s.slice(0, -digits)}.${s.slice(-digits)}`
}

export function formatMoney(amount: number, currency: string): string {
  return `${fromMinor(amount, currency)} ${currency}`
}

/** Locale-aware display, still without a float: Intl formats the decimal string. */
export function formatPrice(amount: number, currency: string, locale: string): string {
  const digits = MINOR_DIGITS[currency] ?? 2
  try {
    return new Intl.NumberFormat(locale, {
      style: 'currency', currency, minimumFractionDigits: digits, maximumFractionDigits: digits,
    }).format(fromMinor(amount, currency) as unknown as number)
  } catch {
    return formatMoney(amount, currency)
  }
}

