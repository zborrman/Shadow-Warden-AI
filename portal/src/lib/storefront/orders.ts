/**
 * portal/src/lib/storefront/orders.ts
 * The buyer's side of an order request (M2M plan, stage M5). Anonymous: the
 * request is opened by its id plus a one-time token the gateway returns once.
 *
 * The token lives in the URL fragment (`#t=`), which browsers never send to a
 * server, and travels to the gateway in the X-Order-Token header, never the
 * query string, so no access log holds it.
 */
import type { OrderRequestView } from './types'

export const PUBLIC_API = process.env.NEXT_PUBLIC_API_URL || 'https://api.shadow-warden-ai.com'

export type OrderError = 'tooMany' | 'conflict' | 'invalid' | 'unavailable' | 'notFound' | 'failed'

export class OrderRequestError extends Error {
  constructor(public readonly kind: OrderError, public readonly status: number) {
    super(kind)
  }
}

function kindOf(status: number): OrderError {
  if (status === 429) return 'tooMany'
  if (status === 409) return 'conflict'
  if (status === 422) return 'invalid'
  if (status === 503) return 'unavailable'
  if (status === 404) return 'notFound'
  return 'failed'
}

async function call<T>(path: string, init: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(`${PUBLIC_API}/m2m-store/storefront/${path}`, { cache: 'no-store', ...init })
  } catch {
    throw new OrderRequestError('failed', 0)
  }
  if (!res.ok) throw new OrderRequestError(kindOf(res.status), res.status)
  return res.json() as Promise<T>
}

export interface OrderRequestBody {
  items: { product_id: string; qty: number }[]
  currency: string
  country: string
  contact: {
    name: string; email: string; phone: string
    address_line1: string; address_line2: string; city: string; postal_code: string; region: string
  }
  note: string
  locale: string
  timezone: string
}

export function buyerTimezone(): string {
  try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC' } catch { return 'UTC' }
}

export const placeOrderRequest = (slug: string, body: OrderRequestBody) =>
  call<OrderRequestView & { buyer_token: string }>(`${slug}/order-requests`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  })

export const getOrderRequest = (slug: string, id: string, token: string) =>
  call<OrderRequestView>(`${slug}/order-requests/${encodeURIComponent(id)}`, {
    headers: { 'X-Order-Token': token },
  })

export const cancelOrderRequest = (slug: string, id: string, token: string) =>
  call<OrderRequestView>(`${slug}/order-requests/${encodeURIComponent(id)}/cancel`, {
    method: 'POST', headers: { 'X-Order-Token': token },
  })

/** The token from a `#t=` fragment, or '' when the link is incomplete. */
export function tokenFromHash(hash: string): string {
  const t = new URLSearchParams(hash.replace(/^#/, '')).get('t') ?? ''
  return /^[A-Za-z0-9_-]{20,128}$/.test(t) ? t : ''
}

/** A time in the buyer's own timezone, falling back to the browser's. */
export function formatAt(iso: string, locale: string, timeZone: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  try {
    return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short', timeZone }).format(d)
  } catch {
    return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(d)
  }
}
