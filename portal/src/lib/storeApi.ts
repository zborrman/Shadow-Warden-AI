/**
 * portal/src/lib/storeApi.ts
 * Typed client for the M2M Commerce Store builder (owner routes).
 *
 * Calls go straight to the gateway with the user's portal session token (the
 * shared `api` instance attaches it and refreshes it). They must not go
 * through a server-side proxy holding the gateway key: that key is one tenant,
 * so every portal user would edit the same stores.
 */
import { api, API_URL } from './api'

const BASE = `${API_URL}/m2m-store`

// ── Types ─────────────────────────────────────────────────────────────────────

export interface Store {
  id: string
  slug: string
  name: string
  description: string
  default_currency: string
  currencies: string[]
  locales: string[]
  active: boolean
  created_at: string
}

export interface Category {
  id: string
  store_id: string
  parent_id: string
  slug: string
  name: string
  position: number
  children: Category[]
}

export interface Price { currency: string; amount_minor: number }

export interface ProductImage {
  id: string
  url: string
  content_type: string
  bytes: number
  width: number
  height: number
}

export interface StoreProduct {
  id: string
  store_id: string
  category_id: string
  name: string
  description: string
  currency: string
  price_minor: number
  stock: number
  available: number
  unit: string
  active: boolean
  prices: Price[]
  translations: Record<string, { name: string; description: string }>
  images: ProductImage[]
}

export interface ShippingZone {
  id: string
  store_id: string
  name: string
  countries: string[]
  currency: string
  rate_minor: number
  free_over_minor: number | null
  duty_estimate_bps: number
  min_days: number
  max_days: number
}

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

// ── Errors ────────────────────────────────────────────────────────────────────

/** The gateway's own message (FastAPI `detail`), readable for a toast. */
export function errorMessage(err: unknown): string {
  const e = err as { response?: { status?: number; data?: { detail?: unknown } }; message?: string }
  const detail = e?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    return detail.map((d: { loc?: unknown[]; msg?: string }) =>
      `${(d.loc ?? []).slice(1).join('.')}: ${d.msg ?? ''}`.replace(/^: /, '')).join('; ')
  }
  if (e?.response?.status === 503) return 'Photo storage is unavailable. Try again later.'
  return e?.message ?? 'Request failed'
}

// ── Calls ─────────────────────────────────────────────────────────────────────

const get  = <T,>(p: string) => api.get<T>(`${BASE}${p}`).then(r => r.data)
const send = <T,>(method: 'post' | 'put' | 'patch', p: string, body: unknown) =>
  api.request<T>({ method, url: `${BASE}${p}`, data: body }).then(r => r.data)
const del  = (p: string) => api.delete(`${BASE}${p}`).then(() => undefined)

export const storeApi = {
  listStores:   () => get<Store[]>('/stores'),
  createStore:  (body: Pick<Store, 'slug' | 'name' | 'description' | 'default_currency' | 'currencies' | 'locales'>) =>
    send<Store>('post', '/stores', body),
  patchStore:   (id: string, body: Partial<Pick<Store, 'name' | 'description' | 'active'>>) =>
    send<Store>('patch', `/stores/${id}`, body),
  deleteStore:  (id: string) => del(`/stores/${id}`),

  categories:     (storeId: string) => get<Category[]>(`/stores/${storeId}/categories`),
  createCategory: (storeId: string, body: { slug: string; name: string; parent_id: string; position?: number }) =>
    send<Category>('post', `/stores/${storeId}/categories`, body),
  deleteCategory: (id: string) => del(`/categories/${id}`),

  products:      (storeId: string) => get<StoreProduct[]>(`/stores/${storeId}/products`),
  saveProduct:   (body: {
    id?: string; store_id: string; category_id: string; name: string; description: string
    price_minor: number; stock: number; unit: string; active: boolean
  }) => send<{ id: string; name: string }>('post', '/products', body),
  deleteProduct: (id: string) => del(`/products/${id}`),
  setPrices:     (id: string, prices: Price[]) => send<Price[]>('put', `/products/${id}/prices`, prices),
  setTranslation: (id: string, locale: string, body: { name: string; description: string }) =>
    send('put', `/products/${id}/translations/${locale}`, body),

  uploadImage: (productId: string, file: File) =>
    api.post<ProductImage>(`${BASE}/products/${productId}/images`, file, {
      headers: { 'Content-Type': file.type },
    }).then(r => r.data),
  deleteImage: (id: string) => del(`/images/${id}`),
  /** Image bytes as an object URL: an <img src> cannot send the session token. */
  imageBlobUrl: (image: ProductImage) =>
    api.get<Blob>(`${API_URL}${image.url}`, { responseType: 'blob' })
      .then(r => URL.createObjectURL(r.data)),

  zones:      (storeId: string) => get<ShippingZone[]>(`/stores/${storeId}/shipping-zones`),
  createZone: (storeId: string, body: Omit<ShippingZone, 'id' | 'store_id'>) =>
    send<ShippingZone>('post', `/stores/${storeId}/shipping-zones`, body),
  deleteZone: (id: string) => del(`/shipping-zones/${id}`),
}
