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
import type { Price } from './money'
import type { OrderRequestStatus, OrderRequestView } from './storefront/types'

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

export type { Price } from './money'

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
  /** GS1 GTIN, digits only; "" when none. */
  gtin: string
  /** Amazon FNSKU, 10 letters and digits; "" when none. Seller-side only. */
  fnsku: string
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

// Money, currencies and locales live in ./money so server pages can use them
// without pulling in the session-bearing axios client.
export {
  MINOR_DIGITS, CURRENCIES, SETTLEMENT_CURRENCY, orderCurrencies, LOCALES, SLUG_RE,
  MAX_IMAGE_BYTES, toMinor, fromMinor, formatMoney,
} from './money'

export type { OrderRequestStatus } from './storefront/types'

/** The seller's view of an order request: the buyer's view plus their contact details. */
export interface SellerOrderRequest extends OrderRequestView {
  store_id: string
  note: string
  contact: {
    name: string; email: string; phone: string; address_line1: string; address_line2: string
    city: string; postal_code: string; region: string
  }
}


/** R8.1: one buyer of this store, built from its order requests. */
export interface CustomerSummary {
  id: string
  store_id: string
  name: string
  email: string
  country: string
  orders: number
  /** Agreed sales only (accepted, paid, shipped, completed), per currency, minor units. */
  spent_minor: Record<string, number>
  tags: string[]
  first_seen_at: string
  last_seen_at: string
}

export interface Customer extends CustomerSummary {
  contact: SellerOrderRequest['contact']
  notes: string
  order_requests: {
    id: string; status: OrderRequestStatus; currency: string; total_minor: number; created_at: string
    items: { product_id: string; name: string; qty: number }[]
  }[]
}

/** One line of a customer's timeline: the seller's own entry, or an order status change. */
export type JournalEntry =
  | { id: string; type: 'note' | 'message'; status: 'LOGGED' | 'DRAFT' | 'SENT'
      subject: string; body: string; at: string; updated_at: string }
  | { id: string; type: 'order'; request_id: string; status: OrderRequestStatus; by: string; at: string }

/** Moves the seller may make from each status; mirrors SELLER_MOVES in order_requests.py. */
export const SELLER_MOVES: Partial<Record<OrderRequestStatus, OrderRequestStatus[]>> = {
  PENDING_MERCHANT: ['ACCEPTED', 'REJECTED'],
  ACCEPTED: ['PAID', 'SHIPPED', 'CANCELLED'],
  PAID: ['SHIPPED', 'CANCELLED'],
  SHIPPED: ['COMPLETED'],
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
    price_minor: number; stock: number; unit: string; gtin: string; fnsku: string; active: boolean
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

  orderRequests: (storeId: string, status = '') =>
    get<SellerOrderRequest[]>(`/stores/${storeId}/order-requests${status ? `?status=${status}` : ''}`),
  answerOrderRequest: (id: string, body: { status: OrderRequestStatus; note: string }) =>
    send<SellerOrderRequest>('patch', `/order-requests/${id}`, body),
  setPaymentLink: (id: string, url: string) =>
    send<SellerOrderRequest>('put', `/order-requests/${id}/payment-link`, { url }),
  customers: (storeId: string, q = '') =>
    get<CustomerSummary[]>(`/stores/${storeId}/customers${q ? `?q=${encodeURIComponent(q)}` : ''}`),
  customer: (storeId: string, id: string) => get<Customer>(`/stores/${storeId}/customers/${id}`),
  updateCustomer: (storeId: string, id: string, body: { notes?: string; tags?: string[] }) =>
    send<Customer>('patch', `/stores/${storeId}/customers/${id}`, body),
  exportCustomer: (storeId: string, id: string) =>
    get<Record<string, unknown>>(`/stores/${storeId}/customers/${id}/export`),
  eraseCustomer: (storeId: string, id: string) => del(`/stores/${storeId}/customers/${id}`),
  journal: (storeId: string, id: string) =>
    get<JournalEntry[]>(`/stores/${storeId}/customers/${id}/journal`),
  addJournal: (storeId: string, id: string, body: { kind: 'note' | 'message'; subject?: string; body: string }) =>
    send<JournalEntry>('post', `/stores/${storeId}/customers/${id}/journal`, body),
  updateJournal: (storeId: string, id: string, entryId: string,
                  body: { subject?: string; body?: string; sent?: boolean }) =>
    send<JournalEntry>('patch', `/stores/${storeId}/customers/${id}/journal/${entryId}`, body),
  /** Claims in a product's own text that need proof or a registration (EPA, FDA, FTC, EU). */
  lintListing: (body: { name: string; description: string }) =>
    send<{ term: string; category: string; field: string; basis: string; suggestion: string }[]>('post', '/listing-lint', body),
  /** Counts labels against the plan's monthly allowance before they are drawn (403 plan_limit when over). */
  useLabels: (count: number) => send<{ used: number; limit: number }>('post', '/labels/usage', { count }),
  deleteJournal: (storeId: string, id: string, entryId: string) =>
    del(`/stores/${storeId}/customers/${id}/journal/${entryId}`),
}
