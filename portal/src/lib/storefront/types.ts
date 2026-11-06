/**
 * portal/src/lib/storefront/types.ts
 * What the gateway's anonymous storefront routes return (warden/m2m_store).
 */
import type { Price } from '../money'

export interface PublicCategory {
  id: string
  parent_id: string
  slug: string
  name: string
  position: number
  children: PublicCategory[]
}

export interface PublicStore {
  id: string
  slug: string
  name: string
  description: string
  default_currency: string
  currencies: string[]
  locales: string[]
  categories: PublicCategory[]
}

export interface PublicImage {
  id: string
  url: string
  width: number
  height: number
}

export interface FeedProduct {
  id: string
  name: string
  description: string
  category_id: string
  unit: string
  available: number
  prices: Price[]
  translations: Record<string, { name: string; description: string }>
  images: PublicImage[]
}

export interface Feed {
  store: string
  name: string
  default_currency: string
  locales: string[]
  categories: PublicCategory[]
  products: FeedProduct[]
  count: number
}

export interface ShippingQuote {
  zone: string
  country: string
  currency: string
  shipping_minor: number
  duty_estimate_minor: number
  duty_is_estimate: boolean
  min_days: number
  max_days: number
}

export type OrderRequestStatus =
  | 'PENDING_MERCHANT' | 'ACCEPTED' | 'PAID' | 'REJECTED' | 'SHIPPED' | 'COMPLETED' | 'CANCELLED'

export interface OrderRequestLine {
  product_id: string
  name: string
  unit: string
  qty: number
  unit_minor: number
  line_minor: number
}

export interface OrderRequestEvent {
  status: OrderRequestStatus
  at: string
  by: 'buyer' | 'seller'
  note?: string
}

/** What the buyer sees. Contact details are never in it: the link alone opens it. */
export interface OrderRequestView {
  id: string
  status: OrderRequestStatus
  currency: string
  subtotal_minor: number
  shipping_minor: number
  /** Separate from the total: the seller's estimate, set by customs. */
  duty_estimate_minor: number
  duty_is_estimate: boolean
  total_minor: number
  country: string
  locale: string
  buyer_tz: string
  items: OrderRequestLine[]
  history: OrderRequestEvent[]
  /** The seller's own payment page. To the buyer it is "" unless the request is ACCEPTED. */
  payment_url: string
  created_at: string
  updated_at: string
}
