/**
 * portal/src/lib/storefront/seo.ts
 * Machine-readable descriptions of a public storefront (M2M plan, stage M6):
 * schema.org JSON-LD for the store and each product, and the store's sitemap.
 *
 * Everything here is the seller's own data. No rating, review or sales figure
 * is ever emitted: nothing measures one.
 */
import { fromMinor } from '../money'
import type { FeedProduct, PublicStore } from './types'

/** The public origin of the storefront. A constant, never the Host header: it lands in caches and sitemaps. */
export const STOREFRONT_ORIGIN = (process.env.STOREFRONT_ORIGIN || 'https://portal.shadow-warden-ai.com')
  .replace(/\/+$/, '')

/** Where photos are served from: the gateway's anonymous image route. */
const IMAGE_ORIGIN = (process.env.NEXT_PUBLIC_API_URL || 'https://api.shadow-warden-ai.com').replace(/\/+$/, '')

export const storeUrl = (slug: string) => `${STOREFRONT_ORIGIN}/s/${slug}/`
export const productUrl = (slug: string, id: string) => `${STOREFRONT_ORIGIN}/s/${slug}/p/${encodeURIComponent(id)}/`

export function storeJsonLd(store: PublicStore) {
  return {
    '@context': 'https://schema.org',
    '@type': 'OnlineStore',
    '@id': `${storeUrl(store.slug)}#store`,
    name: store.name,
    ...(store.description ? { description: store.description } : {}),
    url: storeUrl(store.slug),
    currenciesAccepted: store.currencies.join(', '),
    availableLanguage: store.locales,
  }
}

export function productJsonLd(store: PublicStore, p: FeedProduct) {
  const url = productUrl(store.slug, p.id)
  return {
    '@context': 'https://schema.org',
    '@type': 'Product',
    '@id': `${url}#product`,
    sku: p.id,
    name: p.name,
    ...(p.description ? { description: p.description } : {}),
    url,
    ...(p.images.length ? { image: p.images.map(i => `${IMAGE_ORIGIN}${i.url}`) } : {}),
    offers: p.prices.map(price => ({
      '@type': 'Offer',
      price: fromMinor(price.amount_minor, price.currency),
      priceCurrency: price.currency,
      availability: p.available > 0 ? 'https://schema.org/InStock' : 'https://schema.org/OutOfStock',
      url,
      seller: { '@id': `${storeUrl(store.slug)}#store` },
    })),
  }
}

/**
 * JSON for a <script type="application/ld+json"> body. Seller text is
 * untrusted: `<` is escaped so a name containing "</script>" cannot close the
 * element, and U+2028/2029 so the body stays valid inside script.
 */
const LINE_SEP = new RegExp(String.fromCharCode(0x2028), 'g')
const PARA_SEP = new RegExp(String.fromCharCode(0x2029), 'g')

export function jsonLdScript(data: unknown): string {
  return JSON.stringify(data)
    .replace(/</g, '\\u003c')
    .replace(LINE_SEP, '\\u2028')
    .replace(PARA_SEP, '\\u2029')
}

const xmlEscape = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;')

/** The store's sitemap: its catalog and every product page. Cart and order pages are private. */
export function sitemapXml(slug: string, productIds: string[]): string {
  const urls = [storeUrl(slug), ...productIds.map(id => productUrl(slug, id))]
  return '<?xml version="1.0" encoding="UTF-8"?>\n'
    + '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    + urls.map(u => `  <url><loc>${xmlEscape(u)}</loc></url>`).join('\n')
    + '\n</urlset>\n'
}
