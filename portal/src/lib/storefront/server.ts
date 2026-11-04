/**
 * portal/src/lib/storefront/server.ts
 * Server-side reads for the storefront. The portal reaches the gateway inside
 * the cluster; responses are cached for a minute (ISR), so a seller's edit
 * shows within that time and a busy store costs the gateway one read a minute.
 */
import { SLUG_RE } from '../money'
import type { Feed, PublicStore } from './types'

const GATEWAY = process.env.WARDEN_INTERNAL_URL
  || process.env.NEXT_PUBLIC_API_URL
  || 'https://api.shadow-warden-ai.com'

export const REVALIDATE_SECONDS = 60

async function read<T>(path: string): Promise<T | null> {
  const res = await fetch(`${GATEWAY}/m2m-store${path}`, { next: { revalidate: REVALIDATE_SECONDS } })
  if (res.status === 404) return null
  if (!res.ok) throw new Error(`storefront read failed: ${res.status}`)
  return res.json() as Promise<T>
}

export function getStore(slug: string): Promise<PublicStore | null> {
  if (!SLUG_RE.test(slug)) return Promise.resolve(null)
  return read<PublicStore>(`/storefront/${slug}`)
}

export function getFeed(slug: string): Promise<Feed | null> {
  if (!SLUG_RE.test(slug)) return Promise.resolve(null)
  return read<Feed>(`/storefront/${slug}/catalog/ucp`)
}
