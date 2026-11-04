/**
 * portal/src/lib/storefront/cart.ts
 * The buyer's cart: product ids and quantities in localStorage, per store.
 * Prices are never stored here; every render re-reads them from the catalog,
 * and the server reprices any order in any case.
 */
'use client'
import { useSyncExternalStore } from 'react'

export interface CartLine { id: string; qty: number }

export const MAX_QTY = 999
const EMPTY: CartLine[] = []
const listeners = new Set<() => void>()
const cache = new Map<string, { raw: string | null; lines: CartLine[] }>()
const key = (slug: string) => `sf_cart:${slug}`

function parse(raw: string | null): CartLine[] {
  if (!raw) return EMPTY
  try {
    const data: unknown = JSON.parse(raw)
    if (!Array.isArray(data)) return EMPTY
    return data
      .filter((l): l is CartLine => typeof l?.id === 'string' && Number.isInteger(l?.qty) && l.qty > 0)
      .map(l => ({ id: l.id, qty: Math.min(l.qty, MAX_QTY) }))
  } catch {
    return EMPTY
  }
}

function read(slug: string): CartLine[] {
  let raw: string | null = null
  try { raw = window.localStorage.getItem(key(slug)) } catch { /* blocked storage: empty cart */ }
  const hit = cache.get(slug)
  if (hit && hit.raw === raw) return hit.lines
  const lines = parse(raw)
  cache.set(slug, { raw, lines })
  return lines
}

function write(slug: string, lines: CartLine[]) {
  try { window.localStorage.setItem(key(slug), JSON.stringify(lines)) } catch { /* not persisted */ }
  listeners.forEach(l => l())
}

function subscribe(cb: () => void) {
  listeners.add(cb)
  const onStorage = (e: StorageEvent) => { if (e.key?.startsWith('sf_cart:')) cb() }
  window.addEventListener('storage', onStorage)
  return () => { listeners.delete(cb); window.removeEventListener('storage', onStorage) }
}

export function useCart(slug: string) {
  const lines = useSyncExternalStore(subscribe, () => read(slug), () => EMPTY)
  return {
    lines,
    count: lines.reduce((n, l) => n + l.qty, 0),
    qtyOf: (id: string) => lines.find(l => l.id === id)?.qty ?? 0,
    /** Adds up to what is available; returns the quantity now in the cart. */
    add: (id: string, qty: number, max: number): number => {
      const cur = read(slug)
      const have = cur.find(l => l.id === id)?.qty ?? 0
      const next = Math.min(have + qty, max, MAX_QTY)
      if (next > have) {
        write(slug, have ? cur.map(l => (l.id === id ? { id, qty: next } : l)) : [...cur, { id, qty: next }])
      }
      return Math.max(next, have)
    },
    set: (id: string, qty: number) => {
      const cur = read(slug)
      write(slug, qty > 0 ? cur.map(l => (l.id === id ? { id, qty: Math.min(qty, MAX_QTY) } : l))
                          : cur.filter(l => l.id !== id))
    },
    remove: (id: string) => write(slug, read(slug).filter(l => l.id !== id)),
  }
}
