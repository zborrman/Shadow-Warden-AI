'use client'
import { useMemo, useState } from 'react'
import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import { Package, Plus, Search } from 'lucide-react'
import { useCart } from '@/lib/storefront/cart'
import { fmt } from '@/lib/storefront/i18n'
import type { Feed, FeedProduct, PublicCategory } from '@/lib/storefront/types'
import { imageSrc, Price } from './Price'
import { useStorefront } from './StorefrontProvider'

/** Every category id under (and including) each category. */
function subtrees(cats: PublicCategory[]): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>()
  const walk = (c: PublicCategory): Set<string> => {
    const ids = new Set([c.id])
    c.children.forEach(ch => walk(ch).forEach(id => ids.add(id)))
    out.set(c.id, ids)
    return ids
  }
  cats.forEach(walk)
  return out
}

function findCategory(cats: PublicCategory[], id: string): PublicCategory | null {
  for (const c of cats) {
    if (c.id === id) return c
    const hit = findCategory(c.children, id)
    if (hit) return hit
  }
  return null
}

export function ProductCard({ product }: { product: FeedProduct }) {
  const { t, base, store, nameOf } = useStorefront()
  const cart = useCart(store.slug)
  const name = nameOf(product)
  const img = product.images[0]
  const inCart = cart.qtyOf(product.id)
  const soldOut = product.available <= 0
  return (
    <li className="group flex flex-col overflow-hidden rounded-xl border border-white/10 bg-dark-800
                   transition-colors hover:border-brand-400/40">
      <Link href={`${base}/p/${product.id}/`} className="flex flex-1 flex-col focus-visible:outline-none
                                                        focus-visible:ring-2 focus-visible:ring-brand-400">
        <div className="aspect-square bg-dark-700">
          {img ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img src={imageSrc(img.url)} alt={fmt(t.photoOf, { name })} width={img.width} height={img.height}
                 loading="lazy" className="h-full w-full object-cover" />
          ) : (
            <div className="flex h-full items-center justify-center text-slate-600">
              <Package className="h-10 w-10" aria-hidden />
            </div>
          )}
        </div>
        <div className="flex flex-1 flex-col gap-1.5 p-3">
          <h3 className="line-clamp-2 text-sm font-semibold text-slate-100">{name}</h3>
          <Price product={product} />
          <p className={soldOut ? 'text-xs text-red-400' : 'text-xs text-slate-500'}>
            {soldOut ? t.outOfStock : fmt(t.available, { n: product.available })}
          </p>
        </div>
      </Link>
      <div className="flex items-center justify-between gap-2 border-t border-white/[0.06] px-3 py-2">
        <span className="text-xs text-brand-300" aria-live="polite">
          {inCart > 0 ? fmt(t.inCart, { n: inCart }) : ''}
        </span>
        <button type="button" disabled={soldOut || inCart >= product.available}
                onClick={() => cart.add(product.id, 1, product.available)}
                className="flex h-8 items-center gap-1 rounded-lg bg-brand-500 px-3 text-xs font-bold
                           text-dark-950 transition-[filter,transform] hover:brightness-110 active:scale-[.97]
                           disabled:cursor-not-allowed disabled:opacity-40">
          <Plus className="h-3.5 w-3.5" aria-hidden />{t.addToCart}
        </button>
      </div>
    </li>
  )
}

export function Catalog({ feed }: { feed: Feed }) {
  const { t, store, nameOf, descriptionOf } = useStorefront()
  const params = useSearchParams()
  const categoryId = params.get('c') ?? ''
  const [query, setQuery] = useState('')
  const [inStock, setInStock] = useState(false)

  const trees = useMemo(() => subtrees(feed.categories), [feed.categories])
  const category = categoryId ? findCategory(feed.categories, categoryId) : null

  const shown = useMemo(() => {
    const q = query.trim().toLocaleLowerCase()
    const allowed = category ? trees.get(category.id) : null
    return feed.products.filter(p =>
      (!allowed || allowed.has(p.category_id))
      && (!inStock || p.available > 0)
      && (!q || `${nameOf(p)} ${descriptionOf(p)} ${p.name}`.toLocaleLowerCase().includes(q)))
  }, [feed.products, category, trees, inStock, query, nameOf, descriptionOf])

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-bold text-slate-100">{category?.name ?? store.name}</h1>
        {!category && store.description && (
          <p className="mt-1 max-w-2xl text-sm text-slate-400">{store.description}</p>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <label className="relative min-w-[200px] flex-1 sm:max-w-sm">
          <span className="sr-only">{t.search}</span>
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500"
                  aria-hidden />
          <input type="search" value={query} onChange={e => setQuery(e.target.value)} placeholder={t.search}
                 className="h-10 w-full rounded-lg border border-white/10 bg-dark-800 pl-9 pr-3 text-sm
                            text-slate-100 placeholder:text-slate-500 focus:outline-none
                            focus-visible:ring-2 focus-visible:ring-brand-400" />
        </label>
        <label className="flex items-center gap-2 text-sm text-slate-300">
          <input type="checkbox" checked={inStock} onChange={e => setInStock(e.target.checked)}
                 className="h-4 w-4 accent-sky-500" />
          {t.inStockOnly}
        </label>
      </div>

      {shown.length === 0 ? (
        <p className="rounded-xl border border-dashed border-white/10 px-4 py-10 text-center text-sm text-slate-500">
          {t.noProducts}
        </p>
      ) : (
        <ul className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-3 2xl:grid-cols-4">
          {shown.map(p => <ProductCard key={p.id} product={p} />)}
        </ul>
      )}
    </div>
  )
}
