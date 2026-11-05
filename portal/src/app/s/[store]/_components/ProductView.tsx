'use client'
import { useState } from 'react'
import Link from 'next/link'
import { ArrowLeft, Check, Package, Plus } from 'lucide-react'
import { MAX_QTY, useCart } from '@/lib/storefront/cart'
import { fmt } from '@/lib/storefront/i18n'
import type { FeedProduct } from '@/lib/storefront/types'
import { cn } from '@/lib/utils'
import { imageSrc, Price } from './Price'
import { useStorefront } from './StorefrontProvider'

export function ProductView({ product }: { product: FeedProduct }) {
  const { t, base, store, nameOf, descriptionOf } = useStorefront()
  const cart = useCart(store.slug)
  const [shown, setShown] = useState(0)
  const [qty, setQty] = useState(1)
  const [added, setAdded] = useState(false)
  const name = nameOf(product)
  const inCart = cart.qtyOf(product.id)
  const room = Math.max(0, Math.min(product.available, MAX_QTY) - inCart)
  const img = product.images[shown]

  return (
    <div className="space-y-5">
      <Link href={`${base}/`} className="inline-flex items-center gap-1.5 text-sm text-slate-400 hover:text-slate-100">
        <ArrowLeft className="h-4 w-4" aria-hidden />{t.backToCatalog}
      </Link>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="space-y-3">
          <div className="aspect-square overflow-hidden rounded-xl border border-white/10 bg-dark-700">
            {img ? (
              // eslint-disable-next-line @next/next/no-img-element
              <img src={imageSrc(img.url)} alt={fmt(t.photoOf, { name })} width={img.width} height={img.height}
                   className="h-full w-full object-contain" />
            ) : (
              <div className="flex h-full items-center justify-center text-slate-400">
                <Package className="h-16 w-16" aria-hidden />
              </div>
            )}
          </div>
          {product.images.length > 1 && (
            <ul className="flex flex-wrap gap-2">
              {product.images.map((im, i) => (
                <li key={im.id}>
                  <button type="button" onClick={() => setShown(i)} aria-pressed={i === shown}
                          aria-label={fmt(t.photoCount, { i: i + 1, n: product.images.length })}
                          className={cn('h-16 w-16 overflow-hidden rounded-lg border-2 transition-colors',
                            i === shown ? 'border-brand-400' : 'border-transparent opacity-70 hover:opacity-100')}>
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img src={imageSrc(im.url)} alt="" loading="lazy" className="h-full w-full object-cover" />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="space-y-4">
          <h1 className="text-2xl font-bold text-slate-100">{name}</h1>
          <Price product={product} size="lg" />
          <p className={product.available > 0 ? 'text-sm text-slate-400' : 'text-sm text-red-400'}>
            {product.available > 0 ? fmt(t.available, { n: product.available }) : t.outOfStock}
          </p>

          <form className="flex flex-wrap items-end gap-3"
                onSubmit={e => {
                  e.preventDefault()
                  if (room <= 0) return
                  cart.add(product.id, Math.min(qty, room), product.available)
                  setQty(1); setAdded(true)
                  window.setTimeout(() => setAdded(false), 2000)
                }}>
            <label className="text-sm text-slate-300">
              <span className="mb-1 block text-xs font-semibold text-slate-400">{t.quantity}</span>
              <input type="number" min={1} max={Math.max(room, 1)} value={qty} disabled={room <= 0}
                     onChange={e => setQty(Math.max(1, Math.min(Number(e.target.value) || 1, Math.max(room, 1))))}
                     className="h-10 w-24 rounded-lg border border-white/10 bg-dark-800 px-3 font-mono text-sm
                                text-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-400" />
            </label>
            <button type="submit" disabled={room <= 0}
                    className="flex h-10 items-center gap-2 rounded-lg bg-brand-500 px-5 text-sm font-bold
                               text-dark-950 transition-[filter,transform] hover:brightness-110
                               active:scale-[.97] disabled:cursor-not-allowed disabled:opacity-40">
              {added ? <Check className="h-4 w-4" aria-hidden /> : <Plus className="h-4 w-4" aria-hidden />}
              {added ? t.addedToCart : t.addToCart}
            </button>
            <span className="text-xs text-brand-300" aria-live="polite">
              {inCart > 0 ? fmt(t.inCart, { n: inCart }) : ''}
            </span>
          </form>

          {descriptionOf(product) && (
            <p className="whitespace-pre-line text-sm leading-relaxed text-slate-300">{descriptionOf(product)}</p>
          )}
        </div>
      </div>
    </div>
  )
}
