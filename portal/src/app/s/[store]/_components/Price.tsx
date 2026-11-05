'use client'
import { fmt } from '@/lib/storefront/i18n'
import { PUBLIC_API } from '@/lib/storefront/orders'
import type { FeedProduct } from '@/lib/storefront/types'
import { convertUnitPrice } from '@/lib/storefront/units'
import { cn } from '@/lib/utils'
import { useStorefront } from './StorefrontProvider'

export { PUBLIC_API }
export const imageSrc = (url: string) => `${PUBLIC_API}${url}`

/** The seller's price per unit, plus the other unit system marked approximate. */
export function Price({ product, size = 'md' }: { product: FeedProduct; size?: 'md' | 'lg' }) {
  const { t, money, priceOf, units } = useStorefront()
  const price = priceOf(product)
  if (!price) return null
  const other = convertUnitPrice(price.amountMinor, product.unit, units)
  return (
    <div>
      <p className={cn('font-mono font-bold text-slate-100', size === 'lg' ? 'text-2xl' : 'text-base')}>
        {money(price.amountMinor, price.currency)}
        {product.unit && (
          <span className="ml-1 font-sans text-xs font-normal text-slate-500">
            {fmt(t.perUnit, { unit: product.unit })}
          </span>
        )}
      </p>
      {other && (
        <p className="text-xs text-slate-500">
          {t.approx} {money(other.amountMinor, price.currency)} {fmt(t.perUnit, { unit: other.unit })}
        </p>
      )}
      {price.fallback && (
        <p className="text-xs text-amber-400">{fmt(t.pricedOnlyIn, { cur: price.currency })}</p>
      )}
    </div>
  )
}
