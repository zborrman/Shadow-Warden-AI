import type { Metadata } from 'next'
import { notFound } from 'next/navigation'
import { productJsonLd, productUrl } from '@/lib/storefront/seo'
import { getFeed, getStore } from '@/lib/storefront/server'
import { JsonLd } from '../../_components/JsonLd'
import { ProductView } from '../../_components/ProductView'

type Params = { params: { store: string; id: string } }

export async function generateMetadata({ params }: Params): Promise<Metadata> {
  const product = (await getFeed(params.store))?.products.find(p => p.id === params.id)
  if (!product) return {}
  return {
    title: product.name,
    description: product.description.slice(0, 160) || undefined,
    alternates: { canonical: productUrl(params.store, product.id) },
  }
}

export default async function StorefrontProductPage({ params }: Params) {
  const [store, feed] = await Promise.all([getStore(params.store), getFeed(params.store)])
  const product = feed?.products.find(p => p.id === params.id)
  if (!store || !product) notFound()
  return (
    <>
      <JsonLd data={productJsonLd(store, product)} />
      <ProductView product={product} />
    </>
  )
}
