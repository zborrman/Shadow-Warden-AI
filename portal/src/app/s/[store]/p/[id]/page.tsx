import type { Metadata } from 'next'
import { notFound } from 'next/navigation'
import { getFeed } from '@/lib/storefront/server'
import { ProductView } from '../../_components/ProductView'

type Params = { params: { store: string; id: string } }

export async function generateMetadata({ params }: Params): Promise<Metadata> {
  const product = (await getFeed(params.store))?.products.find(p => p.id === params.id)
  return product ? { title: product.name, description: product.description.slice(0, 160) || undefined } : {}
}

export default async function StorefrontProductPage({ params }: Params) {
  const product = (await getFeed(params.store))?.products.find(p => p.id === params.id)
  if (!product) notFound()
  return <ProductView product={product} />
}
