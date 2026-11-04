import type { Metadata } from 'next'
import { notFound } from 'next/navigation'
import { getFeed } from '@/lib/storefront/server'
import { CartView } from '../_components/CartView'

export const metadata: Metadata = { robots: { index: false } }

export default async function StorefrontCartPage({ params }: { params: { store: string } }) {
  const feed = await getFeed(params.store)
  if (!feed) notFound()
  return <CartView feed={feed} />
}
