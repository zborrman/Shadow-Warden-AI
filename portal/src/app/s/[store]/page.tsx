import { Suspense } from 'react'
import { notFound } from 'next/navigation'
import { getFeed } from '@/lib/storefront/server'
import { Catalog } from './_components/Catalog'

export default async function StorefrontCatalogPage({ params }: { params: { store: string } }) {
  const feed = await getFeed(params.store)
  if (!feed) notFound()
  return (
    <Suspense>
      <Catalog feed={feed} />
    </Suspense>
  )
}
