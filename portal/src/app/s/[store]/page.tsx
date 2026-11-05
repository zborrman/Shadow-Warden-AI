import { Suspense } from 'react'
import type { Metadata } from 'next'
import { notFound } from 'next/navigation'
import { storeJsonLd, storeUrl } from '@/lib/storefront/seo'
import { getFeed, getStore } from '@/lib/storefront/server'
import { Catalog } from './_components/Catalog'
import { JsonLd } from './_components/JsonLd'

export function generateMetadata({ params }: { params: { store: string } }): Metadata {
  return { alternates: { canonical: storeUrl(params.store) } }
}

export default async function StorefrontCatalogPage({ params }: { params: { store: string } }) {
  const [store, feed] = await Promise.all([getStore(params.store), getFeed(params.store)])
  if (!store || !feed) notFound()
  return (
    <>
      <JsonLd data={storeJsonLd(store)} />
      <Suspense>
        <Catalog feed={feed} />
      </Suspense>
    </>
  )
}
