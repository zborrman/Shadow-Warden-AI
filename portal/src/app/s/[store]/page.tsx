import { Suspense } from 'react'
import type { Metadata } from 'next'
import { notFound } from 'next/navigation'
import { storeJsonLd, storeUrl } from '@/lib/storefront/seo'
import { getFeed, getStore } from '@/lib/storefront/server'
import { Catalog } from './_components/Catalog'
import { JsonLd } from './_components/JsonLd'

export async function generateMetadata(props: { params: Promise<{ store: string }> }): Promise<Metadata> {
  const params = await props.params;
  return { alternates: { canonical: storeUrl(params.store) } }
}

export default async function StorefrontCatalogPage(props: { params: Promise<{ store: string }> }) {
  const params = await props.params;
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
