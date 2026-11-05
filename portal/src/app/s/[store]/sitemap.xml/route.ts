import { sitemapXml } from '@/lib/storefront/seo'
import { getFeed, REVALIDATE_SECONDS } from '@/lib/storefront/server'

// /s/<store>/sitemap.xml: the URL a seller submits to a search engine.
export const revalidate = 60

export async function GET(_req: Request, { params }: { params: { store: string } }) {
  const feed = await getFeed(params.store)
  if (!feed) return new Response('Not found', { status: 404 })
  return new Response(sitemapXml(params.store, feed.products.map(p => p.id)), {
    headers: {
      'Content-Type': 'application/xml; charset=utf-8',
      'Cache-Control': `public, max-age=${REVALIDATE_SECONDS}`,
    },
  })
}
