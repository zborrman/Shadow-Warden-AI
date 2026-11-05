import type { MetadataRoute } from 'next'

// The portal is a signed-in app; only the public storefronts are for crawlers,
// and within them only the catalog and product pages. Carts and order pages are
// private to one buyer. Each store publishes its own /s/<store>/sitemap.xml.
export default function robots(): MetadataRoute.Robots {
  return {
    rules: [{
      userAgent: '*',
      allow: ['/s/'],
      disallow: ['/s/*/cart/', '/s/*/order/', '/'],
    }],
  }
}
