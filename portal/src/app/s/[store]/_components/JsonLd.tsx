import { jsonLdScript } from '@/lib/storefront/seo'

/** A schema.org block. Server-rendered so crawlers read it without running scripts. */
export function JsonLd({ data }: { data: unknown }) {
  return <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: jsonLdScript(data) }} />
}
