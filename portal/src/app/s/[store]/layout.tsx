/**
 * /s/[store] — a seller's public storefront (M2M plan, stage M4).
 * Anonymous: it reads only what the gateway's storefront routes publish.
 */
import type { Metadata } from 'next'
import { cookies, headers } from 'next/headers'
import { notFound } from 'next/navigation'
import { negotiateLocale } from '@/lib/storefront/i18n'
import { PREF_COOKIES } from '@/lib/storefront/prefs'
import { getStore } from '@/lib/storefront/server'
import { Shell } from './_components/Shell'
import { StorefrontProvider, type Prefs } from './_components/StorefrontProvider'

// Countries that measure in imperial units by default; the buyer can switch.
const IMPERIAL_COUNTRIES = new Set(['US', 'LR', 'MM'])

export async function generateMetadata({ params }: { params: { store: string } }): Promise<Metadata> {
  const store = await getStore(params.store)
  if (!store) return { title: 'Store not found' }
  return { title: store.name, description: store.description || undefined }
}

export default async function StorefrontLayout(
  { children, params }: { children: React.ReactNode; params: { store: string } },
) {
  const store = await getStore(params.store)
  if (!store) notFound()

  const jar = cookies()
  const hdrs = headers()
  // Cloudflare's country header; XX and T1 (Tor) name no country.
  const cf = (hdrs.get('cf-ipcountry') ?? '').toUpperCase()
  const country = /^[A-Z]{2}$/.test(cf) && cf !== 'XX' && cf !== 'T1' ? cf : ''
  const chosenCurrency = jar.get(PREF_COOKIES.currency)?.value ?? ''
  const chosenUnits = jar.get(PREF_COOKIES.units)?.value

  const initial: Prefs = {
    locale: negotiateLocale(store.locales, jar.get(PREF_COOKIES.locale)?.value, hdrs.get('accept-language')),
    currency: store.currencies.includes(chosenCurrency) ? chosenCurrency : store.default_currency,
    units: chosenUnits === 'imperial' || chosenUnits === 'metric'
      ? chosenUnits
      : IMPERIAL_COUNTRIES.has(country) ? 'imperial' : 'metric',
    sidebar: jar.get(PREF_COOKIES.sidebar)?.value === 'collapsed' ? 'collapsed' : 'expanded',
    country,
  }

  return (
    <StorefrontProvider store={store} initial={initial}>
      <Shell>{children}</Shell>
    </StorefrontProvider>
  )
}
