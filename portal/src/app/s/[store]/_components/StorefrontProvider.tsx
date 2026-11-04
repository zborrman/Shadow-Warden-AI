'use client'
import { createContext, useCallback, useContext, useMemo, useState } from 'react'
import { formatPrice, orderCurrencies } from '@/lib/money'
import { dict, type Dict, type UiLocale, isUiLocale } from '@/lib/storefront/i18n'
import { PREF_COOKIES } from '@/lib/storefront/prefs'
import type { FeedProduct, PublicStore } from '@/lib/storefront/types'
import type { UnitSystem } from '@/lib/storefront/units'

export interface Prefs {
  locale: UiLocale
  currency: string
  units: UnitSystem
  sidebar: 'expanded' | 'collapsed'
  country: string
}

interface Ctx extends Prefs {
  store: PublicStore
  base: string
  t: Dict
  currencies: string[]
  locales: UiLocale[]
  setLocale: (l: UiLocale) => void
  setCurrency: (c: string) => void
  setUnits: (u: UnitSystem) => void
  setSidebar: (s: Prefs['sidebar']) => void
  money: (amountMinor: number, currency: string) => string
  /** The product's price in the chosen currency, or in the store default when it has none. */
  priceOf: (p: FeedProduct) => { amountMinor: number; currency: string; fallback: boolean } | null
  nameOf: (p: FeedProduct) => string
  descriptionOf: (p: FeedProduct) => string
}

const StorefrontContext = createContext<Ctx | null>(null)

function setCookie(name: string, value: string) {
  try {
    document.cookie = `${name}=${encodeURIComponent(value)}; Path=/s; Max-Age=31536000; SameSite=Lax`
  } catch { /* cookies blocked: the choice lasts this visit */ }
}

export function StorefrontProvider(
  { store, initial, children }: { store: PublicStore; initial: Prefs; children: React.ReactNode },
) {
  const [prefs, setPrefs] = useState(initial)
  const update = useCallback(<K extends keyof Prefs>(k: K, cookie: string, v: Prefs[K]) => {
    setPrefs(p => ({ ...p, [k]: v }))
    setCookie(cookie, String(v))
  }, [])

  const value = useMemo<Ctx>(() => {
    const { locale, currency } = prefs
    return {
      ...prefs,
      store,
      base: `/s/${store.slug}`,
      t: dict(locale),
      currencies: orderCurrencies(store.currencies),
      locales: store.locales.filter(isUiLocale),
      setLocale: l => update('locale', PREF_COOKIES.locale, l),
      setCurrency: c => update('currency', PREF_COOKIES.currency, c),
      setUnits: u => update('units', PREF_COOKIES.units, u),
      setSidebar: s => update('sidebar', PREF_COOKIES.sidebar, s),
      money: (a, c) => formatPrice(a, c, locale),
      priceOf: p => {
        const exact = p.prices.find(x => x.currency === currency)
        if (exact) return { amountMinor: exact.amount_minor, currency, fallback: false }
        const dflt = p.prices.find(x => x.currency === store.default_currency) ?? p.prices[0]
        return dflt ? { amountMinor: dflt.amount_minor, currency: dflt.currency, fallback: true } : null
      },
      nameOf: p => p.translations[locale]?.name || p.name,
      descriptionOf: p => p.translations[locale]?.description || p.description,
    }
  }, [prefs, store, update])

  return (
    <StorefrontContext.Provider value={value}>
      <div lang={prefs.locale} className="contents">{children}</div>
    </StorefrontContext.Provider>
  )
}

export function useStorefront(): Ctx {
  const ctx = useContext(StorefrontContext)
  if (!ctx) throw new Error('useStorefront outside StorefrontProvider')
  return ctx
}
