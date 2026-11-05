'use client'
import { Suspense, useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { usePathname, useSearchParams } from 'next/navigation'
import { ChevronsLeft, ChevronsRight, LayoutGrid, Menu, ShoppingCart, X } from 'lucide-react'
import { LOCALES } from '@/lib/money'
import { fmt, type UiLocale } from '@/lib/storefront/i18n'
import { useCart } from '@/lib/storefront/cart'
import type { PublicCategory } from '@/lib/storefront/types'
import { cn } from '@/lib/utils'
import { useStorefront } from './StorefrontProvider'

const selectCls = 'h-9 rounded-lg border border-white/10 bg-dark-800 px-2 text-sm text-slate-200 ' +
  'focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-400'

function CurrencySelect({ className }: { className?: string }) {
  const { t, currency, currencies, setCurrency } = useStorefront()
  if (currencies.length < 2) return null
  return (
    <select aria-label={t.currency} value={currency} onChange={e => setCurrency(e.target.value)}
            className={cn(selectCls, className)}>
      {currencies.map(c => <option key={c} value={c}>{c}</option>)}
    </select>
  )
}

function LocaleSelect({ className }: { className?: string }) {
  const { t, locale, locales, setLocale } = useStorefront()
  if (locales.length < 2) return null
  return (
    <select aria-label={t.language} value={locale} onChange={e => setLocale(e.target.value as UiLocale)}
            className={cn(selectCls, className)}>
      {locales.map(l => <option key={l} value={l}>{LOCALES.find(x => x.code === l)?.label ?? l}</option>)}
    </select>
  )
}

function UnitsToggle() {
  const { t, units, setUnits } = useStorefront()
  return (
    <div role="group" aria-label={t.units} className="flex h-9 rounded-lg border border-white/10 p-0.5 text-xs">
      {(['metric', 'imperial'] as const).map(u => (
        <button key={u} type="button" aria-pressed={units === u} onClick={() => setUnits(u)}
                className={cn('rounded-md px-2 font-semibold transition-colors',
                  units === u ? 'bg-brand-500/20 text-brand-300' : 'text-slate-400 hover:text-slate-200')}>
          {u === 'metric' ? t.metric : t.imperial}
        </button>
      ))}
    </div>
  )
}

function CartLink() {
  const { t, base, store } = useStorefront()
  const { count } = useCart(store.slug)
  return (
    <Link href={`${base}/cart/`} aria-label={fmt(t.cartItems, { n: count })}
          className="relative flex h-9 w-9 items-center justify-center rounded-lg border border-white/10
                     text-slate-200 hover:border-brand-400/50 focus-visible:outline-none
                     focus-visible:ring-2 focus-visible:ring-brand-400">
      <ShoppingCart className="h-4 w-4" />
      {count > 0 && (
        <span className="absolute -right-1.5 -top-1.5 min-w-[18px] rounded-full bg-brand-500 px-1 text-center
                         font-mono text-[10px] font-bold leading-[18px] text-dark-950">
          {count > 99 ? '99+' : count}
        </span>
      )}
    </Link>
  )
}

function CategoryNav({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: () => void }) {
  const { t, base, store } = useStorefront()
  const params = useSearchParams()
  const path = usePathname()
  const onCatalog = path === `${base}/` || path === base
  const active = onCatalog ? (params.get('c') ?? '') : null

  const item = (id: string, label: string, depth: number, icon?: React.ReactNode) => {
    const current = active === id
    return (
      <li key={id || 'all'}>
        <Link href={id ? `${base}/?c=${id}` : `${base}/`} onClick={onNavigate}
              aria-current={current ? 'page' : undefined} title={collapsed ? label : undefined}
              className={cn('flex items-center gap-3 rounded-lg py-2 text-sm transition-colors',
                collapsed ? 'justify-center px-0' : 'px-3',
                current ? 'bg-brand-500/15 font-semibold text-brand-300'
                        : 'text-slate-400 hover:bg-white/[0.04] hover:text-slate-100')}
              style={collapsed ? undefined : { paddingLeft: 12 + depth * 14 }}>
          {collapsed
            ? icon ?? <span aria-hidden className="flex h-7 w-7 items-center justify-center rounded-md border
                            border-white/10 text-xs font-bold uppercase">{label.slice(0, 1)}</span>
            : icon}
          <span className={collapsed ? 'sr-only' : 'truncate'}>{label}</span>
        </Link>
      </li>
    )
  }
  const walk = (cats: PublicCategory[], depth: number): React.ReactNode[] =>
    cats.flatMap(c => [item(c.id, c.name, depth),
      ...(collapsed ? [] : walk(c.children, depth + 1))])

  return (
    <nav aria-label={t.storeMenu}>
      <ul className="space-y-0.5">
        {item('', t.allProducts, 0, <LayoutGrid className="h-4 w-4 shrink-0" />)}
      </ul>
      {store.categories.length > 0 && (
        <>
          {!collapsed && (
            <p className="mb-1 mt-5 px-3 text-xs font-semibold uppercase tracking-[0.1em] text-slate-400">
              {t.categories}
            </p>
          )}
          <ul className={cn('space-y-0.5', collapsed && 'mt-3')}>{walk(store.categories, 0)}</ul>
        </>
      )}
    </nav>
  )
}

export function Shell({ children }: { children: React.ReactNode }) {
  const { t, store, base, sidebar, setSidebar } = useStorefront()
  const collapsed = sidebar === 'collapsed'
  const [drawer, setDrawer] = useState(false)
  const openBtn = useRef<HTMLButtonElement>(null)
  const closeBtn = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (!drawer) return
    closeBtn.current?.focus()
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setDrawer(false) }
    document.addEventListener('keydown', onKey)
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = prev
      openBtn.current?.focus()
    }
  }, [drawer])

  return (
    <div className="min-h-screen bg-dark-900 text-slate-100">
      <header className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b border-white/[0.06]
                         bg-dark-900/90 px-3 backdrop-blur sm:gap-3 sm:px-4">
        <button ref={openBtn} type="button" onClick={() => setDrawer(true)} aria-label={t.openMenu}
                aria-expanded={drawer} aria-controls="sf-drawer"
                className="flex h-9 w-9 items-center justify-center rounded-lg text-slate-300
                           hover:bg-white/[0.05] md:hidden">
          <Menu className="h-5 w-5" />
        </button>
        <Link href={`${base}/`} className="min-w-0 flex-1 truncate text-[15px] font-bold text-slate-100">
          {store.name}
        </Link>
        <div className="hidden items-center gap-2 md:flex">
          <LocaleSelect />
          <UnitsToggle />
        </div>
        <CurrencySelect />
        <CartLink />
      </header>

      <div className="flex">
        <aside className={cn('sticky top-14 hidden h-[calc(100vh-3.5rem)] shrink-0 flex-col border-r',
                             'border-white/[0.06] transition-[width] duration-200 md:flex',
                             collapsed ? 'w-[72px]' : 'w-[280px]')}
               style={{ transitionTimingFunction: 'cubic-bezier(0.23,1,0.32,1)' }}>
          <div className="flex-1 overflow-y-auto overflow-x-hidden p-3">
            <Suspense><CategoryNav collapsed={collapsed} /></Suspense>
          </div>
          <button type="button" onClick={() => setSidebar(collapsed ? 'expanded' : 'collapsed')}
                  aria-label={collapsed ? t.expandMenu : t.collapseMenu} aria-expanded={!collapsed}
                  className={cn('m-3 flex h-9 items-center gap-2 rounded-lg text-xs text-slate-400',
                                'hover:bg-white/[0.04] hover:text-slate-200',
                                collapsed ? 'justify-center' : 'px-3')}>
            {collapsed ? <ChevronsRight className="h-4 w-4" />
                       : <><ChevronsLeft className="h-4 w-4" />{t.collapseMenu}</>}
          </button>
        </aside>

        <main className="min-w-0 flex-1 px-4 py-5 sm:px-6 sm:py-6">{children}</main>
      </div>

      {drawer && (
        <div className="fixed inset-0 z-40 md:hidden">
          <div className="absolute inset-0 bg-black/60" onClick={() => setDrawer(false)} aria-hidden />
          <div id="sf-drawer" role="dialog" aria-modal="true" aria-label={t.storeMenu}
               className="absolute inset-y-0 left-0 flex w-[280px] max-w-[85vw] flex-col border-r
                          border-white/10 bg-dark-900">
            <div className="flex h-14 items-center justify-between border-b border-white/[0.06] px-3">
              <span className="truncate text-sm font-bold">{store.name}</span>
              <button ref={closeBtn} type="button" onClick={() => setDrawer(false)} aria-label={t.closeMenu}
                      className="flex h-9 w-9 items-center justify-center rounded-lg text-slate-300
                                 hover:bg-white/[0.05]">
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-3">
              <Suspense><CategoryNav collapsed={false} onNavigate={() => setDrawer(false)} /></Suspense>
            </div>
            <div className="flex flex-wrap items-center gap-2 border-t border-white/[0.06] p-3">
              <LocaleSelect />
              <UnitsToggle />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
