'use client'
// Portal sidebar — the marketing site's shell (site/src/layouts/BaseLayout.astro +
// styles/shell.css), so the seller moves between site and portal without the
// frame changing: brand, quick links with NEW badges, hub sections with coloured
// square markers and mono uppercase labels, theme + sign-out at the foot.
// Below 1024px it becomes a top bar with a drawer, as on the site.
import { useEffect, useState } from 'react'
import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import {
  BarChart2, BookOpen, ChevronRight, ClipboardCheck, Code2, ExternalLink, Globe, Key,
  LogOut, Menu, Moon, Settings, Store, Sun, Tag, X,
} from 'lucide-react'
import { logout } from '@/lib/auth'
import { useTheme } from '@/components/ui/ThemeProvider'

type Item = { href: string; label: string; icon: React.ElementType; badge?: string; external?: boolean }
type Hub = { label: string; color: string; items: Item[] }

const SITE = 'https://www.shadow-warden-ai.com'

// Only screens a portal session can reach (2026-11-19 cut): /portal/* and the
// store's owner routes. Hub colours are the site's own.
export const QUICK: Item[] = [
  { href: '/preflight/', label: 'Listing Preflight', icon: ClipboardCheck, badge: 'New' },
  { href: '/dashboard/', label: 'Overview', icon: BarChart2 },
]
export const HUBS: Hub[] = [
  { label: 'Sell', color: '#4d9cfc', items: [{ href: '/store/manage/', label: 'Store Builder', icon: Store }] },
  { label: 'Develop', color: '#fbbf24', items: [
    { href: '/api-keys/', label: 'API Keys', icon: Key },
    { href: '/sdk/', label: 'SDK & API', icon: Code2 },
  ] },
  { label: 'Account', color: '#fb923c', items: [{ href: '/settings/', label: 'Settings', icon: Settings }] },
  { label: 'Resources', color: '#34d399', items: [
    { href: `${SITE}/doc`, label: 'Documentation', icon: BookOpen, external: true },
    { href: `${SITE}/price`, label: 'Pricing', icon: Tag, external: true },
    { href: SITE, label: 'Website', icon: Globe, external: true },
  ] },
]

const trim = (p: string) => p.replace(/\/$/, '') || '/'
export const isOn = (path: string, i: Item) => !i.external && trim(path).startsWith(trim(i.href))

/** The section and page a path belongs to, for the breadcrumb. */
export function locate(path: string): { hub?: string; page?: string } {
  const q = QUICK.find(i => isOn(path, i))
  if (q) return { page: q.label }
  for (const h of HUBS) {
    const i = h.items.find(x => isOn(path, x))
    if (i) return { hub: h.label, page: i.label }
  }
  return {}
}

function Row({ item, path, onNavigate }: { item: Item; path: string; onNavigate?: () => void }) {
  const Icon = item.icon
  const on = isOn(path, item)
  const cls = 'sw-item'
  const body = (
    <>
      <Icon className="sw-item__icon" width={16} height={16} strokeWidth={1.75} aria-hidden />
      <span className="sw-item__label">{item.label}</span>
      {item.badge && <span className="sw-badge">{item.badge}</span>}
      {item.external && <ExternalLink className="sw-item__ext" width={12} height={12} aria-hidden />}
    </>
  )
  return item.external
    ? <a href={item.href} className={cls} target="_blank" rel="noopener noreferrer">{body}</a>
    : <Link href={item.href} className={cls} aria-current={on ? 'page' : undefined} onClick={onNavigate}>{body}</Link>
}

function Nav({ path, onNavigate }: { path: string; onNavigate?: () => void }) {
  const [open, setOpen] = useState<Record<string, boolean>>({})
  const isOpen = (h: Hub) => open[h.label] ?? true
  return (
    <>
      <ul className="sw-quick">
        {QUICK.map(i => <li key={i.href}><Row item={i} path={path} onNavigate={onNavigate} /></li>)}
      </ul>
      {HUBS.map((h, n) => (
        <div key={h.label} className="sw-hub" data-open={isOpen(h) ? 'true' : 'false'}
             style={{ ['--hub' as string]: h.color }}>
          <div className="sw-hub__head">
            <span className="sw-hub__link"><span className="sw-hub__mark" aria-hidden />
              <span className="sw-hub__label">{h.label}</span></span>
            <button type="button" className="sw-hub__toggle" aria-expanded={isOpen(h)} aria-controls={`hub-${n}`}
                    aria-label={`${h.label} section`} onClick={() => setOpen(o => ({ ...o, [h.label]: !isOpen(h) }))}>
              <ChevronRight width={14} height={14} strokeWidth={2} aria-hidden />
            </button>
          </div>
          <div className="sw-hub__body" id={`hub-${n}`}>
            <ul className="sw-hub__list">
              {h.items.map(i => <li key={i.href}><Row item={i} path={path} onNavigate={onNavigate} /></li>)}
            </ul>
          </div>
        </div>
      ))}
    </>
  )
}

export function Sidebar() {
  const path = usePathname() || '/'
  const router = useRouter()
  const { theme, toggle } = useTheme()
  const [drawer, setDrawer] = useState(false)

  useEffect(() => { setDrawer(false) }, [path])
  useEffect(() => {
    if (!drawer) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setDrawer(false) }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [drawer])

  async function signOut() {
    await logout()
    router.replace('/login/')
  }

  const ThemeIcon = theme === 'dark' ? Sun : Moon
  return (
    <>
      <header className="sw-side">
        <div className="sw-side__brand">
          <Link href="/dashboard/" className="sw-brand" aria-label="Shadow Warden — workspace home">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src="/logo.png" alt="" width={63} height={34} />
            <span className="sw-brand__name">Shadow Warden<span className="sw-brand__ai">AI</span></span>
          </Link>
        </div>

        <div className="sw-side__cta">
          <Link href="/preflight/" className="sw-cta">Check a listing</Link>
          <button type="button" className="sw-iconbtn sw-only-mobile" aria-label={drawer ? 'Close menu' : 'Open menu'}
                  aria-controls="portal-drawer" aria-expanded={drawer} onClick={() => setDrawer(d => !d)}>
            {drawer ? <X width={18} height={18} aria-hidden /> : <Menu width={18} height={18} aria-hidden />}
          </button>
        </div>

        <nav className="sw-side__nav" aria-label="Workspace">
          <Nav path={path} />
        </nav>

        <div className="sw-side__foot">
          <div className="sw-foot__row">
            <button type="button" className="sw-item sw-theme" onClick={toggle} aria-label="Switch colour theme">
              <ThemeIcon className="sw-item__icon" width={16} height={16} strokeWidth={1.75} aria-hidden />
              <span className="sw-item__label">{theme === 'dark' ? 'Light theme' : 'Dark theme'}</span>
            </button>
          </div>
          <button type="button" className="sw-item sw-item--danger" onClick={signOut}>
            <LogOut className="sw-item__icon" width={16} height={16} strokeWidth={1.75} aria-hidden />
            <span className="sw-item__label">Sign out</span>
          </button>
        </div>
      </header>

      {drawer && (
        <div id="portal-drawer" className="sw-drawer" role="dialog" aria-modal="true" aria-label="Workspace menu"
             onClick={e => { if (e.target === e.currentTarget) setDrawer(false) }}>
          <div className="sw-drawer__panel">
            <Nav path={path} onNavigate={() => setDrawer(false)} />
            <div className="sw-drawer__foot">
              <button type="button" className="sw-item" onClick={toggle}>
                <ThemeIcon className="sw-item__icon" width={16} height={16} strokeWidth={1.75} aria-hidden />
                <span className="sw-item__label">Switch theme</span>
              </button>
              <button type="button" className="sw-item sw-item--danger" onClick={signOut}>
                <LogOut className="sw-item__icon" width={16} height={16} strokeWidth={1.75} aria-hidden />
                <span className="sw-item__label">Sign out</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
