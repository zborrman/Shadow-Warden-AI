'use client'
// Portal shell: an icon rail (sections) beside a collapsible panel (the pages of
// the current section), the layout of a settings console. One component, used by
// every signed-in layout, so the whole portal moves together.
import { useEffect, useState } from 'react'
import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import {
  BarChart2, BookOpen, ChevronsLeft, ChevronsRight, ExternalLink,
  Key, LogOut, Moon, Settings, Store, Sun,
} from 'lucide-react'
import clsx from 'clsx'
import { logout } from '@/lib/auth'
import { useTheme } from '@/components/ui/ThemeProvider'

type Item = { href: string; label: string; external?: boolean }
type Section = { id: string; label: string; icon: React.ElementType; groups: { label: string; items: Item[] }[] }

// Only screens whose API a portal session can reach (see 2026-11-19 cut): the
// portal session is accepted by /portal/* and the store's owner routes.
const SECTIONS: Section[] = [
  { id: 'store', label: 'Store', icon: Store, groups: [
    { label: 'Store', items: [{ href: '/store/manage/', label: 'Store Builder' }] },
  ] },
  { id: 'overview', label: 'Overview', icon: BarChart2, groups: [
    { label: 'Account', items: [{ href: '/dashboard/', label: 'Overview' }] },
  ] },
  { id: 'keys', label: 'API Keys', icon: Key, groups: [
    { label: 'Developer', items: [{ href: '/api-keys/', label: 'API Keys' }, { href: '/sdk/', label: 'SDK & API' }] },
  ] },
  { id: 'settings', label: 'Settings', icon: Settings, groups: [
    { label: 'Account', items: [{ href: '/settings/', label: 'Account settings' }] },
  ] },
  { id: 'resources', label: 'Docs', icon: BookOpen, groups: [
    { label: 'Resources', items: [
      { href: 'https://www.shadow-warden-ai.com/doc', label: 'Documentation', external: true },
      { href: 'https://www.shadow-warden-ai.com/price', label: 'Pricing', external: true },
      { href: 'https://www.shadow-warden-ai.com', label: 'Website', external: true },
    ] },
  ] },
]

const trim = (p: string) => p.replace(/\/$/, '')
const owns = (s: Section, path: string) =>
  s.groups.some(g => g.items.some(i => !i.external && trim(path).startsWith(trim(i.href))))

export function Sidebar() {
  const pathname = usePathname() || '/'
  const router = useRouter()
  const { theme, toggle } = useTheme()
  const current = SECTIONS.find(s => owns(s, pathname)) ?? SECTIONS[1]
  const [picked, setPicked] = useState<string | null>(null)
  const [collapsed, setCollapsed] = useState(false)
  const section = SECTIONS.find(s => s.id === picked) ?? current

  // Browser-only preference read after hydration (server render is always expanded).
  useEffect(() => { setCollapsed(localStorage.getItem('sw_nav_collapsed') === '1') }, [])
  useEffect(() => { setPicked(null) }, [pathname])

  function setCollapse(v: boolean) {
    setCollapsed(v)
    localStorage.setItem('sw_nav_collapsed', v ? '1' : '0')
  }

  async function signOut() {
    await logout()
    router.replace('/login/')
  }

  const railBtn = 'flex w-14 flex-col items-center gap-1 rounded-lg py-2 text-[10px] font-medium transition-colors'

  return (
    <div className="flex h-screen shrink-0">
      {/* Rail */}
      <nav aria-label="Sections" className="flex w-[72px] flex-col items-center gap-1 border-r border-white/[0.06] bg-dark-950 py-3">
        <Link href="/dashboard/" aria-label="Shadow Warden home"
              className="mb-3 flex h-9 w-9 items-center justify-center rounded-lg bg-brand-500 text-sm font-bold text-white">
          SW
        </Link>
        {SECTIONS.map(s => {
          const Icon = s.icon
          const on = s.id === section.id
          return (
            <button key={s.id} type="button" aria-current={on ? 'true' : undefined}
                    onClick={() => { setPicked(s.id); if (collapsed) setCollapse(false) }}
                    className={clsx(railBtn, on ? 'text-white' : 'text-slate-400 hover:text-slate-200')}>
              <span className={clsx('flex h-9 w-9 items-center justify-center rounded-lg',
                                    on ? 'bg-brand-500/25 ring-1 ring-brand-500/60' : 'hover:bg-white/[0.06]')}>
                <Icon className="h-[18px] w-[18px]" />
              </span>
              {s.label}
            </button>
          )
        })}
        <div className="mt-auto flex flex-col items-center gap-1">
          <button type="button" onClick={toggle} aria-label="Toggle theme" className={clsx(railBtn, 'text-slate-400 hover:text-slate-200')}>
            {theme === 'dark' ? <Sun className="h-[18px] w-[18px]" /> : <Moon className="h-[18px] w-[18px]" />}
          </button>
          <button type="button" onClick={signOut} aria-label="Sign out" className={clsx(railBtn, 'text-slate-400 hover:text-red-400')}>
            <LogOut className="h-[18px] w-[18px]" />
          </button>
        </div>
      </nav>

      {/* Panel */}
      {collapsed ? (
        <div className="flex w-6 items-start justify-center border-r border-white/[0.06] bg-dark-900 pt-4">
          <button type="button" aria-label="Expand navigation" onClick={() => setCollapse(false)}
                  className="text-slate-400 hover:text-slate-200"><ChevronsRight className="h-4 w-4" /></button>
        </div>
      ) : (
        <aside aria-label={`${section.label} pages`} className="flex w-60 flex-col overflow-y-auto border-r border-white/[0.06] bg-dark-900">
          <div className="flex h-12 items-center justify-between px-4">
            <span className="text-sm font-semibold text-slate-100">{section.label}</span>
            <button type="button" aria-label="Collapse navigation" onClick={() => setCollapse(true)}
                    className="text-slate-400 hover:text-slate-200"><ChevronsLeft className="h-4 w-4" /></button>
          </div>
          <div className="space-y-5 px-2 pb-4">
            {section.groups.map(g => (
              <div key={g.label}>
                <p className="px-3 pb-1.5 text-[13px] font-semibold text-slate-200">{g.label}</p>
                <ul className="space-y-0.5">
                  {g.items.map(i => {
                    const on = !i.external && trim(pathname) === trim(i.href)
                    return (
                      <li key={i.href}>
                        <Link href={i.href} target={i.external ? '_blank' : undefined}
                              rel={i.external ? 'noopener noreferrer' : undefined}
                              aria-current={on ? 'page' : undefined}
                              className={clsx('flex items-center gap-2 rounded-md border px-3 py-1.5 text-sm transition-colors',
                                on ? 'border-brand-500/60 bg-brand-500/20 text-white'
                                   : 'border-transparent text-slate-400 hover:bg-white/[0.04] hover:text-slate-200')}>
                          <span className="flex-1">{i.label}</span>
                          {i.external && <ExternalLink className="h-3 w-3 opacity-60" />}
                        </Link>
                      </li>
                    )
                  })}
                </ul>
              </div>
            ))}
          </div>
        </aside>
      )}
    </div>
  )
}
