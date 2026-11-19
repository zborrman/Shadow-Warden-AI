'use client'
import { useState } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import {
  ShieldCheck, LogOut, ExternalLink, ChevronDown,
  Key, CreditCard, BookOpen, DollarSign, BarChart2,
  Sun, Moon, Store,
} from 'lucide-react'
import { logout } from '@/lib/auth'
import { useRouter } from 'next/navigation'
import clsx from 'clsx'
import { useTheme } from '@/components/ui/ThemeProvider'

type NavItem = { href: string; label: string; icon: React.ElementType }
type NavGroup = {
  id: string
  label: string
  accent: string
  icon: string
  items: NavItem[]
}

// Only screens whose API a portal session can reach. The portal session is
// accepted by /portal/* and by the store's owner routes (require_store_owner);
// every other gateway route wants an X-API-Key. Items for those screens were
// removed on 2026-11-19 - each one opened an empty page or the Overview again
// (13 pointed at `?tab=` values no page reads). The pages stay in the repo; a
// screen comes back to this menu when its API accepts the portal session.
const groups: NavGroup[] = [
  {
    id: 'store',
    label: 'Store',
    accent: '#BF5AF2',
    icon: '◈',
    items: [
      { href: '/store/manage/', label: 'Store Builder', icon: Store },
    ],
  },
  {
    id: 'account',
    label: 'Account',
    accent: '#0A84FF',
    icon: '◈',
    items: [
      { href: '/dashboard/', label: 'Overview', icon: BarChart2  },
      { href: '/api-keys/',  label: 'API Keys', icon: Key        },
      { href: '/settings/',  label: 'Settings', icon: CreditCard },
    ],
  },
]

const singleLinks = [
  { href: '/sdk/',                                  label: 'SDK & API', accent: '#30D158', icon: BookOpen,   external: false },
  { href: 'https://www.shadow-warden-ai.com/doc',   label: 'Docs',      accent: '#FFD60A', icon: BookOpen,   external: true  },
  { href: 'https://www.shadow-warden-ai.com/price', label: 'Price',     accent: '#FF8C42', icon: DollarSign, external: true  },
]

export function Sidebar() {
  const pathname = usePathname()
  const router   = useRouter()
  const { theme, toggle } = useTheme()
  const [open, setOpen] = useState<Record<string, boolean>>({ store: true, account: true })

  const isDark = theme === 'dark'
  const sidebarBg    = isDark ? '#0D0D14' : '#ffffff'
  const borderColor  = isDark ? 'rgba(255,255,255,0.06)' : '#e2e8f0'
  const textMuted    = isDark ? '#8E8E9E' : '#64748b'
  const dividerBg    = isDark ? 'rgba(255,255,255,0.05)' : '#e2e8f0'

  async function handleLogout() {
    await logout()
    router.replace('/login/')
  }

  function isGroupActive(group: NavGroup) {
    return group.items.some(i => pathname.startsWith(i.href.split('?')[0].replace(/\/$/, '')))
  }

  return (
    <aside className="w-64 h-screen flex flex-col shrink-0 overflow-y-auto"
           style={{ background: sidebarBg, borderRight: `1px solid ${borderColor}` }}>

      {/* Logo */}
      <div className="px-5 py-4 shrink-0" style={{ borderBottom: `1px solid ${borderColor}` }}>
        <Link href="/dashboard/" className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 text-sm"
               style={{ background: 'linear-gradient(135deg,#FF2D55,#FF6B35)', boxShadow: '0 0 14px rgba(255,45,85,0.35)' }}>
            🛡️
          </div>
          <div className="flex flex-col leading-none">
            <span className="text-[13px] font-bold" style={{ color: isDark ? '#ffffff' : '#0f172a' }}>Shadow Warden</span>
            <span className="text-[9px] font-bold tracking-wider" style={{ color: '#FF2D55' }}>v7.10 · LIVE</span>
          </div>
        </Link>
      </div>

      {/* Grouped nav */}
      <nav className="flex-1 px-2 py-3 space-y-0.5">
        {groups.map(group => {
          const isOpen = open[group.id] ?? false
          const active = isGroupActive(group)
          return (
            <div key={group.id}>
              {/* Group header */}
              <button
                onClick={() => setOpen(s => ({ ...s, [group.id]: !isOpen }))}
                className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-[12px] font-bold transition-all duration-150"
                style={{
                  color: active || isOpen ? group.accent : textMuted,
                  background: active || isOpen ? `color-mix(in srgb,${group.accent} 8%,transparent)` : 'transparent',
                }}
              >
                <span className="text-[10px]" style={{ color: group.accent }}>{group.icon}</span>
                <span className="flex-1 text-left">{group.label}</span>
                <ChevronDown
                  className="w-3.5 h-3.5 shrink-0 transition-transform duration-200"
                  style={{ transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)' }}
                />
              </button>

              {/* Group items */}
              {isOpen && (
                <div className="mt-0.5 ml-3 pl-3 space-y-0.5"
                     style={{ borderLeft: `1px solid color-mix(in srgb,${group.accent} 20%,transparent)` }}>
                  {group.items.map(({ href, label, icon: Icon }) => {
                    const base = href.split('?')[0].replace(/\/$/, '')
                    const isActive = pathname.replace(/\/$/, '') === base
                    return (
                      <Link
                        key={href}
                        href={href}
                        className="flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-[12px] font-medium transition-all duration-100"
                        style={{
                          color: isActive ? group.accent : textMuted,
                          background: isActive ? `color-mix(in srgb,${group.accent} 10%,transparent)` : 'transparent',
                        }}
                      >
                        <Icon className="w-3.5 h-3.5 shrink-0" />
                        {label}
                      </Link>
                    )
                  })}
                </div>
              )}
            </div>
          )
        })}

        {/* Divider */}
        <div className="my-2 mx-3 h-px" style={{ background: dividerBg }} />

        {/* Single links: Docs + Price */}
        {singleLinks.map(({ href, label, accent, icon: Icon, external }) => (
          <Link
            key={href}
            href={href}
            target={external ? '_blank' : undefined}
            rel={external ? 'noopener noreferrer' : undefined}
            className="flex items-center gap-2.5 px-3 py-2 rounded-xl text-[12px] font-bold transition-all duration-150"
            style={{ color: accent }}
          >
            <Icon className="w-3.5 h-3.5 shrink-0" />
            {label}
            {external && <ExternalLink className="w-3 h-3 ml-auto opacity-50" />}
          </Link>
        ))}
      </nav>

      {/* Bottom actions */}
      <div className="px-2 py-3 shrink-0" style={{ borderTop: `1px solid ${borderColor}` }}>
        {/* Theme toggle */}
        <button
          onClick={toggle}
          className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-[12px] transition-all duration-150"
          style={{ color: textMuted }}
          aria-label="Toggle theme"
        >
          {isDark
            ? <Sun className="w-3.5 h-3.5 shrink-0" />
            : <Moon className="w-3.5 h-3.5 shrink-0" />}
          {isDark ? 'Light mode' : 'Dark mode'}
        </button>

        <a
          href="https://shadow-warden-ai.com"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2.5 px-3 py-2 rounded-xl text-[12px] transition-all"
          style={{ color: textMuted }}
        >
          <ExternalLink className="w-3.5 h-3.5" />
          Back to Website
        </a>
        <button
          onClick={handleLogout}
          className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-[12px] text-slate-400 hover:text-red-400 transition-all"
        >
          <LogOut className="w-3.5 h-3.5" />
          Sign out
        </button>
      </div>
    </aside>
  )
}
