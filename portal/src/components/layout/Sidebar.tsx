'use client'
import { useState } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import {
  ShieldCheck, LogOut, ExternalLink, ChevronDown,
  Users, Network, Star, Database,
  Zap, Eye, FileText, Bot,
  BarChart2, List, Search, Activity, GitBranch,
  Key, Lock, Globe, Trash2, CreditCard,
  BookOpen, DollarSign,
} from 'lucide-react'
import { logout } from '@/lib/auth'
import { useRouter } from 'next/navigation'
import clsx from 'clsx'

type NavItem = { href: string; label: string; icon: React.ElementType }
type NavGroup = {
  id: string
  label: string
  accent: string
  icon: string
  items: NavItem[]
}

const groups: NavGroup[] = [
  {
    id: 'community',
    label: 'Business Community',
    accent: '#BF5AF2',
    icon: '◈',
    items: [
      { href: '/communities/',  label: 'Communities',   icon: Users    },
      { href: '/hub/',          label: 'SEP Hub',        icon: Network  },
      { href: '/dashboard/?tab=reputation', label: 'Reputation', icon: Star },
      { href: '/dashboard/?tab=pods',       label: 'Data Pods',  icon: Database },
    ],
  },
  {
    id: 'security',
    label: 'Cyber Security',
    accent: '#FF2D55',
    icon: '◈',
    items: [
      { href: '/dashboard/?tab=events',    label: 'Filter Events',  icon: Zap      },
      { href: '/dashboard/?tab=shadow-ai', label: 'Shadow AI',      icon: Eye      },
      { href: '/dashboard/?tab=xai',       label: 'XAI Reports',    icon: FileText },
      { href: '/dashboard/?tab=agents',    label: 'Agent Monitor',  icon: Bot      },
    ],
  },
  {
    id: 'dashboard',
    label: 'Dashboard',
    accent: '#0A84FF',
    icon: '◈',
    items: [
      { href: '/dashboard/',               label: 'Overview',       icon: BarChart2  },
      { href: '/dashboard/?tab=log',       label: 'Event Log',      icon: List       },
      { href: '/dashboard/?tab=intel',     label: 'Threat Intel',   icon: Search     },
      { href: '/dashboard/?tab=metrics',   label: 'Metrics',        icon: Activity   },
      { href: '/dashboard/?tab=traces',    label: 'Traces',         icon: GitBranch  },
    ],
  },
  {
    id: 'settings',
    label: 'Settings',
    accent: '#30D158',
    icon: '◈',
    items: [
      { href: '/api-keys/',                label: 'API Keys',         icon: Key       },
      { href: '/settings/?tab=secrets',    label: 'Secrets Vault',    icon: Lock      },
      { href: '/settings/?tab=sovereign',  label: 'Sovereign Routing',icon: Globe     },
      { href: '/settings/?tab=gdpr',       label: 'GDPR Controls',    icon: Trash2    },
      { href: '/settings/',                label: 'Billing',          icon: CreditCard},
    ],
  },
]

const singleLinks = [
  { href: 'https://shadow-warden-ai.com#docs',  label: 'Docs',  accent: '#FFD60A', icon: BookOpen,    external: true },
  { href: '/settings/?tab=billing',              label: 'Price', accent: '#FF8C42', icon: DollarSign,  external: false },
]

export function Sidebar() {
  const pathname = usePathname()
  const router   = useRouter()
  const [open, setOpen] = useState<Record<string, boolean>>({ dashboard: true })

  async function handleLogout() {
    await logout()
    router.replace('/login/')
  }

  function isGroupActive(group: NavGroup) {
    return group.items.some(i => pathname.startsWith(i.href.split('?')[0].replace(/\/$/, '')))
  }

  return (
    <aside className="w-64 h-screen flex flex-col shrink-0 overflow-y-auto"
           style={{ background: '#0D0D14', borderRight: '1px solid rgba(255,255,255,0.06)' }}>

      {/* Logo */}
      <div className="px-5 py-4 shrink-0" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <Link href="/dashboard/" className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 text-sm"
               style={{ background: 'linear-gradient(135deg,#FF2D55,#FF6B35)', boxShadow: '0 0 14px rgba(255,45,85,0.35)' }}>
            🛡️
          </div>
          <div className="flex flex-col leading-none">
            <span className="text-[13px] font-bold text-white">Shadow Warden</span>
            <span className="text-[9px] font-bold tracking-wider" style={{ color: '#FF2D55' }}>v4.19 · LIVE</span>
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
                  color: active || isOpen ? group.accent : '#8E8E9E',
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
                          color: isActive ? group.accent : '#8E8E9E',
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
        <div className="my-2 mx-3 h-px" style={{ background: 'rgba(255,255,255,0.05)' }} />

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
      <div className="px-2 py-3 shrink-0" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
        <a
          href="https://shadow-warden-ai.com"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2.5 px-3 py-2 rounded-xl text-[12px] text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] transition-all"
        >
          <ExternalLink className="w-3.5 h-3.5" />
          Back to Website
        </a>
        <button
          onClick={handleLogout}
          className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-[12px] text-slate-400 hover:text-red-400 transition-all"
          style={{ ['--hover-bg' as string]: 'rgba(239,68,68,0.06)' }}
        >
          <LogOut className="w-3.5 h-3.5" />
          Sign out
        </button>
      </div>
    </aside>
  )
}
