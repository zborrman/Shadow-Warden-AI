'use client'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { ShieldCheck, LayoutDashboard, Key, Settings, LogOut, ExternalLink, Puzzle, Globe, Users } from 'lucide-react'
import { logout } from '@/lib/auth'
import { useRouter } from 'next/navigation'
import clsx from 'clsx'

const nav = [
  { href: '/dashboard/', label: 'Dashboard',  icon: LayoutDashboard },
  { href: '/hub/',       label: 'Warden Hub', icon: Globe },
  { href: '/api-keys/',  label: 'API Keys',   icon: Key },
  { href: '/extension/',   label: 'Extension',   icon: Puzzle },
  { href: '/communities/', label: 'Communities', icon: Users },
  { href: '/settings/',    label: 'Settings',    icon: Settings },
]

export function Sidebar() {
  const pathname = usePathname()
  const router   = useRouter()

  async function handleLogout() {
    await logout()
    router.replace('/login/')
  }

  return (
    <aside className="w-64 h-screen flex flex-col bg-dark-800 border-r border-white/[0.06] shrink-0">
      {/* Logo */}
      <div className="px-6 py-5 border-b border-white/[0.06]">
        <Link href="/dashboard/" className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-brand-gradient flex items-center justify-center shrink-0">
            <ShieldCheck className="w-5 h-5 text-white" />
          </div>
          <span className="font-bold text-white">Shadow Warden</span>
        </Link>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-0.5">
        {nav.map(({ href, label, icon: Icon }) => (
          <Link
            key={href}
            href={href}
            className={clsx(
              'flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-150',
              pathname.startsWith(href.replace(/\/$/, ''))
                ? 'bg-brand-400/10 text-brand-400 border border-brand-400/20'
                : 'text-slate-400 hover:text-slate-200 hover:bg-white/[0.04]'
            )}
          >
            <Icon className="w-4 h-4 shrink-0" />
            {label}
          </Link>
        ))}
      </nav>

      {/* Bottom */}
      <div className="px-3 py-4 border-t border-white/[0.06] space-y-1">
        <a
          href="https://shadow-warden-ai.com"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] transition-all"
        >
          <ExternalLink className="w-4 h-4" />
          Back to Website
        </a>
        <a
          href="https://shadow-warden-ai.com/docs"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] transition-all"
        >
          <ExternalLink className="w-4 h-4" />
          Documentation
        </a>
        <button
          onClick={handleLogout}
          className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm text-slate-400 hover:text-red-400 hover:bg-red-500/[0.06] transition-all"
        >
          <LogOut className="w-4 h-4" />
          Sign out
        </button>
      </div>
    </aside>
  )
}
