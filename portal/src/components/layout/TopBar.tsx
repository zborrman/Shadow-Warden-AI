'use client'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { Bell, User } from 'lucide-react'

export function TopBar({ title }: { title: string }) {
  const { data: me } = useQuery({
    queryKey: ['me'],
    queryFn:  () => api.get('/me').then(r => r.data),
    staleTime: 60_000,
  })

  return (
    <header className="h-16 border-b border-white/[0.06] flex items-center justify-between px-6 bg-dark-900/50 backdrop-blur-sm shrink-0">
      <h1 className="text-lg font-semibold text-white">{title}</h1>
      <div className="flex items-center gap-3">
        <button className="w-9 h-9 rounded-xl bg-white/[0.04] border border-white/[0.06] flex items-center justify-center text-slate-400 hover:text-slate-200 transition-colors">
          <Bell className="w-4 h-4" />
        </button>
        <div className="flex items-center gap-2.5 pl-3 border-l border-white/[0.06]">
          <div className="w-8 h-8 rounded-full bg-brand-gradient flex items-center justify-center shrink-0">
            <User className="w-4 h-4 text-white" />
          </div>
          <div className="text-right">
            <p className="text-sm font-medium text-white leading-none">
              {me?.display_name || me?.email?.split('@')[0] || '…'}
            </p>
            <p className="text-xs text-slate-500 mt-0.5">{me?.tenant_id || '…'}</p>
          </div>
        </div>
      </div>
    </header>
  )
}
