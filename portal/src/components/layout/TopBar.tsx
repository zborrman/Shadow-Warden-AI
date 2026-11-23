'use client'
// Page header in the console layout: a breadcrumb on the left, the signed-in
// account on the right.
import Link from 'next/link'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'

export function TopBar({ title }: { title: string }) {
  const { data: me } = useQuery({
    queryKey: ['me'],
    queryFn:  () => api.get('/me').then(r => r.data),
    staleTime: 60_000,
  })
  const name: string = me?.display_name || me?.email?.split('@')[0] || ''

  return (
    <header className="flex h-12 shrink-0 items-center justify-between border-b border-white/[0.06] bg-dark-900 px-6">
      <nav aria-label="Breadcrumb" className="flex items-center gap-2 text-sm">
        <Link href="/dashboard/" className="text-slate-400 hover:text-slate-200">Shadow Warden</Link>
        <span className="text-slate-500" aria-hidden>/</span>
        <h1 className="font-semibold text-slate-100">{title}</h1>
      </nav>
      <div className="flex items-center gap-2.5">
        <span className="hidden text-right sm:block">
          <span className="block text-sm font-medium leading-none text-slate-100">{name || '…'}</span>
          <span className="mt-0.5 block text-xs text-slate-400">{me?.tenant_id || '…'}</span>
        </span>
        <span className="flex h-8 w-8 items-center justify-center rounded-md bg-brand-500 text-xs font-bold text-white" aria-hidden>
          {(name || 'SW').slice(0, 2).toUpperCase()}
        </span>
      </div>
    </header>
  )
}
