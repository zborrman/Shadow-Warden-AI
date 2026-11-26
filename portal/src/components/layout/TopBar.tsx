'use client'
// Page header — the site's sticky top bar (.sw-topbar): breadcrumb trail on the
// left, a few links and the signed-in account on the right.
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { locate } from '@/components/layout/Sidebar'

const SITE = 'https://www.shadow-warden-ai.com'

export function TopBar({ title }: { title: string }) {
  const path = usePathname() || '/'
  const { hub } = locate(path)
  const { data: me } = useQuery({
    queryKey: ['me'],
    queryFn:  () => api.get('/me').then(r => r.data),
    staleTime: 60_000,
  })
  const name: string = me?.display_name || me?.email?.split('@')[0] || ''

  return (
    <div className="sw-topbar">
      <nav aria-label="Breadcrumb" className="sw-crumbs">
        <ol>
          <li><Link href="/dashboard/">Workspace</Link></li>
          {hub && <li><span className="sw-crumbs__sep" aria-hidden="true">/</span><span>{hub}</span></li>}
          <li><span className="sw-crumbs__sep" aria-hidden="true">/</span><h1 aria-current="page" className="pw-crumb-title">{title}</h1></li>
        </ol>
      </nav>
      <div className="sw-topbar__actions">
        <a href={`${SITE}/doc`} className="sw-toplink" target="_blank" rel="noopener noreferrer">Docs</a>
        <a href={`${SITE}/status`} className="sw-toplink" target="_blank" rel="noopener noreferrer">Status</a>
        <Link href="/settings/" className="pw-account" aria-label={`Account settings${name ? ` for ${name}` : ''}`}>
          <span className="pw-account__text">
            <span className="pw-account__name">{name || '…'}</span>
            <span className="pw-account__tenant">{me?.tenant_id || '…'}</span>
          </span>
          <span className="sw-avatar pw-account__avatar" aria-hidden="true">{(name || 'SW').slice(0, 2).toUpperCase()}</span>
        </Link>
      </div>
    </div>
  )
}
