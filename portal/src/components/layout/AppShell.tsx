'use client'
// Every signed-in portal screen sits in this frame: the site's sidebar and a
// content column. Nothing is rendered until a session token is in hand, so no
// page fires a request on behalf of nobody; without a session the browser goes
// to the sign-in page.
import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Toaster } from 'react-hot-toast'
import { api, getAccessToken, setAccessToken } from '@/lib/api'
import { Sidebar } from '@/components/layout/Sidebar'

export function AppShell({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const [ready, setReady] = useState(false)

  useEffect(() => {
    if (getAccessToken()) { setReady(true); return }
    api.post('/auth/refresh')
      .then(r => { setAccessToken(r.data.access_token); setReady(true) })
      .catch(() => router.replace('/login/'))
  }, [router])

  return (
    <div className="pw-scope">
      <Sidebar />
      <div className="sw-main">
        <main id="main" className="pw-content">
          {ready ? children : <p className="pw-loading" role="status">Loading your workspace…</p>}
        </main>
      </div>
      <Toaster
        position="bottom-right"
        toastOptions={{
          duration: 3500,
          className: 'pw-toast',
          style: {
            background: 'var(--sw-surf-1)',
            color: 'var(--ink-1)',
            border: '1px solid var(--sw-border-strong)',
            boxShadow: 'var(--sw-shadow-lg)',
            fontSize: '13px',
          },
        }}
      />
    </div>
  )
}
