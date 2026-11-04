'use client'
import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Toaster } from 'react-hot-toast'
import { getAccessToken, setAccessToken, api } from '@/lib/api'
import { Sidebar } from '@/components/layout/Sidebar'

export default function StoreManageLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  // Every call here acts on the signed-in user's own tenant, so nothing is
  // fetched until a session token is in hand.
  const [ready, setReady] = useState(() => Boolean(getAccessToken()))

  useEffect(() => {
    if (getAccessToken()) { setReady(true); return }
    api.post('/auth/refresh')
      .then(r => { setAccessToken(r.data.access_token); setReady(true) })
      .catch(() => router.replace('/login/'))
  }, [router])

  return (
    <div className="flex h-screen bg-dark-900 overflow-hidden">
      <Sidebar />
      <main className="flex-1 flex flex-col min-w-0 overflow-y-auto">
        {ready ? children : <div className="p-8 text-sm text-slate-500">Loading…</div>}
      </main>
      <Toaster
        position="bottom-right"
        toastOptions={{
          duration: 3500,
          style: {
            background: '#1a1f35',
            color:      '#e2e8f0',
            border:     '1px solid rgba(99,102,241,0.25)',
            fontSize:   '13px',
          },
          success: { iconTheme: { primary: '#34d399', secondary: '#1a1f35' } },
          error:   { iconTheme: { primary: '#f87171', secondary: '#1a1f35' } },
        }}
      />
    </div>
  )
}
