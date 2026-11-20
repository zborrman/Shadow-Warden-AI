'use client'
import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { getAccessToken, setAccessToken, api } from '@/lib/api'
import { Toaster } from 'react-hot-toast'
import { Sidebar } from '@/components/layout/Sidebar'

export default function SettingsLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  useEffect(() => {
    if (!getAccessToken()) {
      api.post('/auth/refresh')
        .then(r => setAccessToken(r.data.access_token))
        .catch(() => router.replace('/login/'))
    }
  }, [router])
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <main className="flex-1 flex flex-col min-w-0 overflow-y-auto">{children}</main>
      <Toaster position="bottom-right" toastOptions={{ duration: 3500, style: {
        background: '#1a1f35', color: '#e2e8f0', border: '1px solid rgba(99,102,241,0.25)', fontSize: '13px',
      } }} />
    </div>
  )
}
