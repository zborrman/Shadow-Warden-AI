'use client'
import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { getAccessToken, setAccessToken } from '@/lib/api'
import { api } from '@/lib/api'
import { Sidebar } from '@/components/layout/Sidebar'

export default function PortalLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()

  useEffect(() => {
    if (!getAccessToken()) {
      // Try refresh from cookie
      api.post('/auth/refresh')
        .then(r => { setAccessToken(r.data.access_token) })
        .catch(() => router.replace('/login/'))
    }
  }, [router])

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <main className="flex-1 flex flex-col min-w-0 overflow-y-auto">
        {children}
      </main>
    </div>
  )
}
