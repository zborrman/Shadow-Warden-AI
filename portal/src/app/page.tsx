'use client'
import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { refreshSession } from '@/lib/auth'

export default function Home() {
  const router = useRouter()
  useEffect(() => {
    refreshSession().then(ok => {
      router.replace(ok ? '/dashboard/' : '/login/')
    })
  }, [router])
  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="w-8 h-8 border-2 border-brand-400 border-t-transparent rounded-full animate-spin" />
    </div>
  )
}
