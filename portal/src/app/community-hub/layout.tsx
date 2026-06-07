'use client'
import { Sidebar } from '@/components/layout/Sidebar'
import { Toaster } from 'react-hot-toast'

export default function CommunityHubLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen bg-dark-900 overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">{children}</main>
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
