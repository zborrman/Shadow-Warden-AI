import { Sidebar } from '@/components/layout/Sidebar'

export default function CommunitiesLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen bg-dark-900 overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">{children}</main>
    </div>
  )
}
