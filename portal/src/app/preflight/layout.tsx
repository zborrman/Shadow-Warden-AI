import { AppShell } from '@/components/layout/AppShell'

export default function PreflightLayout({ children }: { children: React.ReactNode }) {
  return <AppShell>{children}</AppShell>
}
