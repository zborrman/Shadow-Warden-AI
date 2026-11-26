import { AppShell } from '@/components/layout/AppShell'

export default function SdkLayout({ children }: { children: React.ReactNode }) {
  return <AppShell>{children}</AppShell>
}
