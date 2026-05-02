import type { Metadata } from 'next'
import './globals.css'
import { Providers } from './providers'
import AccessibilityWidget from '@/components/ui/AccessibilityWidget'

export const metadata: Metadata = {
  title: 'Shadow Warden — Portal',
  description: 'Manage your Shadow Warden AI security gateway.',
  icons: { icon: '/favicon.ico' },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body>
        <Providers>{children}</Providers>
        <AccessibilityWidget />
      </body>
    </html>
  )
}
