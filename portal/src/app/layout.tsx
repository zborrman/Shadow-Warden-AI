import type { Metadata } from 'next'
import './globals.css'
import '@/styles/tokens.css'
import '@/styles/shell.css'
import '@/styles/portal-shell.css'
import { Providers } from './providers'
import AccessibilityWidget from '@/components/ui/AccessibilityWidget'

export const metadata: Metadata = {
  title: 'Shadow Warden — Portal',
  description: 'Manage your Shadow Warden AI security gateway.',
  icons: { icon: '/favicon.ico' },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        {/* Anti-FOUT: stored theme, else light like the site; the public storefront
            keeps the dark default its accessibility audit runs against. */}
        <script dangerouslySetInnerHTML={{ __html:
          `try{var t=localStorage.getItem('sw-theme');if(t!=='light'&&t!=='dark')t=location.pathname.indexOf('/s/')===0?'dark':'light';var r=document.documentElement;r.setAttribute('data-theme',t);r.classList.add(t)}catch(e){}`
        }} />
      </head>
      <body>
        <Providers>{children}</Providers>
        <AccessibilityWidget />
      </body>
    </html>
  )
}
