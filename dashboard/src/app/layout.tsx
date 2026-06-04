import type { Metadata } from "next";
import "./globals.css";
import { Providers } from "./providers";

export const metadata: Metadata = {
  title: "Shadow Warden AI — SOC Dashboard",
  description: "AI security gateway — security operations center",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        {/* Anti-FOUT: apply stored theme before first paint */}
        <script dangerouslySetInnerHTML={{ __html:
          `try{var t=localStorage.getItem('sw-theme');if(t==='light'||t==='dark')document.documentElement.setAttribute('data-theme',t)}catch(e){}`
        }} />
      </head>
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
