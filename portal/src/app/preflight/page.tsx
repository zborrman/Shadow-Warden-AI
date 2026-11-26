'use client'
import { TopBar } from '@/components/layout/TopBar'

// The simulator is a self-contained page (public/preflight/sim.html) shown in a
// sandboxed frame: no allow-same-origin, so it runs in an opaque origin and can
// reach neither the portal's session nor its styles. It works only in the
// browser; nothing the seller types is sent anywhere. Its own header carries the
// title, the description and the not-affiliated / simulation notice.
export default function PreflightPage() {
  return (
    <>
      <TopBar title="Listing Preflight" />
      <div className="flex flex-col p-6 min-h-0 flex-1">
        <iframe
          src="/preflight/sim.html"
          title="Listing Preflight simulator"
          sandbox="allow-scripts allow-downloads allow-popups allow-popups-to-escape-sandbox"
          allow="clipboard-write"
          referrerPolicy="no-referrer"
          className="w-full flex-1 min-h-[1100px] rounded-lg border border-white/10 bg-white"
        />
      </div>
    </>
  )
}
