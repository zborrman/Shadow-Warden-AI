/**
 * portal/src/app/api/doc-scanner/route.ts
 * ─────────────────────────────────────────
 * Server-side proxy: forwards multipart file uploads to
 * the Warden gateway's /document-intel/convert-and-scan endpoint.
 * Injects X-API-Key from the server environment — never exposed to the browser.
 *
 * Env vars (server-side only):
 *   WARDEN_INTERNAL_URL  — gateway URL reachable from the portal server
 *   WARDEN_API_KEY       — gateway API key
 */
import { NextRequest, NextResponse } from 'next/server'
import { requirePortalSession } from '@/lib/server/portalSession'

const WARDEN_URL = process.env.WARDEN_INTERNAL_URL || process.env.NEXT_PUBLIC_API_URL || 'http://warden:8001'
const API_KEY    = process.env.WARDEN_API_KEY || ''

export async function POST(req: NextRequest): Promise<NextResponse> {
  // The key below is the server's; only a signed-in portal user may spend it.
  const user = await requirePortalSession(req)
  if (user instanceof NextResponse) return user
  // Forward raw multipart body verbatim (preserves Content-Type + boundary)
  const contentType = req.headers.get('content-type') ?? ''
  const body        = await req.arrayBuffer()

  try {
    const upstream = await fetch(`${WARDEN_URL}/document-intel/convert-and-scan`, {
      method:  'POST',
      headers: { 'Content-Type': contentType, 'X-API-Key': API_KEY },
      body,
    })

    const data = await upstream.json().catch(() => ({ detail: 'Invalid JSON from gateway' }))
    return NextResponse.json(data, { status: upstream.status })
  } catch (err) {
    console.error('[doc-scanner-proxy] upstream error:', err)
    return NextResponse.json({ detail: 'Gateway unreachable' }, { status: 502 })
  }
}
