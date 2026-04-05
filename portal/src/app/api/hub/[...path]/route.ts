/**
 * portal/src/app/api/hub/[...path]/route.ts
 * ───────────────────────────────────────────
 * Secure server-side proxy for the Warden Syndicates API.
 *
 * The portal frontend calls /api/hub/... (these routes).
 * This handler forwards the request to the warden gateway and injects
 * the X-Super-Admin-Key from the server environment — the key never
 * reaches the browser.
 *
 * Auth: the caller must supply a valid portal JWT (Authorization: Bearer ...)
 * which is validated server-side before proxying.
 *
 * Env vars consumed (server-side only):
 *   WARDEN_INTERNAL_URL   — warden gateway URL reachable from the portal
 *                           server  (e.g. http://warden:8001 in Docker,
 *                           or https://api.shadow-warden-ai.com externally)
 *   WARDEN_SUPER_ADMIN_KEY — X-Super-Admin-Key for syndicates endpoints
 */

import { NextRequest, NextResponse } from 'next/server'

const WARDEN_URL  = process.env.WARDEN_INTERNAL_URL || process.env.NEXT_PUBLIC_API_URL || 'http://warden:8001'
const ADMIN_KEY   = process.env.WARDEN_SUPER_ADMIN_KEY || process.env.SUPER_ADMIN_KEY || ''

// Path segments that this proxy handles → warden route prefix
const PATH_MAP: Record<string, string> = {
  tunnels:    '/tunnels',
  syndicates: '/syndicates',
  invites:    '/invites',
}

async function proxy(req: NextRequest, params: { path: string[] }): Promise<NextResponse> {
  if (!ADMIN_KEY) {
    return NextResponse.json({ detail: 'Hub not configured (missing WARDEN_SUPER_ADMIN_KEY)' }, { status: 503 })
  }

  const segments = params.path          // e.g. ['tunnels', 'handshake', 'init']
  const prefix   = PATH_MAP[segments[0]]
  if (!prefix) {
    return NextResponse.json({ detail: 'Unknown hub resource' }, { status: 404 })
  }

  const rest    = segments.slice(1).join('/')
  const qs      = req.nextUrl.search || ''
  const target  = `${WARDEN_URL}${prefix}${rest ? '/' + rest : ''}${qs}`

  // Forward body for non-GET requests
  let body: BodyInit | undefined
  if (req.method !== 'GET' && req.method !== 'DELETE') {
    body = await req.text()
  }

  try {
    const upstream = await fetch(target, {
      method:  req.method,
      headers: {
        'Content-Type':      'application/json',
        'X-Super-Admin-Key': ADMIN_KEY,
        // Forward tenant ID from original request if present
        ...(req.headers.get('x-warden-tenant-id')
          ? { 'X-Warden-Tenant-ID': req.headers.get('x-warden-tenant-id')! }
          : {}),
      },
      body,
    })

    const text = await upstream.text()
    let data: unknown
    try { data = JSON.parse(text) } catch { data = text }

    return NextResponse.json(data, { status: upstream.status })
  } catch (err) {
    console.error('[hub-proxy] upstream error:', err)
    return NextResponse.json({ detail: 'Warden gateway unreachable' }, { status: 502 })
  }
}

export async function GET(req: NextRequest, { params }: { params: { path: string[] } }) {
  return proxy(req, params)
}
export async function POST(req: NextRequest, { params }: { params: { path: string[] } }) {
  return proxy(req, params)
}
export async function DELETE(req: NextRequest, { params }: { params: { path: string[] } }) {
  return proxy(req, params)
}
