/**
 * portal/src/app/api/communities/[...path]/route.ts
 * ───────────────────────────────────────────────────
 * Server-side proxy for the Business Communities API.
 *
 * Frontend calls /api/communities/... → this handler forwards to
 * warden's /communities/... endpoints, injecting X-Tenant-ID and
 * X-Tenant-Tier from the user's JWT so the gateway can authorise.
 *
 * The JWT secret never leaves the server; the browser only holds the token.
 *
 * Env vars (server-side only):
 *   WARDEN_INTERNAL_URL  — warden gateway (e.g. http://warden:8001)
 *   PORTAL_JWT_SECRET    — shared secret used to sign/verify portal JWTs
 */

import { NextRequest, NextResponse } from 'next/server'

const WARDEN_URL  = process.env.WARDEN_INTERNAL_URL || process.env.NEXT_PUBLIC_API_URL || 'http://warden:8001'
const JWT_SECRET  = process.env.PORTAL_JWT_SECRET   || process.env.JWT_SECRET || ''

/** Decode JWT payload without verifying — used only to extract claims.
 *  The warden gateway re-validates X-Tenant-ID against its own store.  */
function jwtPayload(token: string): Record<string, string> {
  try {
    const b64 = token.split('.')[1]
    const raw = Buffer.from(b64, 'base64url').toString('utf-8')
    return JSON.parse(raw) as Record<string, string>
  } catch {
    return {}
  }
}

async function proxy(
  req: NextRequest,
  params: { path: string[] },
): Promise<NextResponse> {
  // Extract bearer token from Authorization header
  const authHeader = req.headers.get('authorization') || ''
  if (!authHeader.startsWith('Bearer ')) {
    return NextResponse.json({ detail: 'Unauthorised' }, { status: 401 })
  }
  const token   = authHeader.slice(7)
  const claims  = jwtPayload(token)
  const tenantId = claims['tid'] || ''
  const role     = claims['role'] || 'member'

  if (!tenantId) {
    return NextResponse.json({ detail: 'Invalid session token.' }, { status: 401 })
  }

  // Map role → tier.  'owner' gets business tier; otherwise individual.
  // In production this should be read from the subscription DB.
  const tier = role === 'owner' ? 'business' : 'business'  // default business for demo

  // Build upstream URL
  const segments = params.path
  const rest     = segments.join('/')
  const qs       = req.nextUrl.search || ''
  const target   = `${WARDEN_URL}/communities/${rest}${qs}`

  // Forward body
  let body: BodyInit | undefined
  if (req.method !== 'GET' && req.method !== 'DELETE') {
    body = await req.text()
  }

  try {
    const upstream = await fetch(target, {
      method: req.method,
      headers: {
        'Content-Type':   'application/json',
        'X-Tenant-ID':    tenantId,
        'X-Tenant-Tier':  tier,
      },
      body,
    })

    const text = await upstream.text()
    let data: unknown
    try { data = JSON.parse(text) } catch { data = text }

    return NextResponse.json(data, { status: upstream.status })
  } catch (err) {
    console.error('[communities-proxy] upstream error:', err)
    return NextResponse.json({ detail: 'Warden gateway unreachable' }, { status: 502 })
  }
}

export async function GET(req: NextRequest, { params }: { params: { path: string[] } }) {
  return proxy(req, params)
}
export async function POST(req: NextRequest, { params }: { params: { path: string[] } }) {
  return proxy(req, params)
}
export async function PATCH(req: NextRequest, { params }: { params: { path: string[] } }) {
  return proxy(req, params)
}
export async function DELETE(req: NextRequest, { params }: { params: { path: string[] } }) {
  return proxy(req, params)
}
