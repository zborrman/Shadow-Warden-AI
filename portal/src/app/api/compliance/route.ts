/**
 * portal/src/app/api/compliance/route.ts
 * ────────────────────────────────────────
 * Server-side proxy: forwards compliance requests to the Warden gateway.
 * Injects X-API-Key from server env — never exposed to the browser.
 *
 * Proxied paths:
 *   GET  /api/compliance/posture/gaps
 *   GET  /api/compliance/posture/:framework
 *   POST /api/compliance/posture/recalculate
 */
import { NextRequest, NextResponse } from 'next/server'

const WARDEN_URL = process.env.WARDEN_INTERNAL_URL || process.env.NEXT_PUBLIC_API_URL || 'http://warden:8001'
const API_KEY    = process.env.WARDEN_API_KEY || ''

async function proxy(req: NextRequest): Promise<NextResponse> {
  // Strip /api/compliance prefix → /compliance/...
  const path   = req.nextUrl.pathname.replace(/^\/api\/compliance/, '/compliance')
  const qs     = req.nextUrl.search || ''
  const target = `${WARDEN_URL}${path}${qs}`

  try {
    const upstream = await fetch(target, {
      method:  req.method,
      headers: { 'X-API-Key': API_KEY, 'X-Tenant-Tier': 'pro' },
      body:    req.method === 'GET' ? undefined : await req.text(),
    })
    const data = await upstream.json().catch(() => ({ detail: 'Invalid JSON' }))
    return NextResponse.json(data, { status: upstream.status })
  } catch (err) {
    console.error('[compliance-proxy] upstream error:', err)
    return NextResponse.json({ detail: 'Gateway unreachable' }, { status: 502 })
  }
}

export async function GET(req: NextRequest)  { return proxy(req) }
export async function POST(req: NextRequest) { return proxy(req) }
