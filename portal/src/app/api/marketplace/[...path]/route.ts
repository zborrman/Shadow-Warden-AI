/**
 * portal/src/app/api/marketplace/[...path]/route.ts
 * Server-side proxy — forwards /api/marketplace/* to warden /marketplace/*.
 */

import { NextRequest, NextResponse } from 'next/server'
import { requirePortalSession } from '@/lib/server/portalSession'

const WARDEN_URL = process.env.WARDEN_INTERNAL_URL || process.env.NEXT_PUBLIC_API_URL || 'http://warden:8001'
const API_KEY    = process.env.WARDEN_API_KEY || ''

async function proxy(req: NextRequest, params: { path: string[] }): Promise<NextResponse> {
  const user = await requirePortalSession(req)
  if (user instanceof NextResponse) return user
  // The server key is one tenant: a write through it would act for that tenant,
  // whoever is signed in. Reads only, until the portal has per-seller access.
  if (req.method !== 'GET') {
    return NextResponse.json({ detail: 'Not available from the portal.' }, { status: 403 })
  }
  const rawQs = req.nextUrl.search || ''
  const qs    = rawQs || ''
  const rest  = params.path.join('/')
  const target = `${WARDEN_URL}/marketplace/${rest}${qs}`

  const fwdHeaders: Record<string, string> = {}
  if (API_KEY) fwdHeaders['X-API-Key'] = API_KEY

  const contentType = req.headers.get('content-type') ?? ''
  if (req.method !== 'GET' && req.method !== 'DELETE') {
    fwdHeaders['Content-Type'] = contentType || 'application/json'
  }

  let body: BodyInit | undefined
  if (req.method !== 'GET' && req.method !== 'DELETE') {
    body = await req.text()
  }

  try {
    const upstream = await fetch(target, { method: req.method, headers: fwdHeaders, body })
    const text = await upstream.text()
    let data: unknown
    try { data = JSON.parse(text) } catch { data = text }
    return NextResponse.json(data, { status: upstream.status })
  } catch (err) {
    console.error('[marketplace-proxy] upstream error:', err)
    return NextResponse.json({ detail: 'Warden gateway unreachable' }, { status: 502 })
  }
}

export async function GET(req: NextRequest, props: { params: Promise<{ path: string[] }> }) {
  const params = await props.params;
  return proxy(req, params)
}
export async function POST(req: NextRequest, props: { params: Promise<{ path: string[] }> }) {
  const params = await props.params;
  return proxy(req, params)
}
export async function PUT(req: NextRequest, props: { params: Promise<{ path: string[] }> }) {
  const params = await props.params;
  return proxy(req, params)
}
export async function DELETE(req: NextRequest, props: { params: Promise<{ path: string[] }> }) {
  const params = await props.params;
  return proxy(req, params)
}
