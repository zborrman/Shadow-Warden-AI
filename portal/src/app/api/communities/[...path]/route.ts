/**
 * portal/src/app/api/communities/[...path]/route.ts
 * Server-side proxy — forwards /api/communities/* to warden /communities/*.
 * Auto-injects tenant_id / requester_tenant_id from JWT so hub pages
 * don't need to handle auth plumbing themselves.
 */

import { NextRequest, NextResponse } from 'next/server'

const WARDEN_URL = process.env.WARDEN_INTERNAL_URL || process.env.NEXT_PUBLIC_API_URL || 'http://warden:8001'

function jwtPayload(token: string): Record<string, string> {
  try {
    const b64 = token.split('.')[1]
    const raw = Buffer.from(b64, 'base64url').toString('utf-8')
    return JSON.parse(raw) as Record<string, string>
  } catch {
    return {}
  }
}

async function proxy(req: NextRequest, params: { path: string[] }): Promise<NextResponse> {
  const authHeader = req.headers.get('authorization') || ''
  if (!authHeader.startsWith('Bearer ')) {
    return NextResponse.json({ detail: 'Unauthorised' }, { status: 401 })
  }
  const token    = authHeader.slice(7)
  const claims   = jwtPayload(token)
  const tenantId = claims['tid'] || ''
  const role     = claims['role'] || 'member'

  if (!tenantId) {
    return NextResponse.json({ detail: 'Invalid session token.' }, { status: 401 })
  }

  const tier = role === 'owner' ? 'business' : 'business'

  // Build query string — auto-inject tenant_id for GET, requester_tenant_id for DELETE
  const rawQs = req.nextUrl.search || ''
  const urlParams = new URLSearchParams(rawQs.startsWith('?') ? rawQs.slice(1) : rawQs)

  if (req.method === 'GET' && !urlParams.has('tenant_id')) {
    urlParams.set('tenant_id', tenantId)
  }
  if (req.method === 'DELETE' && !urlParams.has('requester_tenant_id')) {
    urlParams.set('requester_tenant_id', tenantId)
  }

  const qs     = urlParams.toString() ? `?${urlParams.toString()}` : ''
  const rest   = params.path.join('/')
  const target = `${WARDEN_URL}/communities/${rest}${qs}`

  // Detect multipart to preserve Content-Type boundary
  const contentType = req.headers.get('content-type') ?? ''
  const isMultipart = contentType.includes('multipart/form-data')

  const fwdHeaders: Record<string, string> = {
    'X-Tenant-ID':   tenantId,
    'X-Tenant-Tier': tier,
  }
  if (isMultipart) {
    fwdHeaders['Content-Type'] = contentType   // includes boundary=...
  } else if (req.method !== 'GET' && req.method !== 'DELETE') {
    fwdHeaders['Content-Type'] = 'application/json'
  }

  let body: BodyInit | undefined
  if (req.method !== 'GET' && req.method !== 'DELETE') {
    if (isMultipart) {
      body = Buffer.from(await req.arrayBuffer())
    } else {
      body = await req.text()
    }
  }

  try {
    const upstream = await fetch(target, {
      method: req.method,
      headers: fwdHeaders,
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
export async function PUT(req: NextRequest, { params }: { params: { path: string[] } }) {
  return proxy(req, params)
}
export async function DELETE(req: NextRequest, { params }: { params: { path: string[] } }) {
  return proxy(req, params)
}
