/**
 * Server-side gate for the portal's API proxies.
 *
 * A proxy that adds a server-held key to the request must first know who is
 * asking. The caller sends its portal session (Authorization: Bearer <access
 * token>); we ask the gateway's /portal/me whether it is valid. No session, or
 * an invalid one, is a 401 before anything is forwarded.
 *
 * This proves the caller is a signed-in portal user, nothing more. The key the
 * proxy then adds is still one tenant's, so a proxy must not be used for data
 * that belongs to a specific seller.
 */
import { NextRequest, NextResponse } from 'next/server'

const WARDEN_URL = process.env.WARDEN_INTERNAL_URL || process.env.NEXT_PUBLIC_API_URL || 'http://warden:8001'

export interface PortalUser { user_id: string; tenant_id: string }

export async function requirePortalSession(req: NextRequest): Promise<PortalUser | NextResponse> {
  const auth = req.headers.get('authorization') ?? ''
  if (!/^Bearer \S+$/.test(auth)) {
    return NextResponse.json({ detail: 'Sign in to use this.' }, { status: 401 })
  }
  try {
    const r = await fetch(`${WARDEN_URL}/portal/me`, { headers: { Authorization: auth }, cache: 'no-store' })
    if (!r.ok) return NextResponse.json({ detail: 'Your session has expired. Sign in again.' }, { status: 401 })
    const me = await r.json() as PortalUser
    return { user_id: me.user_id, tenant_id: me.tenant_id }
  } catch {
    return NextResponse.json({ detail: 'Gateway unreachable' }, { status: 502 })
  }
}
