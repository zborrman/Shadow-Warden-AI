/**
 * portal/src/app/api/hub/[...path]/route.ts
 * ───────────────────────────────────────────
 * Disabled (2026-11-20). This proxy forwarded any caller, signed in or not, to
 * /syndicates, /tunnels and /invites with the platform's X-Super-Admin-Key and
 * a tenant id taken from the request. Its comment said it checked the portal
 * JWT; it never did. Super-admin actions are the operator's, never a tenant's,
 * so no session check would make this safe: it answers 410 until the hub has
 * tenant-scoped endpoints of its own.
 */
import { NextResponse } from 'next/server'

const gone = () => NextResponse.json({ detail: 'The community hub is not available in the portal.' }, { status: 410 })

export const GET = gone
export const POST = gone
export const PUT = gone
export const PATCH = gone
export const DELETE = gone
