import { NextRequest, NextResponse } from "next/server";
import {
  PENDING_COOKIE, PENDING_TTL_S, SESSION_COOKIE, clearFailures, clientAddress, cookieBase,
  issuePending, lockedFor, recordFailure, sameSecret,
} from "@/lib/twoStep";

/**
 * Step 1 of 2: the access key. A right key earns only a 5-minute pending
 * cookie; the session itself is set by /api/auth/verify after the TOTP code.
 */
export async function POST(req: NextRequest) {
  const expected = process.env.DASHBOARD_API_KEY;
  if (!expected) {
    return NextResponse.json({ error: "Dashboard sign-in is not configured (DASHBOARD_API_KEY is unset)." }, { status: 503 });
  }
  if (!process.env.DASHBOARD_TOTP_SECRET) {
    return NextResponse.json({ error: "Two-step verification is not configured (DASHBOARD_TOTP_SECRET is unset)." }, { status: 503 });
  }
  const addr = clientAddress(req.headers);
  const wait = lockedFor("key", addr);
  if (wait) {
    return NextResponse.json({ error: `Too many attempts. Try again in ${Math.ceil(wait / 60000)} min.` }, { status: 429 });
  }
  const body = (await req.json().catch(() => ({}))) as { key?: unknown };
  const key = typeof body.key === "string" ? body.key : "";
  if (!key || !sameSecret(key, expected)) {
    const left = recordFailure("key", addr);
    return NextResponse.json(
      { error: left ? `Invalid key. ${left} attempt${left === 1 ? "" : "s"} left.` : "Invalid key. Locked for 15 minutes." },
      { status: left ? 401 : 429 },
    );
  }
  clearFailures("key", addr);
  const res = NextResponse.json({ ok: true, next: "totp" });
  res.cookies.set(PENDING_COOKIE, issuePending(expected), { ...cookieBase, maxAge: PENDING_TTL_S });
  res.cookies.delete(SESSION_COOKIE);
  return res;
}

export async function DELETE() {
  const res = NextResponse.json({ ok: true });
  res.cookies.delete(SESSION_COOKIE);
  res.cookies.delete(PENDING_COOKIE);
  return res;
}
