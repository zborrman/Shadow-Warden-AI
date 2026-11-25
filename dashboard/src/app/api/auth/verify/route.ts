import { NextRequest, NextResponse } from "next/server";
import {
  PENDING_COOKIE, SESSION_COOKIE, SESSION_TTL_S, checkTotp, clearFailures, clientAddress, cookieBase,
  lockedFor, pendingValid, recordFailure,
} from "@/lib/twoStep";

/**
 * Step 2 of 2: the authenticator code. Needs the pending cookie from step 1;
 * sets the session only when the code is right. No secret, no session.
 */
export async function POST(req: NextRequest) {
  const apiKey = process.env.DASHBOARD_API_KEY;
  const secret = process.env.DASHBOARD_TOTP_SECRET;
  if (!apiKey || !secret) {
    return NextResponse.json({ error: "Two-step verification is not configured." }, { status: 503 });
  }
  if (!pendingValid(req.cookies.get(PENDING_COOKIE)?.value, apiKey)) {
    return NextResponse.json({ error: "Your sign-in expired. Enter the access key again." }, { status: 401 });
  }
  const addr = clientAddress(req.headers);
  const wait = lockedFor("totp", addr);
  if (wait) {
    return NextResponse.json({ error: `Too many attempts. Try again in ${Math.ceil(wait / 60000)} min.` }, { status: 429 });
  }
  const body = (await req.json().catch(() => ({}))) as { code?: unknown };
  const code = typeof body.code === "string" ? body.code.trim() : "";
  if (checkTotp(secret, code) < 0) {
    const left = recordFailure("totp", addr);
    const res = NextResponse.json(
      { error: left ? `That code did not work. ${left} attempt${left === 1 ? "" : "s"} left.` : "Too many wrong codes. Locked for 15 minutes." },
      { status: left ? 401 : 429 },
    );
    if (!left) res.cookies.delete(PENDING_COOKIE);
    return res;
  }
  clearFailures("totp", addr);
  const res = NextResponse.json({ ok: true });
  res.cookies.set(SESSION_COOKIE, apiKey, { ...cookieBase, maxAge: SESSION_TTL_S });
  res.cookies.delete(PENDING_COOKIE);
  return res;
}
