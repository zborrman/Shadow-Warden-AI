import { NextResponse } from "next/server";

/* Passkey credential verification is done client-side via WebAuthn.
   This endpoint just issues the session cookie after the browser confirms
   the credential challenge succeeded. */
export async function POST() {
  const key = process.env.DASHBOARD_API_KEY;
  if (!key) {
    return NextResponse.json({ error: "Auth not configured" }, { status: 503 });
  }
  const res = NextResponse.json({ ok: true });
  res.cookies.set("warden_auth", key, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 60 * 60 * 8,
  });
  return res;
}
