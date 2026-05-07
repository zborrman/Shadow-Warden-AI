import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
  const { key } = (await req.json()) as { key: string };
  const expected = process.env.DASHBOARD_API_KEY;
  if (!expected || key !== expected) {
    return NextResponse.json({ error: "Invalid key" }, { status: 401 });
  }
  const res = NextResponse.json({ ok: true });
  res.cookies.set("warden_auth", key, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 60 * 60 * 8, // 8-hour session
  });
  return res;
}

export async function DELETE() {
  const res = NextResponse.json({ ok: true });
  res.cookies.delete("warden_auth");
  return res;
}
