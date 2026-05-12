import { NextResponse } from "next/server";

export async function POST(req: Request) {
  const { email } = await req.json().catch(() => ({}));

  if (!email || typeof email !== "string") {
    return NextResponse.json({ error: "Email required" }, { status: 400 });
  }

  // Always return 200 — never reveal whether an email is registered.
  // In production: look up the user, generate a signed reset token,
  // and send it via your email provider (e.g. Resend, SendGrid, SES).
  console.log(`[auth/forgot] password reset requested for: ${email}`);

  return NextResponse.json({ ok: true });
}
