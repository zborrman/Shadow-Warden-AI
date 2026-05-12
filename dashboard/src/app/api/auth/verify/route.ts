import { createHmac } from "crypto";
import { NextRequest, NextResponse } from "next/server";

/* RFC 6238 TOTP — no external deps */
function base32Decode(s: string): Buffer {
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = s.toUpperCase().replace(/=+$/, "").replace(/[^A-Z2-7]/g, "");
  let bits = 0, value = 0;
  const bytes: number[] = [];
  for (const c of cleaned) {
    const idx = alpha.indexOf(c);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((value >> bits) & 0xff); }
  }
  return Buffer.from(bytes);
}

function hotp(key: Buffer, counter: number): string {
  const buf = Buffer.alloc(8);
  // Write 64-bit counter as big-endian without BigInt
  buf.writeUInt32BE(0, 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const mac = createHmac("sha1", key).update(buf).digest();
  const offset = mac[19] & 0xf;
  const code = (
    ((mac[offset] & 0x7f) << 24) |
    (mac[offset + 1] << 16) |
    (mac[offset + 2] << 8) |
     mac[offset + 3]
  ) % 1_000_000;
  return code.toString().padStart(6, "0");
}

function checkTotp(secret: string, code: string): boolean {
  const key = base32Decode(secret);
  const t = Math.floor(Date.now() / 30000);
  return [-1, 0, 1].some(w => hotp(key, t + w) === code);
}

export async function POST(req: NextRequest) {
  const { code } = (await req.json()) as { code: string };
  const secret = process.env.DASHBOARD_TOTP_SECRET;

  if (!secret) {
    // TOTP not configured — accept any 6-digit code (dev / bypass mode)
    if (/^\d{6}$/.test(code)) return NextResponse.json({ ok: true });
    return NextResponse.json({ error: "Invalid code" }, { status: 401 });
  }

  if (checkTotp(secret, code)) return NextResponse.json({ ok: true });
  return NextResponse.json({ error: "Invalid code" }, { status: 401 });
}
