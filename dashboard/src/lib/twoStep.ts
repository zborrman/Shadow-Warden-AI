/**
 * Two-step sign-in for the SOC dashboard, enforced on the server.
 *
 * Before this, the second step was decoration: `POST /api/auth` set the
 * session cookie as soon as the key matched, `POST /api/auth/verify` accepted
 * any six digits when `DASHBOARD_TOTP_SECRET` was unset (it was unset in
 * production), the page had a button that skipped the step, and
 * `POST /api/auth/passkey` handed out a session to anyone without checking a
 * credential at all.
 *
 * Now the key only earns a short-lived, signed "pending" cookie; the session
 * cookie is set by `/api/auth/verify` and only after a valid TOTP code. With no
 * TOTP secret configured, sign-in fails closed. Wrong keys and wrong codes are
 * counted per client address and lock that address for 15 minutes after 5.
 */
import { createHmac, timingSafeEqual } from "crypto";

export const SESSION_COOKIE = "warden_auth";
export const PENDING_COOKIE = "warden_2fa_pending";
export const PENDING_TTL_S = 5 * 60;
export const SESSION_TTL_S = 8 * 60 * 60;
export const MAX_FAILURES = 5;
export const LOCK_MS = 15 * 60 * 1000;

export function sameSecret(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

// ── pending token: "<expires>.<hmac>" signed with a key derived from the API key ──

function pendingSig(apiKey: string, exp: number): string {
  return createHmac("sha256", apiKey).update(`dashboard-2fa-pending:${exp}`).digest("hex");
}

export function issuePending(apiKey: string, now = Date.now()): string {
  const exp = Math.floor(now / 1000) + PENDING_TTL_S;
  return `${exp}.${pendingSig(apiKey, exp)}`;
}

export function pendingValid(token: string | undefined, apiKey: string, now = Date.now()): boolean {
  if (!token) return false;
  const [expStr, sig] = token.split(".");
  const exp = Number(expStr);
  if (!Number.isInteger(exp) || !sig || exp < Math.floor(now / 1000)) return false;
  return sameSecret(sig, pendingSig(apiKey, exp));
}

// ── RFC 6238 TOTP (SHA-1, 30 s, 6 digits), ±1 step for clock drift ──

function base32Decode(s: string): Buffer {
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = s.toUpperCase().replace(/=+$/, "").replace(/[^A-Z2-7]/g, "");
  let bits = 0, value = 0;
  const bytes: number[] = [];
  for (const c of cleaned) {
    value = (value << 5) | alpha.indexOf(c);
    bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((value >> bits) & 0xff); }
  }
  return Buffer.from(bytes);
}

export function hotp(key: Buffer, counter: number): string {
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const mac = createHmac("sha1", key).update(buf).digest();
  const off = mac[19] & 0xf;
  const code = (((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3]) % 1_000_000;
  return code.toString().padStart(6, "0");
}

let lastUsedStep = -1;

/** The matching time step, or -1. A step already used once is refused (no replay inside its window). */
export function checkTotp(secret: string, code: string, now = Date.now()): number {
  if (!/^\d{6}$/.test(code)) return -1;
  const key = base32Decode(secret);
  if (key.length < 10) return -1;
  const t = Math.floor(now / 30000);
  for (const step of [t - 1, t, t + 1]) {
    if (step > lastUsedStep && sameSecret(hotp(key, step), code)) {
      lastUsedStep = step;
      return step;
    }
  }
  return -1;
}

// ── failure counting per client address (one dashboard container, so memory is enough) ──

type Bucket = { fails: number; lockedUntil: number };
const buckets = new Map<string, Bucket>();

export function clientAddress(headers: Headers): string {
  return headers.get("cf-connecting-ip")
    ?? headers.get("x-real-ip")
    ?? headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    ?? "unknown";
}

/** Milliseconds left on a lock, or 0. */
export function lockedFor(scope: string, addr: string, now = Date.now()): number {
  const b = buckets.get(`${scope}:${addr}`);
  return b && b.lockedUntil > now ? b.lockedUntil - now : 0;
}

/** Count one failure; returns attempts left before the lock (0 = locked now). */
export function recordFailure(scope: string, addr: string, now = Date.now()): number {
  const k = `${scope}:${addr}`;
  const b = buckets.get(k) ?? { fails: 0, lockedUntil: 0 };
  if (b.lockedUntil && b.lockedUntil <= now) { b.fails = 0; b.lockedUntil = 0; }
  b.fails += 1;
  if (b.fails >= MAX_FAILURES) b.lockedUntil = now + LOCK_MS;
  buckets.set(k, b);
  return Math.max(0, MAX_FAILURES - b.fails);
}

export function clearFailures(scope: string, addr: string): void {
  buckets.delete(`${scope}:${addr}`);
}

/** Test hook: forget counters and the replay marker. */
export function _resetForTests(): void {
  buckets.clear();
  lastUsedStep = -1;
}

export const cookieBase = {
  httpOnly: true,
  sameSite: "lax" as const,
  secure: process.env.NODE_ENV === "production",
  path: "/",
};
