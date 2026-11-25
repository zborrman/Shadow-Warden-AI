import { createHmac } from "crypto";
import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { POST as keyStep } from "./route";
import { POST as codeStep } from "./verify/route";
import { PENDING_COOKIE, SESSION_COOKIE, _resetForTests, hotp, issuePending } from "@/lib/twoStep";

const KEY = "test-dashboard-key-0123456789";
const SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

function b32(s: string): Buffer {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, v = 0; const out: number[] = [];
  for (const c of s) { v = (v << 5) | a.indexOf(c); bits += 5; if (bits >= 8) { bits -= 8; out.push((v >> bits) & 0xff); } }
  return Buffer.from(out);
}
const codeNow = () => hotp(b32(SECRET), Math.floor(Date.now() / 30000));

function req(path: string, body: unknown, cookies: Record<string, string> = {}, ip = "10.0.0.1") {
  const cookie = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join("; ");
  return new NextRequest(`http://dash.test${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": ip, ...(cookie ? { cookie } : {}) },
    body: JSON.stringify(body),
  });
}

beforeEach(() => {
  process.env.DASHBOARD_API_KEY = KEY;
  process.env.DASHBOARD_TOTP_SECRET = SECRET;
  _resetForTests();
});
afterEach(() => {
  delete process.env.DASHBOARD_API_KEY;
  delete process.env.DASHBOARD_TOTP_SECRET;
});

describe("dashboard two-step sign-in", () => {
  it("the right key alone never sets the session cookie", async () => {
    const res = await keyStep(req("/api/auth", { key: KEY }));
    expect(res.status).toBe(200);
    expect(res.cookies.get(PENDING_COOKIE)?.value).toBeTruthy();
    expect(res.cookies.get(SESSION_COOKIE)?.value ?? "").toBe("");
  });

  it("the session comes only from a right code with a valid pending cookie", async () => {
    const pending = issuePending(KEY);
    const res = await codeStep(req("/api/auth/verify", { code: codeNow() }, { [PENDING_COOKIE]: pending }));
    expect(res.status).toBe(200);
    expect(res.cookies.get(SESSION_COOKIE)?.value).toBe(KEY);
  });

  it("a code without step one is refused", async () => {
    const res = await codeStep(req("/api/auth/verify", { code: codeNow() }));
    expect(res.status).toBe(401);
    expect(res.cookies.get(SESSION_COOKIE)?.value ?? "").toBe("");
  });

  it("a forged or expired pending cookie is refused", async () => {
    const exp = Math.floor(Date.now() / 1000) + 300;
    const forged = `${exp}.${createHmac("sha256", "not-the-key").update(`dashboard-2fa-pending:${exp}`).digest("hex")}`;
    expect((await codeStep(req("/api/auth/verify", { code: codeNow() }, { [PENDING_COOKIE]: forged }))).status).toBe(401);
    const old = issuePending(KEY, Date.now() - 10 * 60 * 1000);
    expect((await codeStep(req("/api/auth/verify", { code: codeNow() }, { [PENDING_COOKIE]: old }))).status).toBe(401);
  });

  it("any six digits no longer pass, and with no secret sign-in fails closed", async () => {
    const pending = issuePending(KEY);
    const wrong = codeNow() === "123456" ? "654321" : "123456";
    expect((await codeStep(req("/api/auth/verify", { code: wrong }, { [PENDING_COOKIE]: pending }))).status).toBe(401);
    delete process.env.DASHBOARD_TOTP_SECRET;
    expect((await keyStep(req("/api/auth", { key: KEY }))).status).toBe(503);
    expect((await codeStep(req("/api/auth/verify", { code: "000000" }, { [PENDING_COOKIE]: pending }))).status).toBe(503);
  });

  it("a code cannot be used twice", async () => {
    const pending = issuePending(KEY);
    const c = codeNow();
    expect((await codeStep(req("/api/auth/verify", { code: c }, { [PENDING_COOKIE]: pending }))).status).toBe(200);
    expect((await codeStep(req("/api/auth/verify", { code: c }, { [PENDING_COOKIE]: pending }))).status).toBe(401);
  });

  it("five wrong keys lock the address, not everyone", async () => {
    for (let i = 0; i < 4; i++) expect((await keyStep(req("/api/auth", { key: "nope" }))).status).toBe(401);
    expect((await keyStep(req("/api/auth", { key: "nope" }))).status).toBe(429);
    expect((await keyStep(req("/api/auth", { key: KEY }))).status).toBe(429);
    expect((await keyStep(req("/api/auth", { key: KEY }, {}, "10.0.0.2"))).status).toBe(200);
  });

  it("five wrong codes lock the address and drop the pending cookie", async () => {
    const pending = issuePending(KEY);
    const wrong = codeNow() === "111111" ? "222222" : "111111";
    let last;
    for (let i = 0; i < 5; i++) last = await codeStep(req("/api/auth/verify", { code: wrong }, { [PENDING_COOKIE]: pending }));
    expect(last!.status).toBe(429);
    expect((await codeStep(req("/api/auth/verify", { code: codeNow() }, { [PENDING_COOKIE]: pending }))).status).toBe(429);
  });

  it("the passkey and forgot routes that issued sessions unchecked are gone", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const { fileURLToPath } = await import("url");
    const here = path.dirname(fileURLToPath(import.meta.url));
    expect(fs.existsSync(path.join(here, "verify", "route.ts"))).toBe(true);
    expect(fs.existsSync(path.join(here, "passkey", "route.ts"))).toBe(false);
    expect(fs.existsSync(path.join(here, "forgot", "route.ts"))).toBe(false);
  });
});
