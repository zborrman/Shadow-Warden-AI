import { NextRequest, NextResponse } from "next/server";

// `/api/warden` is exempt here because it enforces the session itself, and it
// does so fail-CLOSED (see that route handler). Letting the middleware handle it
// would answer XHR calls with a 307 to the HTML login page, which the data layer
// then tries to parse as JSON; the handler returns a plain 401 instead.
const PUBLIC_PREFIXES = ["/login", "/api/auth", "/api/warden", "/_next", "/favicon.ico"];

/**
 * SW-15. This used to read:
 *
 *     if (!key) return NextResponse.next(); // no auth configured → open access
 *
 * and `docker-compose.yml` passes `DASHBOARD_API_KEY=${DASHBOARD_API_KEY:-}`,
 * so an operator whose `.env` omits the line gets an empty string rather than a
 * missing variable — and the whole SOC UI, every request and verdict and tenant
 * id, is served to anyone who can reach port 3002.
 *
 * The two halves of the same login already disagreed about this.
 * `app/api/auth/route.ts` rejects every attempt when the key is unset, and
 * `app/api/warden/[...path]/route.ts` refuses to proxy at all. The login form
 * was shut while the front door stood open.
 *
 * It is also the second time this default has appeared in this product: the SMB
 * analytics dashboard treated an unset `DASHBOARD_PASSWORD_HASH` as dev mode
 * and admitted everyone (OB-F22). Twice makes it a class.
 *
 * Production sets the variable, so this was a loaded trap rather than an open
 * door — which is a reason to disarm it, not to leave it.
 */
const OPT_OUT = process.env.DASHBOARD_ALLOW_UNAUTHENTICATED === "true";

/**
 * Constant-time string compare.
 *
 * `token === key` returns on the first differing byte. The proxy handler next
 * door already uses `timingSafeEqual` against this same secret; middleware runs
 * on the edge runtime where `node:crypto` is not available, so the same
 * property is built by hand rather than left to differ between two checks of
 * one value.
 */
function secretsMatch(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  if (PUBLIC_PREFIXES.some(p => pathname.startsWith(p))) return NextResponse.next();

  const key = process.env.DASHBOARD_API_KEY;
  if (!key) {
    if (OPT_OUT) return NextResponse.next();
    // Fail closed, and say why. A redirect to /login would be a nicer dead end,
    // but /api/auth cannot succeed either without the key, so the operator
    // would be left guessing at a password that can never be right.
    return new NextResponse(
      "Dashboard authentication is not configured: DASHBOARD_API_KEY is unset, " +
        "so no session can be issued or verified. Set it, or set " +
        "DASHBOARD_ALLOW_UNAUTHENTICATED=true to run without authentication " +
        "on a machine where that is acceptable.",
      { status: 503, headers: { "Content-Type": "text/plain; charset=utf-8" } },
    );
  }

  const token = req.cookies.get("warden_auth")?.value;
  if (typeof token === "string" && secretsMatch(token, key)) return NextResponse.next();

  const url = req.nextUrl.clone();
  url.pathname = "/login";
  return NextResponse.redirect(url);
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|.*\\.png$|.*\\.ico$).*)"],
};
