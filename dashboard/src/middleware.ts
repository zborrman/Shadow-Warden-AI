import { NextRequest, NextResponse } from "next/server";

// `/api/warden` is exempt here because it enforces the session itself, and it
// does so fail-CLOSED (see that route handler). Letting the middleware handle it
// would answer XHR calls with a 307 to the HTML login page, which the data layer
// then tries to parse as JSON; the handler returns a plain 401 instead.
const PUBLIC_PREFIXES = ["/login", "/api/auth", "/api/warden", "/_next", "/favicon.ico"];

export function middleware(req: NextRequest) {
  const key = process.env.DASHBOARD_API_KEY;
  if (!key) return NextResponse.next(); // no auth configured → open access

  const { pathname } = req.nextUrl;
  if (PUBLIC_PREFIXES.some(p => pathname.startsWith(p))) return NextResponse.next();

  const token = req.cookies.get("warden_auth")?.value;
  if (token === key) return NextResponse.next();

  const url = req.nextUrl.clone();
  url.pathname = "/login";
  return NextResponse.redirect(url);
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|.*\\.png$|.*\\.ico$).*)"],
};
