// Read helper for the pages that replaced the sidebar's "SOON" placeholders.
//
// Every call goes through the same-origin proxy (`/api/warden/...`), which
// attaches the gateway key server-side and only forwards paths on its GET
// allowlist. A path missing from that list answers 404 — the page then shows
// DataUnavailable, never invented rows.
import { WARDEN_PROXY } from "@/lib/api";

export const TENANT_ID = process.env.NEXT_PUBLIC_TENANT_ID ?? "default";

export class LiveError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function liveGet<T>(path: string, params?: Record<string, string | number | undefined>): Promise<T> {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params ?? {})) {
    if (v !== undefined && v !== "") qs.set(k, String(v));
  }
  const q = qs.toString();
  const res = await fetch(`${WARDEN_PROXY}${path}${q ? `?${q}` : ""}`, {
    headers: { "X-Tenant-ID": TENANT_ID },
    cache: "no-store",
  });
  if (!res.ok) throw new LiveError(res.status, `${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

/** Normalise the many list envelopes the gateway uses into a plain array. */
export function rowsOf(data: unknown, ...keys: string[]): Record<string, unknown>[] {
  if (Array.isArray(data)) return data as Record<string, unknown>[];
  if (data && typeof data === "object") {
    for (const k of [...keys, "items", "results", "data"]) {
      const v = (data as Record<string, unknown>)[k];
      if (Array.isArray(v)) return v as Record<string, unknown>[];
    }
  }
  return [];
}

export function fmtDate(v: unknown): string {
  if (v === null || v === undefined || v === "") return "—";
  const d = typeof v === "number" ? new Date(v < 1e12 ? v * 1000 : v) : new Date(String(v));
  if (Number.isNaN(d.getTime())) return String(v);
  return d.toLocaleDateString("en-GB", { day: "2-digit", month: "2-digit", year: "2-digit" });
}
