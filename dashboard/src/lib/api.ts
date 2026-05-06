const ANALYTICS = process.env.NEXT_PUBLIC_ANALYTICS_URL ?? "http://localhost:8002";
const API       = process.env.NEXT_PUBLIC_API_URL       ?? "https://api.shadow-warden-ai.com";

async function get<T>(base: string, path: string, params?: Record<string, string>): Promise<T> {
  const url = new URL(`${base}${path}`);
  if (params) Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
  const res = await fetch(url.toString(), { next: { revalidate: 0 } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export const api = {
  stats:     ()                => get<Record<string, unknown>>(ANALYTICS, "/stats"),
  events:    (limit = 100)     => get<Record<string, unknown>[]>(ANALYTICS, "/events", { limit: String(limit) }),
  event:     (id: string)      => get<Record<string, unknown>>(ANALYTICS, `/events/${id}`),
  threats:   ()                => get<Record<string, unknown>[]>(ANALYTICS, "/threats"),
  roi:       ()                => get<Record<string, unknown>>(ANALYTICS, "/roi"),
  compliance: ()               => get<Record<string, unknown>>(ANALYTICS, "/compliance"),
  health:    ()                => get<Record<string, unknown>>(API, "/health"),
  filter:    (body: { content: string; tenant_id?: string }) =>
    fetch(`${API}/filter`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": "" },
      body: JSON.stringify(body),
    }).then(r => r.json()),
};
