const ANALYTICS = process.env.NEXT_PUBLIC_ANALYTICS_URL ?? "http://localhost:8002";
const API       = process.env.NEXT_PUBLIC_API_URL       ?? "https://api.shadow-warden-ai.com";

async function get<T>(base: string, path: string, params?: Record<string, string>): Promise<T> {
  const url = new URL(`${base}${path}`);
  if (params) Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
  const res = await fetch(url.toString(), { next: { revalidate: 0 } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export type EventEntry = {
  request_id: string;
  ts: string;
  tenant_id: string;
  allowed: boolean;
  risk_level: string;
  elapsed_ms: number;
  flags: string[];
  secrets_found: string[];
  content_length?: number;
};

export type StatsResponse = {
  days: number;
  total: number;
  allowed: number;
  blocked: number;
  block_rate_pct: number;
  avg_latency_ms: number;
  by_day: Record<string, { total: number; blocked: number }>;
};

export type EventsResponse = { total: number; events: EventEntry[] };
export type ThreatEntry    = { flag: string; count: number };
export type ThreatsResponse = { days: number; total_flags: number; threats: ThreatEntry[] };

export type RoiResponse = {
  days: number;
  total_requests: number;
  blocked_requests: number;
  shadow_ban: { count: number; tokens_saved: number; cost_saved_usd: number };
  threat_mitigation: { high_block_events: number; estimated_breach_cost_avoided: number };
  secret_protection: { secrets_redacted: number; estimated_credential_savings: number };
  total_estimated_roi_usd: number;
};

export type CommunityFeedItem = {
  ueciid:      string;
  display_name: string;
  risk_level:  string;
  data_class:  string;
  created_at:  string;
};

export type CommunityLookupResponse = {
  query:           string;
  total:           number;
  results:         CommunityFeedItem[];
  recommendations: string[];
  source:          string;
  published:       boolean;
  ueciid:          string | null;
  latency_ms:      number;
};

async function post<T>(base: string, path: string, body: unknown): Promise<T> {
  const res = await fetch(`${base}${path}`, {
    method:  "POST",
    headers: { "Content-Type": "application/json", "X-API-Key": "" },
    body:    JSON.stringify(body),
    next:    { revalidate: 0 },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export const api = {
  stats:      ()               => get<StatsResponse>(ANALYTICS, "/api/v1/stats"),
  events:     (limit = 100)    => get<EventsResponse>(ANALYTICS, "/api/v1/events", { limit: String(limit) }),
  event:      (id: string)     => get<EventEntry>(ANALYTICS, `/api/v1/events/${id}`),
  threats:    ()               => get<ThreatsResponse>(ANALYTICS, "/api/v1/threats"),
  roi:        ()               => get<RoiResponse>(ANALYTICS, "/api/v1/compliance/roi"),
  health:     ()               => get<Record<string, unknown>>(API, "/health"),
  xaiExplain: (id: string)     => get<Record<string, unknown>>(API, `/xai/explain/${id}`),
  filter:     (body: { content: string; tenant_id?: string }) =>
    fetch(`${API}/filter`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": "" },
      body: JSON.stringify(body),
    }).then(r => r.json()),
  communityFeed:   (q: string, limit = 5) =>
    get<{ query: string; total: number; results: CommunityFeedItem[] }>(
      API, "/sep/ueciids/search", { q, limit: String(limit) }
    ),
  communityLookup: (body: { query: string; auto_publish?: boolean; risk_level?: string }) =>
    post<CommunityLookupResponse>(API, "/agent/sova/community/lookup", body),
};
