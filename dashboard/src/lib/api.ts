const ANALYTICS = process.env.NEXT_PUBLIC_ANALYTICS_URL ?? "http://localhost:8002";
const API       = process.env.NEXT_PUBLIC_API_URL       ?? "https://api.shadow-warden-ai.com";

async function get<T>(base: string, path: string, params?: Record<string, string>, headers?: Record<string, string>): Promise<T> {
  const url = new URL(`${base}${path}`);
  if (params) Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
  const res = await fetch(url.toString(), { next: { revalidate: 0 }, ...(headers ? { headers } : {}) });
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

export type PostureStandard = {
  standard:    string;
  short:       string;
  passed:      number;
  partial:     number;
  failed:      number;
  total:       number;
  score:       number;
  attestation: "PASS" | "PARTIAL" | "FAIL";
};

export type PostureResponse = {
  generated_at:   string;
  period_days:    number;
  overall_score:  number;
  overall_status: "PASS" | "PARTIAL" | "FAIL";
  standards:      PostureStandard[];
  org_name:       string;
  tenant_id:      string;
};

export type ComplianceSnapshot = {
  ts:             string;
  overall_score:  number;
  overall_status: "PASS" | "PARTIAL" | "FAIL";
  scores:         Record<string, number>;
};

export type ComplianceHistoryResponse = {
  hours:     number;
  count:     number;
  snapshots: ComplianceSnapshot[];
};

export type Iso27001Control = {
  control:  string;
  theme:    "Organizational" | "People" | "Physical" | "Technological";
  domain:   string;
  status:   "Implemented" | "Partial" | "Delegated";
  evidence: string;
};

export type Iso27001Theme = {
  total:       number;
  implemented: number;
  partial:     number;
  delegated:   number;
};

export type Iso27001Response = {
  standard:       string;
  org_name:       string;
  tenant_id:      string;
  generated_at:   string;
  controls_total: number;
  implemented:    number;
  partial:        number;
  delegated:      number;
  coverage_pct:   number;
  period_days:    number;
  controls:       Iso27001Control[];
  themes:         Record<string, Iso27001Theme>;
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

// ── SMB + BI Types ────────────────────────────────────────────────────────────

export type VendorRecord = {
  vendor_id: string; tenant_id: string; display_name: string;
  website: string; provider_type: string; risk_tier: string;
  status: string; contact_email: string; created_at: string;
};

export type DPARecord = {
  dpa_id: string; vendor_id: string; tenant_id: string;
  dpa_type: string; expires_at: string | null; status: string; created_at: string;
};

export type VendorStats = {
  total: number; by_risk_tier: Record<string, number>;
  by_status: Record<string, number>; expiring_dpas: number; active_dpas: number;
};

export type IncidentEntry = {
  incident_id: string; tenant_id: string; title: string;
  severity: string; category: string; status: string; created_at: string;
};

export type IncidentStats = {
  total: number; open: number;
  by_severity: Record<string, number>; by_category: Record<string, number>;
};

export type BudgetStatusResponse = {
  tenant_id: string; period_month: string;
  departments: Array<{
    department: string; status: string; cap_usd: number;
    current_spend: number; remaining: number; pct_used: number; alert_pct: number;
  }>;
  total_caps: number;
};

export type CostSummary = {
  tenant_id: string; period_month: string; total_usd: number;
  by_department: Record<string, number>; by_vendor: Record<string, number>;
};

export type DeptCost = { department: string; total_usd: number; months: number };

export type SupplierReport = {
  community_id: string; total: number;
  by_risk_label: Record<string, number>;
  assessments: Array<{ vendor_id: string; composite_score: number; risk_label: string }>;
};

export type PromptEntry = {
  prompt_id: string; community_id: string; title: string;
  category: string; use_count: number; visibility: string; created_at: string;
};

export type TrainingCompliance = {
  community_id: string; total_employees: number;
  compliant_pct: number; expiring_count: number; overdue_count: number;
};

export type BIUsage = {
  tenant_id: string; period_days: number; total_requests: number;
  blocked_requests: number; block_rate_pct: number; avg_latency_ms: number;
  daily_breakdown: Record<string, { total: number; blocked: number }>;
};

export type BIThreats = {
  tenant_id: string; period_days: number; total_flags: number;
  by_severity: Record<string, number>;
  top_threats: Array<{ flag: string; count: number }>;
};

export type BICompliance = {
  tenant_id: string; overall_score: number;
  standards: Array<{ standard: string; score: number; attestation: string }>;
  incidents_open: number; training_compliance_pct: number;
};

export type BIPredictive = {
  tenant_id: string; metric: string; current_value: number;
  predicted_value: number; trend_direction: string; r_squared: number;
};

export type DocScanStats = {
  total:         number;
  cache_hits:    number;
  errors:        number;
  sensitive:     number;
  secrets_found: number;
  available:     boolean;
};

// ── Deploy Status Types ───────────────────────────────────────────────────────
export type ServiceHealth = {
  name:        string;
  display:     string;
  status:      "ok" | "degraded" | "down" | "unknown" | "partial";
  latency_ms:  number | null;
  detail:      string;
};
export type DeployStatusResponse = {
  checked_at: string;
  overall:    "ok" | "degraded" | "down" | "partial";
  ok_count:   number;
  total:      number;
  services:   ServiceHealth[];
};

// ── Community Hub Types ───────────────────────────────────────────────────────
export type HubStats = { total: number; active: number; public: number; private: number; suspended: number };
export type HubCommunity = {
  community_id: string; name: string; description: string;
  creator_tenant_id: string; created_at: string; status: string;
  visibility: string; join_policy: string;
  member_count?: number;
  data_stats?: { total_files: number; total_mb: number; total_downloads: number; total_bytes: number };
};
export type HubMember = {
  member_id: string; tenant_id: string; community_id: string;
  role: string; joined_at: string; display_name: string; status: string;
};
export type HubFile = {
  file_id: string; community_id: string; filename: string;
  content_type: string; size_bytes: number; uploaded_at: string;
  download_count: number; status: string; context: string;
};
export type HubCompliance = {
  community_id: string; score: number; status: string;
  controls: Array<{ control: string; status: string; detail: string }>;
  gaps: Array<{ control: string; detail: string }>; generated_at: string;
};
export type HubEvolutionStats = {
  total: number; approved: number; pending: number; rejected: number; total_imports: number;
};
export type HubBundle = {
  bundle_id: string; community_id: string; rule_type: string;
  rule_content: string; status: string; published_at: string; threat_score: number;
};

// ── Marketplace Analytics Types ───────────────────────────────────────────────
// ── Community Governance types ────────────────────────────────────────────────
export type CommunityIntelReport = {
  community_id: string;
  generated_at: string;
  risk: {
    overall: number;
    anomaly_score: number;
    transfer_rejection_rate: number;
    governance_gap: number;
    label: string;
  };
  transfers: {
    total: number;
    accepted: number;
    rejected: number;
    by_data_class: Record<string, number>;
    top_target_communities: { community_id: string; count: number }[];
  };
  peerings: { total: number; active: number; revoked: number; by_policy: Record<string, number> };
  governance: { charter_active: boolean; charter_version: number; acceptance_rate: number; pending_acceptances: number };
  recent_anomalies: { member_id: string; event_type: string; severity: string; z_score: number; detected_at: string }[];
  recommendations: string[];
};
export type OAuthRiskSummary = {
  community_id: string;
  total: number;
  by_verdict: Record<string, number>;
  high_risk_providers: string[];
  risk_score: number;
};

export type MktAnalyticsSummary = {
  period_days:         number;
  total_volume_usd:    number;
  total_trades:        number;
  avg_price_usd:       number;
  active_listings:     number;
  registered_agents:   number;
  dispute_rate:        number;
  top_asset_types:     { type: string; count: number; volume_usd: number }[];
  escrow_pipeline:     { funded: number; delivered: number; confirmed: number; disputed: number };
  pricing_strategy_dist: Record<string, number>;
};
export type MktVolumePoint = { date: string; volume_usd: number; trades: number };
export type MktAgentRank   = { agent_id: string; trades: number; volume_usd: number };

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
  posture:    (days = 7)       => get<PostureResponse>(API, "/compliance/posture", { days: String(days) }),
  complianceHistory: (hours = 24) => get<ComplianceHistoryResponse>(API, "/compliance/history", { hours: String(hours) }),
  iso27001:   (days = 30)      => get<Iso27001Response>(API, "/compliance/iso27001", { days: String(days) }),
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

  // ── BL-24 Budget ─────────────────────────────────────────────────────────
  budgetStatus:    (tenantId: string) =>
    get<BudgetStatusResponse>(API, "/financial/budget/status", { tenant_id: tenantId }),

  // ── IN-25 SMB Suite ───────────────────────────────────────────────────────
  smbProvision:    (body: { tenant_id: string; community_id: string; monthly_budget_usd?: number; vendors?: unknown[] }) =>
    post<Record<string, unknown>>(API, "/smb-suite/provision", body),
  smbStatus:       (tenantId: string, communityId = "") =>
    get<Record<string, unknown>>(API, "/smb-suite/health", { tenant_id: tenantId, ...(communityId ? { community_id: communityId } : {}) }),

  // ── BL-22 Vendor Governance ───────────────────────────────────────────────
  vendorStats:     (tenantId: string) =>
    get<VendorStats>(API, "/vendor-gov/stats", { tenant_id: tenantId }),
  vendors:         (tenantId: string) =>
    get<{ vendors: VendorRecord[] }>(API, "/vendor-gov/vendors", { tenant_id: tenantId }),
  expiringDpas:    (tenantId: string, days = 30) =>
    get<{ dpas: DPARecord[] }>(API, "/vendor-gov/dpa/expiring", { tenant_id: tenantId, within_days: String(days) }),

  // ── CM-35 Incident Register ───────────────────────────────────────────────
  incidents:       (tenantId: string, limit = 20) =>
    get<{ incidents: IncidentEntry[] }>(API, "/incidents", { tenant_id: tenantId, limit: String(limit) }),
  incidentStats:   (tenantId: string) =>
    get<IncidentStats>(API, "/incidents/stats", { tenant_id: tenantId }),

  // ── BL-23 Cost Allocation ─────────────────────────────────────────────────
  costSummary:     (tenantId: string, month: string) =>
    get<CostSummary>(API, "/financial/allocation/summary", { tenant_id: tenantId, period_month: month }),
  costDepartments: (tenantId: string) =>
    get<{ departments: DeptCost[] }>(API, "/financial/allocation/departments", { tenant_id: tenantId }),

  // ── CM-36 Supplier Risk ───────────────────────────────────────────────────
  supplierReport:  (communityId: string) =>
    get<SupplierReport>(API, `/supplier-risk/report/${communityId}`),

  // ── CM-37 Prompt Library ──────────────────────────────────────────────────
  prompts:         (communityId: string) =>
    get<{ prompts: PromptEntry[] }>(API, "/prompt-library", { community_id: communityId }),

  // ── CM-38 Training Records ────────────────────────────────────────────────
  trainingCompliance: (communityId: string) =>
    get<TrainingCompliance>(API, "/training/compliance-report", { community_id: communityId }),

  // ── CM-39 Business Intelligence ───────────────────────────────────────────
  biUsage:         (tenantId: string, days = 7) =>
    get<BIUsage>(API, "/business-intelligence/usage", { tenant_id: tenantId, days: String(days) }),
  biThreats:       (tenantId: string, days = 7) =>
    get<BIThreats>(API, "/business-intelligence/threats", { tenant_id: tenantId, days: String(days) }),
  biCompliance:    (tenantId: string) =>
    get<BICompliance>(API, "/business-intelligence/compliance", { tenant_id: tenantId }),
  biPredictive:    (tenantId: string, metric = "block_rate") =>
    get<BIPredictive>(API, "/business-intelligence/predictions", { tenant_id: tenantId, metric }),

  // ── FE-50 Document Intelligence ───────────────────────────────────────────
  docScans:        () => get<DocScanStats>(API, "/document-intel/stats"),

  // ── Marketplace Analytics ─────────────────────────────────────────────────
  mktSummary:  (p?: Record<string, string>) => get<MktAnalyticsSummary>(API, "/marketplace/analytics/summary", p),
  mktVolume:   (p?: Record<string, string>) => get<MktVolumePoint[]>(API, "/marketplace/analytics/volume", p),
  mktAgents:   (p?: Record<string, string>) => get<{ top_sellers: MktAgentRank[]; top_buyers: MktAgentRank[] }>(API, "/marketplace/analytics/agents", p),

  // ── Community Governance ──────────────────────────────────────────────────
  communityIntel:       (id: string, tenantId: string) => get<CommunityIntelReport>(API, `/community-intel/${id}`, undefined, { "X-Tenant-ID": tenantId }),
  communityOAuthSummary:(id: string, tenantId: string) => get<OAuthRiskSummary>(API, `/community-intel/${id}/oauth/summary`, undefined, { "X-Tenant-ID": tenantId }),

  // ── Deploy & Monitoring ───────────────────────────────────────────────────
  deployStatus:    () => get<DeployStatusResponse>(API, "/deploy/status"),

  // ── Community Hub ─────────────────────────────────────────────────────────
  hubStats:        () => get<HubStats>(API, "/communities/stats"),
  hubList:         (tenantId: string) => get<HubCommunity[]>(API, "/communities", { tenant_id: tenantId }),
  hubGet:          (id: string) => get<HubCommunity>(API, `/communities/${id}`),
  hubMembers:      (id: string) => get<HubMember[]>(API, `/communities/${id}/members`),
  hubFiles:        (id: string) => get<HubFile[]>(API, `/communities/${id}/data`),
  hubCompliance:   (id: string) => get<HubCompliance>(API, `/communities/${id}/compliance`),
  hubEvolutionStats: (id: string) => get<HubEvolutionStats>(API, `/communities/${id}/evolution/stats`),
  hubBundles:      (id: string, status?: string) =>
    get<HubBundle[]>(API, `/communities/${id}/evolution/bundles`, status ? { status } : undefined),
};
