export type Verdict = "ALLOW" | "BLOCK" | "HIGH" | "MEDIUM" | "LOW";

export interface StatsResponse {
  total_requests: number;
  blocked_requests: number;
  high_risk_requests: number;
  allow_requests: number;
  block_rate_pct: number;
  avg_processing_ms: number;
  p99_processing_ms: number;
  uptime_hours: number;
  active_tenants: number;
}

export interface ThreatBreakdown {
  category: string;
  count: number;
  pct: number;
}

export interface EventRow {
  request_id: string;
  ts: string;
  tenant_id: string;
  verdict: Verdict;
  processing_ms: number;
  threat_type: string | null;
  content_length: number;
  ip?: string;
}

export interface EventDetail extends EventRow {
  stages: Record<string, { ms: number; verdict?: string; score?: number }>;
  redacted_secrets: number;
  ers_score: number;
  shadow_banned: boolean;
  causal_risk: number;
}

export interface RoiSummary {
  total_threats_blocked: number;
  estimated_savings_usd: number;
  cost_per_request_usd: number;
  roi_multiplier: number;
  industry: string;
}

export interface ComplianceStatus {
  gdpr: boolean;
  soc2: boolean;
  owasp_llm_top10: boolean;
  last_audit_date: string;
}
