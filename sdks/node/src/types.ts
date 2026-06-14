// sdks/node/src/types.ts — TypeScript types for Shadow Warden AI SDK

export interface ClientConfig {
  apiKey: string;
  baseUrl?: string;
  timeout?: number;
}

export interface FilterResult {
  allowed: boolean;
  blocked: boolean;
  risk_level: "low" | "medium" | "high" | "block";
  risk_score: number;
  flags: string[];
  processing_ms: number;
  request_id: string;
  action: string;
}

export interface HealthResult {
  status: "ok" | "degraded";
  version: string;
  uptime_seconds: number;
}

// ── Community types ───────────────────────────────────────────────────────────

export interface Community {
  id: string;
  name: string;
  description: string;
  visibility: "public" | "private";
  member_count: number;
  created_at: string;
  status: string;
}

export interface CommunityCreateRequest {
  name: string;
  description?: string;
  visibility?: "public" | "private";
  category?: string;
  join_policy?: "open" | "invite" | "request";
  tenant_id: string;
}

export interface CommunityMember {
  member_id: string;
  community_id: string;
  role: "owner" | "admin" | "member";
  joined_at: string;
  status: string;
}

// ── Marketplace types ─────────────────────────────────────────────────────────

export interface MarketplaceAgent {
  agent_id: string;
  community_id: string;
  tenant_id: string;
  capabilities: string[];
  status: "active" | "suspended";
  mandate_id: string;
  created_at: string;
}

export interface AgentRegisterRequest {
  tenant_id: string;
  community_id: string;
  public_key: string;
  capabilities: string[];
}

export interface Listing {
  listing_id: string;
  asset_id: string;
  asset_type: "rule" | "model" | "signals";
  seller_agent: string;
  community_id: string;
  price_usd: number;
  pricing_strategy: string;
  status: string;
  chain: string;
  created_at: string;
}

export interface ListingCreateRequest {
  asset_id: string;
  seller_agent_id: string;
  community_id: string;
  tenant_id: string;
  asset_type?: "rule" | "model" | "signals";
  price_usd: number;
  pricing_strategy?: string;
  expires_hours?: number;
  chain?: string;
}

export interface Escrow {
  escrow_id: string;
  listing_id: string;
  buyer_agent: string;
  seller_agent: string;
  amount_usd: number;
  contract_address: string;
  status: string;
  chain: string;
  created_at: string;
}

export interface GovernanceProposal {
  proposal_id: string;
  community_id: string;
  proposer_id: string;
  proposal_type: "dispute_resolution" | "parameter_change" | "agent_block";
  title: string;
  status: "active" | "passed" | "rejected" | "executed" | "expired";
  created_at: string;
  expires_at: string;
}

export interface MarketplaceStats {
  total_agents: number;
  active_listings: number;
  total_purchases: number;
  total_volume_usd: number;
  dispute_rate: number;
}

// ── Compliance types ──────────────────────────────────────────────────────────

export interface CompliancePosture {
  overall_score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  frameworks: Record<string, number>;
  gaps: ComplianceGap[];
  last_computed: string;
}

export interface ComplianceGap {
  control_id: string;
  framework: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  description: string;
  remediation: string;
}

export interface ComplianceHistory {
  entries: Array<{ ts: string; score: number; grade: string }>;
}

// ── Semantic Layer types ──────────────────────────────────────────────────────

export interface SemanticModel {
  id: string;
  name: string;
  description: string;
  metrics: Array<{ name: string; description: string }>;
  dimensions: Array<{ name: string; description: string }>;
}

export interface SemanticQueryRequest {
  model_id: string;
  metrics: string[];
  dimensions?: string[];
  filters?: Array<{ dimension: string; operator: string; value: unknown }>;
  limit?: number;
}

export interface SemanticQueryResult {
  sql: string;
  model_id: string;
  metrics: string[];
  dimensions: string[];
  generation_ms: number;
}

// ── Document Intelligence types ───────────────────────────────────────────────

export interface DocumentConvertResult {
  text: string;
  data_class: string;
  secrets_found: boolean;
  word_count: number;
  cached: boolean;
  processing_ms: number;
}

export interface DocumentScanResult {
  data_class: string;
  secrets_found: boolean;
  redacted_body: string;
  word_count: number;
}
