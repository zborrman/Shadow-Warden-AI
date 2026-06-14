/**
 * shadow-warden-client/types.ts
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * TypeScript types mirroring the Shadow Warden AI gateway API schema.
 */

export type RiskLevel = "low" | "medium" | "high" | "block";

export interface SecretFinding {
  kind: string;
  token: string;
  start: number;
  end: number;
}

export interface SemanticFlag {
  flag: string;
  score: number;
  detail: string;
}

export interface FilterResult {
  allowed: boolean;
  riskLevel: RiskLevel;
  filteredContent: string;
  secretsFound: SecretFinding[];
  semanticFlags: SemanticFlag[];
  processingMs: Record<string, number>;
  /** Convenience: inverse of `allowed` */
  blocked: boolean;
  /** Convenience: true if any secrets/PII were detected */
  hasSecrets: boolean;
  /** Convenience: true if `pii_detected` flag is present */
  hasPii: boolean;
  /** Convenience: list of semantic flag names */
  flagNames: string[];
}

// ── Request types ─────────────────────────────────────────────────────────────

export interface FilterOptions {
  /** Override the default tenant for this call. */
  tenantId?: string;
  /** Block on MEDIUM risk (default: only HIGH / BLOCK). */
  strict?: boolean;
  /** Arbitrary metadata forwarded to the gateway log. */
  context?: Record<string, unknown>;
  /** Throw WardenBlockedError if blocked instead of returning the result. */
  raiseOnBlock?: boolean;
}

export interface BatchItem {
  content: string;
  tenantId?: string;
  strict?: boolean;
}

export interface BillingStatus {
  plan: string;
  quota: number;
  used: number;
  [key: string]: unknown;
}

// ── Marketplace types ─────────────────────────────────────────────────────────

export interface MktAgent {
  agent_id: string;
  community_id: string;
  tenant_id: string;
  capabilities: string[];
  status: string;
  mandate_id: string;
  created_at: string;
}

export interface MktListing {
  listing_id: string;
  seller_agent_id: string;
  community_id: string;
  asset_type: string;
  title: string;
  description: string;
  price_usd: number;
  pricing_strategy: string;
  status: string;
  created_at: string;
}

export interface MktPurchase {
  purchase_id: string;
  listing_id: string;
  buyer_agent_id: string;
  seller_agent_id: string;
  price_paid: number;
  status: string;
  escrow_id: string;
  purchased_at: string;
}

export interface MktAgentTrust {
  agent_id: string;
  trust_score: number;
  trust_rank: number;
  sybil_flag: boolean;
  sybil_reason: string;
  transitive_peers: { agent_id: string; trust_rank: number; transitive_trust: number }[];
}

export interface MktStats {
  total_listings: number;
  active_listings: number;
  total_trades: number;
  total_volume_usd: number;
  registered_agents: number;
  avg_price_usd: number;
  [key: string]: unknown;
}

// ── SOVA agent types ──────────────────────────────────────────────────────────

export interface AgentResponse {
  session_id: string;
  reply: string;
  tool_calls: number;
  iterations: number;
}

// ── Client config ─────────────────────────────────────────────────────────────

export interface RetryConfig {
  /** Max number of retry attempts on 429 / 5xx. Default: 3 */
  maxRetries?: number;
  /** Base backoff in ms (doubles each attempt). Default: 500 */
  backoffMs?: number;
}

export interface WardenClientConfig {
  /** Base URL of the Warden gateway. Default: `http://localhost:8001` */
  gatewayUrl?: string;
  /** X-API-Key header value. Leave blank if auth is disabled. */
  apiKey?: string;
  /** Default tenant sent with every request. Default: `"default"` */
  tenantId?: string;
  /** Fetch timeout in milliseconds. Default: 10_000 */
  timeoutMs?: number;
  /**
   * If true, a network error or gateway error returns a permissive FilterResult
   * instead of throwing. Mirrors the gateway's own fail-open behaviour.
   * Default: false.
   */
  failOpen?: boolean;
  /** Automatic retry config for 429 / 5xx responses. */
  retry?: RetryConfig;
}

// ── Wire format (snake_case from the API) ────────────────────────────────────

export interface _ApiFilterResponse {
  allowed: boolean;
  risk_level: RiskLevel;
  filtered_content: string;
  secrets_found?: Array<{ kind: string; token: string; start: number; end: number }>;
  semantic_flags?: Array<{ flag: string; score: number; detail?: string }>;
  processing_ms?: Record<string, number>;
}

export interface _ApiBatchResponse {
  results: _ApiFilterResponse[];
}
