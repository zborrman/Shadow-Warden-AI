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

// ── Client config ─────────────────────────────────────────────────────────────

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
