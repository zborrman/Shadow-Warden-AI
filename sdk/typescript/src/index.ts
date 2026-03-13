/**
 * shadow-warden-client
 * ━━━━━━━━━━━━━━━━━━━
 * TypeScript/JavaScript SDK for the Shadow Warden AI security gateway.
 *
 * @example
 * ```ts
 * import { WardenClient } from "shadow-warden-client";
 *
 * const warden = new WardenClient({ gatewayUrl: "http://localhost:8001", apiKey: "sk_..." });
 * const result = await warden.filter("user prompt");
 * if (result.allowed) { ... }
 * ```
 */

export { WardenClient, WardenOpenAIWrapper } from "./client.js";
export {
  WardenBlockedError,
  WardenError,
  WardenGatewayError,
  WardenTimeoutError,
} from "./errors.js";
export type {
  BatchItem,
  BillingStatus,
  FilterOptions,
  FilterResult,
  RiskLevel,
  SecretFinding,
  SemanticFlag,
  WardenClientConfig,
} from "./types.js";

export const VERSION = "0.5.0";
