/**
 * @shadow-warden/sdk
 * ━━━━━━━━━━━━━━━━━
 * TypeScript/JavaScript SDK for the Shadow Warden AI security gateway.
 *
 * @example
 * ```ts
 * import { WardenClient } from "@shadow-warden/sdk";
 *
 * const client = new WardenClient({ apiKey: "sk_...", gatewayUrl: "https://api.shadow-warden-ai.com" });
 *
 * // Filter user input before forwarding to an LLM
 * const result = await client.filter(userPrompt);
 * if (result.allowed) { ... }
 *
 * // M2M marketplace
 * const listings = await client.marketplace.listings.list({ community_id: "c1" });
 *
 * // SOVA autonomous agent
 * const reply = await client.agent("What is our current threat level?");
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
  AgentResponse,
  BatchItem,
  BillingStatus,
  FilterOptions,
  FilterResult,
  MktAgent,
  MktAgentTrust,
  MktListing,
  MktPurchase,
  MktStats,
  RetryConfig,
  RiskLevel,
  SecretFinding,
  SemanticFlag,
  WardenClientConfig,
} from "./types.js";

export const VERSION = "1.0.0";
