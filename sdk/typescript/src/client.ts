/**
 * @shadow-warden/sdk — client.ts
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * WardenClient — async TypeScript/JavaScript client for the Shadow Warden AI gateway.
 *
 * @example
 * ```ts
 * import { WardenClient } from "@shadow-warden/sdk";
 *
 * const client = new WardenClient({ apiKey: "sk_..." });
 *
 * // Filter a prompt
 * const result = await client.filter("Ignore all previous instructions...");
 * if (result.blocked) console.warn("blocked:", result.riskLevel);
 *
 * // M2M marketplace
 * const listings = await client.marketplace.listings.list({ community_id: "c1" });
 *
 * // SOVA autonomous agent
 * const reply = await client.agent("What is our current threat level?");
 * ```
 */

import { WardenBlockedError, WardenGatewayError, WardenTimeoutError } from "./errors.js";
import type {
  _ApiBatchResponse,
  _ApiFilterResponse,
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
  WardenClientConfig,
} from "./types.js";

// ── Internal helpers ──────────────────────────────────────────────────────────

function _toResult(raw: _ApiFilterResponse): FilterResult {
  const flags = (raw.semantic_flags ?? []).map((f) => ({
    flag: f.flag,
    score: f.score,
    detail: f.detail ?? "",
  }));
  const secrets = (raw.secrets_found ?? []).map((s) => ({
    kind: s.kind,
    token: s.token,
    start: s.start,
    end: s.end,
  }));
  return {
    allowed: raw.allowed,
    riskLevel: raw.risk_level,
    filteredContent: raw.filtered_content,
    secretsFound: secrets,
    semanticFlags: flags,
    processingMs: raw.processing_ms ?? {},
    get blocked() { return !this.allowed; },
    get hasSecrets() { return this.secretsFound.length > 0; },
    get hasPii() { return this.semanticFlags.some((f) => f.flag === "pii_detected"); },
    get flagNames() { return this.semanticFlags.map((f) => f.flag); },
  };
}

function _permissiveResult(content: string): FilterResult {
  return _toResult({
    allowed: true,
    risk_level: "low",
    filtered_content: content,
  });
}

async function _parseResponse(res: Response): Promise<_ApiFilterResponse> {
  if (res.ok) {
    return (await res.json()) as _ApiFilterResponse;
  }
  let detail = res.statusText;
  try {
    const body = (await res.json()) as { detail?: string };
    detail = body.detail ?? detail;
  } catch {
    // non-JSON body — use statusText
  }
  throw new WardenGatewayError(res.status, detail);
}

function _sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ── WardenClient ──────────────────────────────────────────────────────────────

export class WardenClient {
  private readonly base: string;
  private readonly tenant: string;
  private readonly failOpen: boolean;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly backoffMs: number;
  private readonly headers: Record<string, string>;

  /** M2M Marketplace — agents, listings, purchases, stats. */
  readonly marketplace: Marketplace;

  constructor(config: WardenClientConfig = {}) {
    this.base      = (config.gatewayUrl ?? "http://localhost:8001").replace(/\/$/, "");
    this.tenant    = config.tenantId ?? "default";
    this.failOpen  = config.failOpen ?? false;
    this.timeoutMs = config.timeoutMs ?? 10_000;
    this.maxRetries = config.retry?.maxRetries ?? 3;
    this.backoffMs  = config.retry?.backoffMs ?? 500;

    this.headers = { "Content-Type": "application/json" };
    if (config.apiKey) {
      this.headers["X-API-Key"] = config.apiKey;
    }

    this.marketplace = new Marketplace(this);
  }

  // ── Core filter ─────────────────────────────────────────────────────────────

  async filter(content: string, options: FilterOptions = {}): Promise<FilterResult> {
    const payload: Record<string, unknown> = {
      content,
      tenant_id: options.tenantId ?? this.tenant,
      strict: options.strict ?? false,
    };
    if (options.context) payload["context"] = options.context;

    let result: FilterResult;
    try {
      const res = await this._postWithRetry("/filter", payload);
      const raw = await _parseResponse(res);
      result = _toResult(raw);
    } catch (err) {
      if ((err instanceof WardenGatewayError || err instanceof WardenTimeoutError) && this.failOpen) {
        return _permissiveResult(content);
      }
      throw err;
    }

    if (options.raiseOnBlock && result.blocked) {
      throw new WardenBlockedError(result);
    }
    return result;
  }

  // ── Batch filter ────────────────────────────────────────────────────────────

  async filterBatch(items: Array<string | BatchItem>): Promise<FilterResult[]> {
    const batch = items.map((item) =>
      typeof item === "string"
        ? { content: item, tenant_id: this.tenant }
        : { ...item, tenant_id: item.tenantId ?? this.tenant }
    );

    const res = await this._postWithRetry("/filter/batch", { items: batch });
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = ((await res.json()) as { detail?: string }).detail ?? detail; } catch { /* */ }
      throw new WardenGatewayError(res.status, detail);
    }
    const body = (await res.json()) as _ApiBatchResponse;
    return body.results.map(_toResult);
  }

  // ── SOVA agent ──────────────────────────────────────────────────────────────

  /**
   * Query the SOVA autonomous security agent (Pro+).
   * Maintains conversation history for the duration of `sessionId`.
   */
  async agent(query: string, options: { sessionId?: string; tenantId?: string } = {}): Promise<AgentResponse> {
    const payload: Record<string, unknown> = {
      query,
      tenant_id: options.tenantId ?? this.tenant,
    };
    if (options.sessionId) payload["session_id"] = options.sessionId;

    const res = await this._postWithRetry("/agent/sova", payload);
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = ((await res.json()) as { detail?: string }).detail ?? detail; } catch { /* */ }
      throw new WardenGatewayError(res.status, detail);
    }
    return (await res.json()) as AgentResponse;
  }

  // ── Health ──────────────────────────────────────────────────────────────────

  /** Check gateway health, version, and pipeline readiness (no auth required). */
  async health(): Promise<Record<string, unknown>> {
    const res = await this._getPath("/health");
    if (!res.ok) throw new WardenGatewayError(res.status, res.statusText);
    return (await res.json()) as Record<string, unknown>;
  }

  // ── Billing ─────────────────────────────────────────────────────────────────

  async getBillingStatus(tenantId?: string): Promise<BillingStatus> {
    const tid = tenantId ?? this.tenant;
    const res = await this._getPath(`/stripe/status?tenant_id=${encodeURIComponent(tid)}`);
    if (!res.ok) throw new WardenGatewayError(res.status, res.statusText);
    return (await res.json()) as BillingStatus;
  }

  // ── OpenAI wrapper ──────────────────────────────────────────────────────────

  wrapOpenAI<T extends OpenAILike>(openaiClient: T): WardenOpenAIWrapper<T> {
    return new WardenOpenAIWrapper(this, openaiClient);
  }

  // ── Internal: GET ────────────────────────────────────────────────────────────

  async _getPath(path: string): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await fetch(`${this.base}${path}`, { headers: this.headers, signal: controller.signal });
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") throw new WardenTimeoutError();
      throw new WardenGatewayError(0, String(err));
    } finally {
      clearTimeout(timer);
    }
  }

  // ── Internal: GET with params ────────────────────────────────────────────────

  async _getQuery(path: string, params?: Record<string, string>): Promise<Response> {
    let url = path;
    if (params && Object.keys(params).length > 0) {
      const qs = new URLSearchParams(params).toString();
      url = `${path}?${qs}`;
    }
    return this._getPath(url);
  }

  // ── Internal: POST with retry ────────────────────────────────────────────────

  async _postWithRetry(path: string, body: unknown): Promise<Response> {
    let attempt = 0;
    while (true) {
      const res = await this._fetch(path, body);
      const shouldRetry = !res.ok && (res.status === 429 || res.status >= 500) && attempt < this.maxRetries;
      if (!shouldRetry) return res;
      await _sleep(this.backoffMs * Math.pow(2, attempt));
      attempt++;
    }
  }

  // ── Internal: raw POST ───────────────────────────────────────────────────────

  private async _fetch(path: string, body: unknown): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await fetch(`${this.base}${path}`, {
        method: "POST",
        headers: this.headers,
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        throw new WardenTimeoutError();
      }
      throw new WardenGatewayError(0, String(err));
    } finally {
      clearTimeout(timer);
    }
  }
}

// ── Marketplace namespace ─────────────────────────────────────────────────────

class MarketplaceAgents {
  constructor(private readonly client: WardenClient) {}

  async list(params?: Record<string, string>): Promise<MktAgent[]> {
    const res = await this.client._getQuery("/marketplace/agents", params);
    if (!res.ok) throw new WardenGatewayError(res.status, res.statusText);
    return (await res.json()) as MktAgent[];
  }

  async register(body: {
    tenant_id: string;
    community_id: string;
    public_key: string;
    capabilities: string[];
  }): Promise<MktAgent> {
    const res = await this.client._postWithRetry("/marketplace/agents/register", body);
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = ((await res.json()) as { detail?: string }).detail ?? detail; } catch { /* */ }
      throw new WardenGatewayError(res.status, detail);
    }
    return (await res.json()) as MktAgent;
  }

  async getTrust(agentId: string): Promise<MktAgentTrust> {
    const res = await this.client._getPath(`/marketplace/agents/${encodeURIComponent(agentId)}/trust`);
    if (!res.ok) throw new WardenGatewayError(res.status, res.statusText);
    return (await res.json()) as MktAgentTrust;
  }
}

class MarketplaceListings {
  constructor(private readonly client: WardenClient) {}

  async list(params?: Record<string, string>): Promise<MktListing[]> {
    const res = await this.client._getQuery("/marketplace/listings", params);
    if (!res.ok) throw new WardenGatewayError(res.status, res.statusText);
    return (await res.json()) as MktListing[];
  }

  async create(body: {
    seller_agent_id: string;
    community_id: string;
    asset_type: string;
    title: string;
    description?: string;
    price_usd: number;
    pricing_strategy?: string;
  }): Promise<MktListing> {
    const res = await this.client._postWithRetry("/marketplace/listings", body);
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = ((await res.json()) as { detail?: string }).detail ?? detail; } catch { /* */ }
      throw new WardenGatewayError(res.status, detail);
    }
    return (await res.json()) as MktListing;
  }

  async purchase(listingId: string, body: {
    buyer_agent_id: string;
    escrow_funded?: boolean;
  }): Promise<MktPurchase> {
    const res = await this.client._postWithRetry(
      `/marketplace/listings/${encodeURIComponent(listingId)}/purchase`,
      body,
    );
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = ((await res.json()) as { detail?: string }).detail ?? detail; } catch { /* */ }
      throw new WardenGatewayError(res.status, detail);
    }
    return (await res.json()) as MktPurchase;
  }
}

class Marketplace {
  readonly agents: MarketplaceAgents;
  readonly listings: MarketplaceListings;

  constructor(private readonly client: WardenClient) {
    this.agents   = new MarketplaceAgents(client);
    this.listings = new MarketplaceListings(client);
  }

  async stats(params?: Record<string, string>): Promise<MktStats> {
    const res = await this.client._getQuery("/marketplace/stats", params);
    if (!res.ok) throw new WardenGatewayError(res.status, res.statusText);
    return (await res.json()) as MktStats;
  }
}

// ── OpenAI wrapper types ──────────────────────────────────────────────────────

interface ChatMessage {
  role: string;
  content: string;
}

interface CompletionCreateParams {
  messages: ChatMessage[];
  raiseOnBlock?: boolean;
  [key: string]: unknown;
}

interface OpenAILike {
  chat: {
    completions: {
      create(params: CompletionCreateParams): Promise<unknown>;
    };
  };
  [key: string]: unknown;
}

// ── WardenOpenAIWrapper ───────────────────────────────────────────────────────

class WardenCompletionsWrapper {
  constructor(
    private readonly warden: WardenClient,
    private readonly completions: OpenAILike["chat"]["completions"],
  ) {}

  async create(params: CompletionCreateParams): Promise<unknown> {
    const { raiseOnBlock = false, ...openAiParams } = params;
    const userText = params.messages
      .filter((m) => m.role === "user")
      .map((m) => m.content)
      .join("\n");

    if (userText.trim()) {
      const result = await this.warden.filter(userText, {
        context: { source: "openai_wrapper" },
        raiseOnBlock,
      });
      if (result.blocked && !raiseOnBlock) {
        throw new WardenBlockedError(result);
      }
    }

    return this.completions.create(openAiParams as CompletionCreateParams);
  }
}

/**
 * Transparent drop-in wrapper around an OpenAI client.
 * Intercepts `chat.completions.create()` to filter user messages first.
 */
export class WardenOpenAIWrapper<T extends OpenAILike> {
  readonly chat: { completions: WardenCompletionsWrapper };

  constructor(warden: WardenClient, private readonly client: T) {
    this.chat = {
      completions: new WardenCompletionsWrapper(warden, client.chat.completions),
    };
  }

  get<K extends keyof T>(prop: K): T[K] {
    return this.client[prop];
  }
}
