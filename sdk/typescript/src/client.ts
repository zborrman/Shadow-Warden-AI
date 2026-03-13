/**
 * shadow-warden-client/client.ts
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * WardenClient — async TypeScript client for the Shadow Warden AI gateway.
 *
 * Quick start:
 * ```ts
 * import { WardenClient } from "shadow-warden-client";
 *
 * const warden = new WardenClient({ gatewayUrl: "http://localhost:8001", apiKey: "sk_..." });
 * const result = await warden.filter("Summarise the contract for client@example.com");
 * if (result.allowed) {
 *   // safe to forward to your AI model
 * }
 * ```
 */

import { WardenBlockedError, WardenGatewayError, WardenTimeoutError } from "./errors.js";
import type {
  _ApiBatchResponse,
  _ApiFilterResponse,
  BatchItem,
  BillingStatus,
  FilterOptions,
  FilterResult,
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

// ── WardenClient ──────────────────────────────────────────────────────────────

export class WardenClient {
  private readonly base: string;
  private readonly tenant: string;
  private readonly failOpen: boolean;
  private readonly timeoutMs: number;
  private readonly headers: Record<string, string>;

  constructor(config: WardenClientConfig = {}) {
    this.base     = (config.gatewayUrl ?? "http://localhost:8001").replace(/\/$/, "");
    this.tenant   = config.tenantId ?? "default";
    this.failOpen = config.failOpen ?? false;
    this.timeoutMs = config.timeoutMs ?? 10_000;

    this.headers = { "Content-Type": "application/json" };
    if (config.apiKey) {
      this.headers["X-API-Key"] = config.apiKey;
    }
  }

  // ── Core filter ─────────────────────────────────────────────────────────────

  /**
   * Send `content` through the Shadow Warden filter pipeline.
   *
   * @param content  The text to filter (prompt, document, user input…).
   * @param options  Per-call overrides (tenantId, strict, context, raiseOnBlock).
   * @returns        FilterResult describing the decision and any findings.
   */
  async filter(content: string, options: FilterOptions = {}): Promise<FilterResult> {
    const payload: Record<string, unknown> = {
      content,
      tenant_id: options.tenantId ?? this.tenant,
      strict: options.strict ?? false,
    };
    if (options.context) payload["context"] = options.context;

    let result: FilterResult;
    try {
      const res = await this._fetch("/filter", payload);
      const raw = await _parseResponse(res);
      result = _toResult(raw);
    } catch (err) {
      if (err instanceof WardenGatewayError && this.failOpen) {
        return _permissiveResult(content);
      }
      if (err instanceof WardenTimeoutError && this.failOpen) {
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

  /**
   * Filter up to 50 items in a single round-trip (`POST /filter/batch`).
   *
   * @param items  Array of content strings or BatchItem objects.
   */
  async filterBatch(items: Array<string | BatchItem>): Promise<FilterResult[]> {
    const batch = items.map((item) =>
      typeof item === "string"
        ? { content: item, tenant_id: this.tenant }
        : { tenant_id: this.tenant, ...item, tenant_id: item.tenantId ?? this.tenant }
    );

    const res = await this._fetch("/filter/batch", { items: batch });
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = ((await res.json()) as { detail?: string }).detail ?? detail; } catch { /* */ }
      throw new WardenGatewayError(res.status, detail);
    }
    const body = (await res.json()) as _ApiBatchResponse;
    return body.results.map(_toResult);
  }

  // ── Billing ─────────────────────────────────────────────────────────────────

  /** Return the current billing plan and quota for a tenant. */
  async getBillingStatus(tenantId?: string): Promise<BillingStatus> {
    const tid = tenantId ?? this.tenant;
    const url = `${this.base}/stripe/status?tenant_id=${encodeURIComponent(tid)}`;
    const res = await this._get(url);
    if (!res.ok) throw new WardenGatewayError(res.status, res.statusText);
    return (await res.json()) as BillingStatus;
  }

  // ── OpenAI wrapper ──────────────────────────────────────────────────────────

  /**
   * Wrap an OpenAI client so every `chat.completions.create()` call
   * is filtered before forwarding to OpenAI.
   *
   * Compatible with the official `openai` npm package.
   *
   * @example
   * ```ts
   * import OpenAI from "openai";
   * const openai = new OpenAI({ apiKey: "sk-openai-..." });
   * const client = warden.wrapOpenAI(openai);
   * await client.chat.completions.create({ model: "gpt-4o", messages: [...] });
   * ```
   */
  wrapOpenAI<T extends OpenAILike>(openaiClient: T): WardenOpenAIWrapper<T> {
    return new WardenOpenAIWrapper(this, openaiClient);
  }

  // ── Internal fetch ──────────────────────────────────────────────────────────

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

  private async _get(url: string): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await fetch(url, { headers: this.headers, signal: controller.signal });
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

  // Forward any other OpenAI property transparently
  get<K extends keyof T>(prop: K): T[K] {
    return this.client[prop];
  }
}
