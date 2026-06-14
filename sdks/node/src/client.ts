// sdks/node/src/client.ts — Base HTTP client for Shadow Warden AI SDK

import type { ClientConfig, FilterResult, HealthResult } from "./types.js";
import { CommunityResource } from "./resources/community.js";
import { MarketplaceResource } from "./resources/marketplace.js";
import { ComplianceResource } from "./resources/compliance.js";
import { SemanticResource } from "./resources/semantic.js";
import { DocumentResource } from "./resources/documents.js";

export class ShadowWardenError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly body: unknown,
  ) {
    super(message);
    this.name = "ShadowWardenError";
  }
}

export class ShadowWardenClient {
  private readonly _baseUrl: string;
  private readonly _headers: Record<string, string>;
  private readonly _timeout: number;

  readonly community: CommunityResource;
  readonly marketplace: MarketplaceResource;
  readonly compliance: ComplianceResource;
  readonly semantic: SemanticResource;
  readonly documents: DocumentResource;

  constructor(config: ClientConfig) {
    if (!config.apiKey) throw new Error("apiKey is required");
    this._baseUrl = (config.baseUrl ?? "https://api.shadow-warden-ai.com").replace(/\/$/, "");
    this._timeout = config.timeout ?? 15_000;
    this._headers = {
      "X-API-Key": config.apiKey,
      "Content-Type": "application/json",
      Accept: "application/json",
    };

    this.community   = new CommunityResource(this);
    this.marketplace = new MarketplaceResource(this);
    this.compliance  = new ComplianceResource(this);
    this.semantic    = new SemanticResource(this);
    this.documents   = new DocumentResource(this);
  }

  // ── Internal fetch helpers ──────────────────────────────────────────────────

  async _get<T>(path: string, params?: Record<string, string | number | boolean>): Promise<T> {
    const url = new URL(`${this._baseUrl}${path}`);
    if (params) {
      for (const [k, v] of Object.entries(params)) {
        if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
      }
    }
    return this._fetch<T>(url.toString(), { method: "GET" });
  }

  async _post<T>(path: string, body: unknown): Promise<T> {
    return this._fetch<T>(`${this._baseUrl}${path}`, {
      method: "POST",
      body: JSON.stringify(body),
    });
  }

  async _delete<T>(path: string): Promise<T> {
    return this._fetch<T>(`${this._baseUrl}${path}`, { method: "DELETE" });
  }

  private async _fetch<T>(url: string, init: RequestInit): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this._timeout);
    try {
      const res = await fetch(url, {
        ...init,
        headers: { ...this._headers, ...(init.headers as Record<string, string> ?? {}) },
        signal: controller.signal,
      });
      const text = await res.text();
      let json: unknown;
      try { json = JSON.parse(text); } catch { json = { detail: text }; }
      if (!res.ok) {
        const msg = (json as Record<string, unknown>)?.detail ?? `HTTP ${res.status}`;
        throw new ShadowWardenError(String(msg), res.status, json);
      }
      return json as T;
    } finally {
      clearTimeout(timer);
    }
  }

  // ── Top-level convenience methods ───────────────────────────────────────────

  async filter(content: string, tenantId = "default"): Promise<FilterResult> {
    return this._post<FilterResult>("/filter", { content, tenant_id: tenantId });
  }

  async health(): Promise<HealthResult> {
    return this._get<HealthResult>("/health");
  }
}
