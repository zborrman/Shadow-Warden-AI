/**
 * mobile/src/services/api.ts
 * ──────────────────────────
 * Shadow Warden gateway API client for the Mobile SOC app.
 */
import AsyncStorage from '@react-native-async-storage/async-storage';

export type AlertEntry = {
  request_id:   string;
  ts:           string;
  risk_level:   'high' | 'block' | 'medium' | 'low';
  tenant_id:    string;
  allowed:      boolean;
  flags:        string[];
  secrets_found: string[];
  elapsed_ms:   number;
};

export type XaiChain = {
  primary_cause?: { stage: string; verdict: string };
  counterfactuals: Array<{ stage: string; action: string; severity: string }>;
  stages: Array<{ stage: string; verdict: string; score: number; color: string }>;
};

class WardenApi {
  private baseUrl = 'https://api.shadow-warden-ai.com';
  private apiKey  = '';

  async loadConfig(): Promise<void> {
    const url = await AsyncStorage.getItem('warden_url');
    const key = await AsyncStorage.getItem('warden_api_key');
    if (url) this.baseUrl = url;
    if (key) this.apiKey  = key;
  }

  async saveConfig(url: string, apiKey: string): Promise<void> {
    this.baseUrl = url.replace(/\/$/, '');
    this.apiKey  = apiKey;
    await AsyncStorage.setItem('warden_url',     this.baseUrl);
    await AsyncStorage.setItem('warden_api_key', apiKey);
  }

  get configured(): boolean {
    return Boolean(this.apiKey);
  }

  private headers(): Record<string, string> {
    return { 'X-API-Key': this.apiKey, 'Content-Type': 'application/json' };
  }

  async getAlerts(limit = 50, minRisk = 'high'): Promise<AlertEntry[]> {
    const r = await fetch(
      `${this.baseUrl}/analytics/events?limit=${limit}`,
      { headers: this.headers() },
    );
    if (!r.ok) throw new Error(`${r.status}`);
    const data = await r.json();
    const entries: AlertEntry[] = data.events ?? data ?? [];
    const order = { block: 3, high: 2, medium: 1, low: 0 };
    const threshold = minRisk === 'block' ? 3 : minRisk === 'high' ? 2 : 1;
    return entries.filter(e => (order[e.risk_level] ?? 0) >= threshold);
  }

  async getXaiChain(requestId: string): Promise<XaiChain> {
    const r = await fetch(
      `${this.baseUrl}/xai/explain/${requestId}`,
      { headers: this.headers() },
    );
    if (!r.ok) throw new Error(`${r.status}`);
    return r.json();
  }

  async registerPushToken(token: string, platform: 'android' | 'ios', tenantId = 'default'): Promise<void> {
    const r = await fetch(`${this.baseUrl}/push/register`, {
      method:  'POST',
      headers: this.headers(),
      body:    JSON.stringify({ device_token: token, platform, tenant_id: tenantId }),
    });
    if (!r.ok) throw new Error(`push register failed: ${r.status}`);
  }

  async getHealth(): Promise<{ status: string }> {
    const r = await fetch(`${this.baseUrl}/health`, { headers: this.headers() });
    return r.json();
  }
}

export const api = new WardenApi();
