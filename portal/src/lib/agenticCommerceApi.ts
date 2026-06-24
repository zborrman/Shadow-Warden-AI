/**
 * portal/src/lib/agenticCommerceApi.ts
 * Typed client for the M2M Agentic Commerce API.
 * All calls go through /api/marketplace/* (server-side proxy).
 */

const BASE = '/api/marketplace'

async function mFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
  })
  if (!res.ok) {
    const body = await res.text().catch(() => res.statusText)
    throw new Error(`${res.status}: ${body}`)
  }
  return res.json() as Promise<T>
}

// ── Types ─────────────────────────────────────────────────────────────────────

export interface MktAgent {
  agent_id:     string
  community_id: string
  tenant_id:    string
  public_key:   string
  capabilities: string[]
  status:       string
  mandate_id:   string
  created_at:   string
}

export interface MktAsset {
  asset_id:        string
  asset_type:      string
  ipfs_hash:       string
  seller_agent_id: string
  community_id:    string
  tenant_id:       string
  created_at:      string
  token_data?:     Record<string, unknown>
}

export interface MktListing {
  listing_id:       string
  asset_id:         string
  seller_agent:     string
  community_id:     string
  tenant_id:        string
  asset_type:       string
  price_usd:        number
  currency:         string
  pricing_strategy: string
  status:           string
  demand_score:     number
  listed_at:        string
  expires_at:       string | null
  sold_at:          string | null
}

export interface MktNegotiation {
  negotiation_id:  string
  buyer_agent_id:  string
  seller_agent_id: string
  listing_id:      string
  status:          string
  current_price:   number
  offers:          MktOffer[]
}

export interface MktOffer {
  offer_id:      string
  from_agent_id: string
  price:         number
  message:       string
  created_at:    string
}

export interface MktEscrow {
  escrow_id:        string
  purchase_id:      string
  listing_id:       string
  buyer_agent:      string
  seller_agent:     string
  amount_usd:       number
  contract_address: string
  status:           string
  asset_hash:       string
  dispute_reason:   string
  created_at:       string
  funded_at:        string | null
  delivered_at:     string | null
  confirmed_at:     string | null
  expires_at:       string
}

export interface MktPurchase {
  purchase_id:    string
  listing_id:     string
  asset_id:       string
  buyer_agent:    string
  seller_agent:   string
  price_paid:     number
  status:         string
  escrow_id:      string
  negotiation_id: string
  purchased_at:   string
  completed_at:   string | null
}

export interface MktStats {
  agents:           number
  active_listings:  number
  total_listings:   number
  completed_trades: number
  pending_trades:   number
  total_volume_usd: number
}

// ── Agent API ─────────────────────────────────────────────────────────────────

export const agenticCommerceApi = {
  // Agents
  listAgents: (params?: { tenant_id?: string; community_id?: string }) =>
    mFetch<MktAgent[]>(`/agents?${new URLSearchParams(params as Record<string, string> ?? {})}`),

  registerAgent: (body: { tenant_id: string; community_id: string; public_key: string; capabilities: string[] }) =>
    mFetch<MktAgent>('/agents/register', { method: 'POST', body: JSON.stringify(body) }),

  updateCapabilities: (agentId: string, body: { tenant_id: string; capabilities: string[] }) =>
    mFetch<{ updated: boolean }>(`/agents/${agentId}/capabilities`, { method: 'PUT', body: JSON.stringify(body) }),

  patchAgent: (agentId: string, body: { name?: string; budget_limit?: number }) =>
    mFetch<{ updated: boolean }>(`/agents/${agentId}`, { method: 'PATCH', body: JSON.stringify(body) }),

  deactivateAgent: (agentId: string) =>
    mFetch<{ deactivated: boolean }>(`/agents/${agentId}`, { method: 'DELETE' }),

  getAgentTrust: (agentId: string) =>
    mFetch<{ agent_id: string; trust_score: number; trust_rank: number; sybil_flag: boolean; sybil_reason: string }>(`/agents/${agentId}/trust`),

  getMaestroFlags: () =>
    mFetch<{ flags: Array<{ agent_id: string; flag_type: string; reason: string; flagged_at: string }> }>('/maestro/flags'),

  // Assets
  listAssets: (params?: { agent_id?: string; type?: string; community_id?: string }) =>
    mFetch<MktAsset[]>(`/assets?${new URLSearchParams(params as Record<string, string> ?? {})}`),

  registerAsset: (body: { tenant_id: string; seller_agent_id: string; asset_type: string; raw_data: unknown }) =>
    mFetch<{ asset_id: string; asset_type: string; seller_agent_id: string }>('/assets', {
      method: 'POST', body: JSON.stringify(body),
    }),

  // Listings
  listListings: (params?: { community_id?: string; asset_type?: string; max_price?: number }) =>
    mFetch<MktListing[]>(`/listings?${new URLSearchParams(params as Record<string, string> ?? {})}`),

  createListing: (body: { asset_id: string; seller_agent_id: string; community_id: string; tenant_id: string; asset_type: string; price_usd: number; pricing_strategy?: string }) =>
    mFetch<MktListing>('/listings', { method: 'POST', body: JSON.stringify(body) }),

  buyListing: (listingId: string, buyerAgentId: string) =>
    mFetch<{ purchase_id: string; escrow_id: string; asset_id: string; price_paid: number }>(`/listings/${listingId}/purchase`, {
      method: 'POST', body: JSON.stringify({ buyer_agent_id: buyerAgentId }),
    }),

  // Negotiations
  startNegotiation: (body: { buyer_agent_id: string; seller_agent_id: string; listing_id: string; initial_price: number }) =>
    mFetch<MktNegotiation>('/negotiations', { method: 'POST', body: JSON.stringify(body) }),

  sendOffer: (negId: string, body: { from_agent_id: string; price: number; message?: string }) =>
    mFetch<MktOffer>(`/negotiations/${negId}/offer`, { method: 'POST', body: JSON.stringify(body) }),

  acceptOffer: (negId: string, fromAgentId: string) =>
    mFetch<{ accepted: boolean }>(`/negotiations/${negId}/accept`, {
      method: 'POST', body: JSON.stringify({ from_agent_id: fromAgentId, price: 0 }),
    }),

  getNegotiation: (negId: string) =>
    mFetch<MktNegotiation>(`/negotiations/${negId}`),

  // Escrow
  listEscrows: (params?: { agent_id?: string; role?: string; status?: string }) =>
    mFetch<MktEscrow[]>(`/escrows?${new URLSearchParams(params as Record<string, string> ?? {})}`),

  fundEscrow: (escrowId: string) =>
    mFetch<{ funded: boolean }>(`/escrow/${escrowId}/fund`, { method: 'POST', body: '{}' }),

  deliverAsset: (escrowId: string, assetHash: string) =>
    mFetch<{ delivered: boolean }>(`/escrow/${escrowId}/deliver`, {
      method: 'POST', body: JSON.stringify({ asset_hash: assetHash }),
    }),

  confirmReceipt: (escrowId: string) =>
    mFetch<{ confirmed: boolean }>(`/escrow/${escrowId}/confirm`, { method: 'POST', body: '{}' }),

  raiseDispute: (escrowId: string, reason: string) =>
    mFetch<{ disputed: boolean }>(`/escrow/${escrowId}/dispute`, {
      method: 'POST', body: JSON.stringify({ reason }),
    }),

  resolveDispute: (escrowId: string, releaseToBuyer: boolean) =>
    mFetch<{ resolved: boolean }>(`/escrow/${escrowId}/resolve`, {
      method: 'POST', body: JSON.stringify({ release_to_buyer: releaseToBuyer }),
    }),

  // Purchases
  listPurchases: (params?: { buyer_agent?: string; seller_agent?: string }) =>
    mFetch<MktPurchase[]>(`/purchases?${new URLSearchParams(params as Record<string, string> ?? {})}`),

  // Stats
  getStats: (tenantId?: string) =>
    mFetch<MktStats>(`/stats${tenantId ? `?tenant_id=${tenantId}` : ''}`),
}
