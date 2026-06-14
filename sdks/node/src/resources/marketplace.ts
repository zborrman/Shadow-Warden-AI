// sdks/node/src/resources/marketplace.ts

import type { ShadowWardenClient } from "../client.js";
import type {
  MarketplaceAgent,
  AgentRegisterRequest,
  Listing,
  ListingCreateRequest,
  Escrow,
  GovernanceProposal,
  MarketplaceStats,
} from "../types.js";

export class MarketplaceResource {
  constructor(private readonly _client: ShadowWardenClient) {}

  // ── Agents ────────────────────────────────────────────────────────────────

  registerAgent(req: AgentRegisterRequest): Promise<MarketplaceAgent> {
    return this._client._post<MarketplaceAgent>("/marketplace/agents/register", req);
  }

  getAgent(agentId: string): Promise<MarketplaceAgent> {
    return this._client._get<MarketplaceAgent>(`/marketplace/agents/${agentId}`);
  }

  getTrust(agentId: string): Promise<{ trust_rank: number; sybil_risk: number }> {
    return this._client._get<{ trust_rank: number; sybil_risk: number }>(
      `/marketplace/agents/${agentId}/trust`,
    );
  }

  // ── Listings ──────────────────────────────────────────────────────────────

  createListing(req: ListingCreateRequest): Promise<Listing> {
    return this._client._post<Listing>("/marketplace/listings", req);
  }

  getListing(listingId: string): Promise<Listing> {
    return this._client._get<Listing>(`/marketplace/listings/${listingId}`);
  }

  listListings(params?: {
    communityId?: string;
    assetType?: string;
    maxPrice?: number;
    limit?: number;
  }): Promise<Listing[]> {
    return this._client._get<Listing[]>("/marketplace/listings", {
      community_id: params?.communityId ?? "",
      asset_type:   params?.assetType ?? "",
      max_price:    params?.maxPrice ?? "",
      limit:        params?.limit ?? 20,
    });
  }

  purchaseListing(
    listingId: string,
    buyerAgentId: string,
  ): Promise<{ escrow_id: string; chain: string; status: string }> {
    return this._client._post<{ escrow_id: string; chain: string; status: string }>(
      `/marketplace/listings/${listingId}/purchase`,
      { buyer_agent_id: buyerAgentId },
    );
  }

  // ── Escrow ────────────────────────────────────────────────────────────────

  getEscrow(escrowId: string): Promise<Escrow> {
    return this._client._get<Escrow>(`/marketplace/escrow/${escrowId}`);
  }

  fundEscrow(escrowId: string): Promise<{ funded: boolean }> {
    return this._client._post<{ funded: boolean }>(
      `/marketplace/escrow/${escrowId}/fund`,
      {},
    );
  }

  confirmReceipt(escrowId: string): Promise<{ confirmed: boolean }> {
    return this._client._post<{ confirmed: boolean }>(
      `/marketplace/escrow/${escrowId}/confirm`,
      {},
    );
  }

  raiseDispute(escrowId: string, reason: string): Promise<{ disputed: boolean }> {
    return this._client._post<{ disputed: boolean }>(
      `/marketplace/escrow/${escrowId}/dispute`,
      { reason },
    );
  }

  // ── Governance ────────────────────────────────────────────────────────────

  createProposal(params: {
    communityId: string;
    proposerId: string;
    proposalType: GovernanceProposal["proposal_type"];
    targetId: string;
    title: string;
    description?: string;
  }): Promise<GovernanceProposal> {
    return this._client._post<GovernanceProposal>("/marketplace/proposals", {
      community_id:  params.communityId,
      proposer_id:   params.proposerId,
      proposal_type: params.proposalType,
      target_id:     params.targetId,
      title:         params.title,
      description:   params.description ?? "",
    });
  }

  listProposals(communityId: string, status?: string): Promise<GovernanceProposal[]> {
    return this._client._get<GovernanceProposal[]>("/marketplace/proposals", {
      community_id: communityId,
      status: status ?? "",
    });
  }

  // ── Stats ─────────────────────────────────────────────────────────────────

  stats(): Promise<MarketplaceStats> {
    return this._client._get<MarketplaceStats>("/marketplace/stats");
  }
}
