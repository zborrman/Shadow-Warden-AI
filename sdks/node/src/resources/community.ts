// sdks/node/src/resources/community.ts

import type { ShadowWardenClient } from "../client.js";
import type {
  Community,
  CommunityCreateRequest,
  CommunityMember,
} from "../types.js";

export class CommunityResource {
  constructor(private readonly _client: ShadowWardenClient) {}

  list(tenantId = "default"): Promise<Community[]> {
    return this._client._get<Community[]>("/communities", { tenant_id: tenantId });
  }

  get(communityId: string): Promise<Community> {
    return this._client._get<Community>(`/communities/${communityId}`);
  }

  create(req: CommunityCreateRequest): Promise<Community> {
    return this._client._post<Community>("/communities/create", req);
  }

  listMembers(communityId: string): Promise<CommunityMember[]> {
    return this._client._get<CommunityMember[]>(`/communities/${communityId}/members`);
  }

  inviteMember(
    communityId: string,
    memberId: string,
    role: "admin" | "member" = "member",
  ): Promise<{ knock_token: string }> {
    return this._client._post<{ knock_token: string }>(
      `/sep/knock/issue`,
      { community_id: communityId, invitee_tenant_id: memberId, suggested_role: role },
    );
  }

  rotateKeys(communityId: string): Promise<{ new_kid: string }> {
    return this._client._post<{ new_kid: string }>(
      `/communities/${communityId}/rotate`,
      {},
    );
  }

  upgradeToHybridPQC(communityId: string): Promise<{ is_hybrid: boolean }> {
    return this._client._post<{ is_hybrid: boolean }>(
      `/communities/${communityId}/upgrade-pqc`,
      {},
    );
  }
}
