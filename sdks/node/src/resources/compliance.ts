// sdks/node/src/resources/compliance.ts

import type { ShadowWardenClient } from "../client.js";
import type {
  CompliancePosture,
  ComplianceGap,
  ComplianceHistory,
} from "../types.js";

export class ComplianceResource {
  constructor(private readonly _client: ShadowWardenClient) {}

  getPosture(tenantId = "default"): Promise<CompliancePosture> {
    return this._client._get<CompliancePosture>("/compliance/posture", {
      tenant_id: tenantId,
    });
  }

  getGaps(tenantId = "default"): Promise<ComplianceGap[]> {
    return this._client._get<ComplianceGap[]>("/compliance/posture/gaps", {
      tenant_id: tenantId,
    });
  }

  getHistory(tenantId = "default"): Promise<ComplianceHistory> {
    return this._client._get<ComplianceHistory>("/compliance/history", {
      tenant_id: tenantId,
    });
  }

  getFramework(
    framework: "gdpr" | "soc2" | "iso27001" | "hipaa",
    tenantId = "default",
  ): Promise<{ framework: string; score: number; controls: unknown[] }> {
    return this._client._get<{ framework: string; score: number; controls: unknown[] }>(
      `/compliance/posture/${framework}`,
      { tenant_id: tenantId },
    );
  }

  recalculate(tenantId = "default"): Promise<CompliancePosture> {
    return this._client._post<CompliancePosture>("/compliance/posture/recalculate", {
      tenant_id: tenantId,
    });
  }

  getISO27001(tenantId = "default"): Promise<{ controls: unknown[]; score: number }> {
    return this._client._get<{ controls: unknown[]; score: number }>(
      "/compliance/iso27001",
      { tenant_id: tenantId },
    );
  }

  getSOC2Evidence(): Promise<{ controls: unknown[] }> {
    return this._client._get<{ controls: unknown[] }>("/compliance/soc2/evidence");
  }
}
