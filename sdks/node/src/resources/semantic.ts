// sdks/node/src/resources/semantic.ts

import type { ShadowWardenClient } from "../client.js";
import type {
  SemanticModel,
  SemanticQueryRequest,
  SemanticQueryResult,
} from "../types.js";

export class SemanticResource {
  constructor(private readonly _client: ShadowWardenClient) {}

  listModels(): Promise<{ models: SemanticModel[]; count: number }> {
    return this._client._get<{ models: SemanticModel[]; count: number }>(
      "/semantic-layer/models",
    );
  }

  getModel(modelId: string): Promise<SemanticModel> {
    return this._client._get<SemanticModel>(`/semantic-layer/models/${modelId}`);
  }

  query(req: SemanticQueryRequest): Promise<SemanticQueryResult> {
    return this._client._post<SemanticQueryResult>("/semantic-layer/query", req);
  }

  aiQuery(
    question: string,
    tenantId = "default",
  ): Promise<SemanticQueryResult & { intent: string }> {
    return this._client._post<SemanticQueryResult & { intent: string }>(
      "/semantic-layer/ai-query",
      { question, tenant_id: tenantId },
    );
  }

  registerModel(model: Omit<SemanticModel, "id"> & { id: string }): Promise<SemanticModel> {
    return this._client._post<SemanticModel>("/semantic-layer/models/catalog", model);
  }
}
