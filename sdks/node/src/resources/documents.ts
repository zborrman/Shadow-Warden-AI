// sdks/node/src/resources/documents.ts

import type { ShadowWardenClient } from "../client.js";
import type { DocumentConvertResult, DocumentScanResult } from "../types.js";

export class DocumentResource {
  constructor(private readonly _client: ShadowWardenClient) {}

  convert(params: {
    fileBase64: string;
    filename: string;
    tenantId?: string;
  }): Promise<DocumentConvertResult> {
    return this._client._post<DocumentConvertResult>("/document-intel/convert", {
      file_base64: params.fileBase64,
      filename: params.filename,
      tenant_id: params.tenantId ?? "default",
    });
  }

  scan(params: {
    content: string;
    source?: string;
    tenantId?: string;
  }): Promise<DocumentScanResult> {
    return this._client._post<DocumentScanResult>("/document-intel/scan", {
      content: params.content,
      source: params.source ?? "api",
      tenant_id: params.tenantId ?? "default",
    });
  }

  getStats(): Promise<{
    total_conversions: number;
    cache_hit_rate: number;
    supported_formats: string[];
  }> {
    return this._client._get<{
      total_conversions: number;
      cache_hit_rate: number;
      supported_formats: string[];
    }>("/document-intel/stats");
  }
}
