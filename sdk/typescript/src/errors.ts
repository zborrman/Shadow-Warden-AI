/**
 * shadow-warden-client/errors.ts
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * Exception hierarchy for the Shadow Warden AI client.
 */

import type { FilterResult } from "./types.js";

/** Base class for all Shadow Warden client errors. */
export class WardenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WardenError";
    // Correct prototype chain in transpiled ES5
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when content is blocked by the gateway (risk level HIGH or BLOCK).
 * Access the full result via `.result`.
 *
 * @example
 * ```ts
 * try {
 *   await warden.filter(text, { raiseOnBlock: true });
 * } catch (e) {
 *   if (e instanceof WardenBlockedError) {
 *     console.log(e.result.riskLevel); // "high" | "block"
 *   }
 * }
 * ```
 */
export class WardenBlockedError extends WardenError {
  readonly result: FilterResult;

  constructor(result: FilterResult) {
    super(`Content blocked by Shadow Warden (risk: ${result.riskLevel})`);
    this.name = "WardenBlockedError";
    this.result = result;
  }
}

/**
 * Thrown when the gateway returns a non-200 HTTP response.
 */
export class WardenGatewayError extends WardenError {
  readonly statusCode: number;
  readonly detail: string;

  constructor(statusCode: number, detail: string) {
    super(`Gateway error ${statusCode}: ${detail}`);
    this.name = "WardenGatewayError";
    this.statusCode = statusCode;
    this.detail = detail;
  }
}

/**
 * Thrown when the request to the gateway times out.
 */
export class WardenTimeoutError extends WardenError {
  constructor(message = "Gateway request timed out") {
    super(message);
    this.name = "WardenTimeoutError";
  }
}
