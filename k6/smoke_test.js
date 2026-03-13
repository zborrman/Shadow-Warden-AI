/**
 * k6/smoke_test.js — Rapid smoke test (CI / pre-deploy gate)
 * ───────────────────────────────────────────────────────────
 * Runs 1 VU for 30 s. Purpose: confirm the gateway is up and
 * responding correctly before promoting a Docker image to production.
 *
 * Usage:
 *   k6 run k6/smoke_test.js
 *   k6 run k6/smoke_test.js --env BASE_URL=https://warden.example.com
 *
 * Exit code 0 = all thresholds passed (safe to deploy).
 * Exit code 1 = threshold violated (do not deploy).
 */

import http from "k6/http";
import { check, group, sleep } from "k6";

const BASE_URL = __ENV.BASE_URL || "http://localhost:8001";
const API_KEY  = __ENV.WARDEN_API_KEY || "";

const HEADERS = {
  "Content-Type": "application/json",
  ...(API_KEY ? { "X-API-Key": API_KEY } : {}),
};

export const options = {
  vus:      1,
  duration: "30s",
  thresholds: {
    http_req_failed:  ["rate == 0"],       // zero errors in smoke
    http_req_duration: ["p(95) < 3000"],   // all responses under 3 s
  },
};

export default function () {
  // ── Health ────────────────────────────────────────────────────────────────
  group("health", () => {
    const res = http.get(`${BASE_URL}/health`);
    check(res, {
      "health 200":  (r) => r.status === 200,
      "health fast": (r) => r.timings.duration < 500,
    });
  });

  // ── Clean prompt (expect allowed=true) ────────────────────────────────────
  group("filter_clean", () => {
    const res = http.post(
      `${BASE_URL}/filter`,
      JSON.stringify({
        content:   "What is the capital of France?",
        tenant_id: "smoke_test",
      }),
      { headers: HEADERS }
    );
    check(res, {
      "filter 200":     (r) => r.status === 200,
      "allowed true":   (r) => r.json("allowed") === true,
      "filter < 2 s":   (r) => r.timings.duration < 2000,
    });
  });

  // ── PII prompt (expect allowed=false or secrets_found non-empty) ──────────
  group("filter_pii", () => {
    const res = http.post(
      `${BASE_URL}/filter`,
      JSON.stringify({
        content:   "My email is test@example.com and my SSN is 123-45-6789.",
        tenant_id: "smoke_test",
      }),
      { headers: HEADERS }
    );
    check(res, {
      "pii filter 200":     (r) => r.status === 200,
      "pii has risk level": (r) => ["low","medium","high","block"].includes(r.json("risk_level")),
    });
  });

  // ── Stripe status (billing subsystem) ─────────────────────────────────────
  group("stripe_status", () => {
    const res = http.get(`${BASE_URL}/stripe/status?tenant_id=smoke_test`);
    check(res, {
      "stripe 200":      (r) => r.status === 200,
      "stripe has plan": (r) => typeof r.json("plan") === "string",
    });
  });

  sleep(1);
}
