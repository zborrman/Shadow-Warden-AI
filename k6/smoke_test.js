/**
 * k6/smoke_test.js - Post-deploy smoke test (CI) and manual check
 * ---------------------------------------------------------------
 * Runs 1 VU for 30 s. k6 exits with code 99 when a threshold is violated.
 *
 * CI runs it with no API key, on purpose: production has one master key, and
 * this test does not justify copying it into GitHub. Without a key it checks:
 *   - /health answers ok
 *   - /health/pipeline?deep=true: a real jailbreak corpus through the real
 *     pipeline, plus one benign prompt, with nothing missed or over-blocked
 *   - /filter refuses an anonymous caller (REQUIRE_AUTH=true)
 *
 * With WARDEN_API_KEY set it also exercises POST /filter as a real caller:
 *   k6 run k6/smoke_test.js --env BASE_URL=https://warden.example.com \
 *     --env WARDEN_API_KEY=...
 */

import http from "k6/http";
import { check, group, sleep } from "k6";

const BASE_URL     = __ENV.BASE_URL || "http://localhost:8001";
const API_KEY      = __ENV.WARDEN_API_KEY || "";
const REQUIRE_AUTH = __ENV.REQUIRE_AUTH === "true";

const JSON_HEADERS = { "Content-Type": "application/json" };
const KEY_HEADERS  = { ...JSON_HEADERS, ...(API_KEY ? { "X-API-Key": API_KEY } : {}) };

// Checks tagged with this fail the run. Timing checks are left out: one slow
// response after a deploy is worth seeing, not worth a red build.
const GATE = { gate: "yes" };

export const options = {
  vus:      1,
  duration: "30s",
  thresholds: {
    http_req_failed:     ["rate == 0"],     // zero errors in smoke
    http_req_duration:   ["p(95) < 3000"],  // all responses under 3 s
    "checks{gate:yes}":  ["rate == 1"],     // every correctness check passed
  },
};

export default function () {
  group("health", () => {
    const res = http.get(`${BASE_URL}/health`);
    check(res, {
      "health 200":       (r) => r.status === 200,
      "health status ok": (r) => r.json("status") === "ok",
    }, GATE);
    check(res, { "health fast": (r) => r.timings.duration < 500 });
  });

  // The canary runs the whole pipeline, so fire it once per run, not per loop.
  if (__ITER === 0) {
    group("pipeline_canary", () => {
      const res = http.get(`${BASE_URL}/health/pipeline?deep=true`);
      check(res, {
        "pipeline 200":        (r) => r.status === 200,
        "no degraded stages":  (r) => r.json("degraded_stages").length === 0,
        "canary ran":          (r) => r.json("canary.available") === true,
        "no jailbreak missed": (r) => r.json("canary.missed") === 0,
        "no false positive":   (r) => r.json("canary.false_positive") === 0,
      }, GATE);
    });
  }

  if (REQUIRE_AUTH) {
    group("filter_requires_key", () => {
      const res = http.post(
        `${BASE_URL}/filter`,
        JSON.stringify({ content: "What is the capital of France?" }),
        { headers: JSON_HEADERS, responseCallback: http.expectedStatuses(401) }
      );
      check(res, { "anonymous filter 401": (r) => r.status === 401 }, GATE);
    });
  }

  if (API_KEY) {
    group("filter_clean", () => {
      const res = http.post(
        `${BASE_URL}/filter`,
        JSON.stringify({ content: "What is the capital of France?", tenant_id: "smoke_test" }),
        { headers: KEY_HEADERS }
      );
      check(res, {
        "filter 200":   (r) => r.status === 200,
        "allowed true": (r) => r.json("allowed") === true,
      }, GATE);
      check(res, { "filter < 2 s": (r) => r.timings.duration < 2000 });
    });

    group("filter_pii", () => {
      const res = http.post(
        `${BASE_URL}/filter`,
        JSON.stringify({
          content:   "My email is test@example.com and my SSN is 123-45-6789.",
          tenant_id: "smoke_test",
        }),
        { headers: KEY_HEADERS }
      );
      check(res, {
        "pii filter 200":     (r) => r.status === 200,
        "pii has risk level": (r) => ["low", "medium", "high", "block"].includes(r.json("risk_level")),
      }, GATE);
    });
  }

  sleep(1);
}
