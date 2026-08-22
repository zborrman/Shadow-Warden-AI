/**
 * examples/basic-usage.ts
 * Demonstrates creating a community, registering a marketplace agent,
 * and running a compliance check.
 *
 * Run:
 *   SHADOW_WARDEN_API_KEY=sw-xxx npx ts-node examples/basic-usage.ts
 */
import { ShadowWardenClient } from "../src/index.js";

const client = new ShadowWardenClient({
  apiKey: process.env.SHADOW_WARDEN_API_KEY ?? "",
  baseUrl: process.env.SHADOW_WARDEN_BASE_URL ?? "https://api.shadow-warden-ai.com",
});

async function main() {
  // 1. Health check
  const health = await client.health();
  console.log("API status:", health.status, "version:", health.version);

  // 2. Filter a prompt
  const filterResult = await client.filter(
    "How do I access the admin panel?",
    "demo-tenant",
  );
  console.log(
    `Filter → ${filterResult.allowed ? "ALLOWED" : "BLOCKED"} | risk=${filterResult.risk_level}`,
  );

  // 3. List communities
  const communities = await client.community.list("demo-tenant");
  console.log(`Communities: ${communities.length} found`);

  // 4. Create a community
  const community = await client.community.create({
    name: "Demo Community",
    description: "Created via SDK example",
    visibility: "private",
    tenant_id: "demo-tenant",
  });
  console.log("Created community:", community.id);

  // 5. Compliance posture
  const posture = await client.compliance.getPosture("demo-tenant");
  console.log(`Compliance score: ${posture.overall_score} (${posture.grade})`);
  if (posture.gaps.length > 0) {
    console.log("Top gap:", posture.gaps[0].description);
  }

  // 6. Semantic Layer query
  const qResult = await client.semantic.query({
    model_id: "filter_events",
    metrics: ["request_count", "block_rate"],
    dimensions: ["risk_level"],
    limit: 10,
  });
  console.log("Generated SQL:", qResult.sql.slice(0, 80), "...");
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
