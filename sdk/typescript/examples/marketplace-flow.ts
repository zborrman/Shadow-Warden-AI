/**
 * examples/marketplace-flow.ts
 * Full M2M trade cycle: register agents → create listing → purchase → confirm.
 *
 * Run:
 *   SHADOW_WARDEN_API_KEY=sw-xxx npx ts-node examples/marketplace-flow.ts
 */
import { ShadowWardenClient } from "../src/index.js";
import * as crypto from "crypto";

const client = new ShadowWardenClient({
  apiKey: process.env.SHADOW_WARDEN_API_KEY ?? "",
  baseUrl: process.env.SHADOW_WARDEN_BASE_URL ?? "https://api.shadow-warden-ai.com",
});

async function main() {
  const tenantId = "demo-tenant";
  const communityId = "demo-community";

  // Generate ephemeral Ed25519 keypair for each agent
  const sellerKey = crypto.generateKeyPairSync("ed25519");
  const buyerKey  = crypto.generateKeyPairSync("ed25519");
  const sellerPub = sellerKey.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const buyerPub  = buyerKey.publicKey.export({ type: "spki", format: "der" }).toString("base64");

  // 1. Register seller agent
  console.log("Registering seller agent...");
  const seller = await client.marketplace.registerAgent({
    tenant_id: tenantId,
    community_id: communityId,
    public_key: sellerPub,
    capabilities: ["marketplace_sell"],
  });
  console.log("Seller:", seller.agent_id.slice(0, 24));

  // 2. Register buyer agent
  console.log("Registering buyer agent...");
  const buyer = await client.marketplace.registerAgent({
    tenant_id: tenantId,
    community_id: communityId,
    public_key: buyerPub,
    capabilities: ["marketplace_buy"],
  });
  console.log("Buyer:", buyer.agent_id.slice(0, 24));

  // 3. Create a listing
  console.log("Creating listing...");
  const listing = await client.marketplace.createListing({
    asset_id: `asset-${Date.now()}`,
    seller_agent_id: seller.agent_id,
    community_id: communityId,
    tenant_id: tenantId,
    asset_type: "rule",
    price_usd: 9.99,
    chain: "sepolia",
  });
  console.log("Listing:", listing.listing_id, "| price $", listing.price_usd);

  // 4. Purchase listing (creates escrow)
  console.log("Purchasing listing...");
  const purchase = await client.marketplace.purchaseListing(
    listing.listing_id,
    buyer.agent_id,
  );
  console.log("Escrow:", purchase.escrow_id, "| chain:", purchase.chain);

  // 5. Fund escrow
  await client.marketplace.fundEscrow(purchase.escrow_id);
  console.log("Escrow funded");

  // 6. Confirm receipt (releases funds to seller)
  await client.marketplace.confirmReceipt(purchase.escrow_id);
  console.log("Receipt confirmed — trade complete!");

  // 7. Check marketplace stats
  const stats = await client.marketplace.stats();
  console.log(
    `Marketplace stats: ${stats.total_agents} agents, ` +
    `${stats.active_listings} listings, ` +
    `$${stats.total_volume_usd.toFixed(2)} volume`,
  );
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
