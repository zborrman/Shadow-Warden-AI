"use client";
import { useState } from "react";
import { LivePage, Panel, LiveTable, CommunityPicker, Pill } from "@/components/ui/live";
import { fmtDate } from "@/lib/live";

export default function PeeringPage() {
  const [community, setCommunity] = useState("");
  return (
    <LivePage title="Peering" subtitle="Inter-community links for exchanging encrypted entities">
      <CommunityPicker value={community} onChange={setCommunity} />
      <Panel title="Peerings">
        <LiveTable
          what="Peerings"
          enabled={!!community}
          path="/sep/peerings"
          params={{ community_id: community }}
          listKeys={["peerings"]}
          empty="No peerings for this community."
          cols={[
            { key: "peering_id", label: "Peering", mono: true },
            { key: "initiator_community", label: "Initiator", mono: true },
            { key: "target_community", label: "Target", mono: true },
            { key: "policy", label: "Policy", render: r => <Pill value={r.policy} tone="info" /> },
            { key: "status", label: "Status", render: r => <Pill value={r.status} /> },
            { key: "created_at", label: "Created", render: r => fmtDate(r.created_at) },
            { key: "accepted_at", label: "Established", render: r => fmtDate(r.accepted_at) },
          ]}
        />
      </Panel>
      <Panel title="Lifecycle">
        <ol className="list-decimal pl-5 space-y-1 text-xs text-gray-400">
          <li>Community A initiates: the peering is PENDING and an HMAC handshake token is returned once.</li>
          <li>The token goes to community B out of band.</li>
          <li>B accepts with the token: ACTIVE. Transfers follow the policy (MIRROR_ONLY, REWRAP_ALLOWED, FULL_SYNC).</li>
          <li>Either side revokes: REVOKED.</li>
        </ol>
      </Panel>
    </LivePage>
  );
}
