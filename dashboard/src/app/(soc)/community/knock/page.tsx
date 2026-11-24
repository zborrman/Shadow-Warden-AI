"use client";
import { useState } from "react";
import { LivePage, Panel, LiveTable, CommunityPicker, Pill } from "@/components/ui/live";
import { fmtDate } from "@/lib/live";

export default function KnockPage() {
  const [community, setCommunity] = useState("");
  return (
    <LivePage title="Knock Invitations" subtitle="Closed invitations for verified Shadow Warden tenants — no public invite links">
      <CommunityPicker value={community} onChange={setCommunity} />
      <Panel title="Pending knocks">
        <LiveTable
          what="Knock invitations"
          enabled={!!community}
          path="/sep/knock/pending"
          params={{ community_id: community }}
          listKeys={["knocks", "pending"]}
          empty="No pending knocks for this community."
          cols={[
            { key: "knock_id", label: "Knock", mono: true },
            { key: "invitee_tenant_id", label: "Target tenant", mono: true },
            { key: "role", label: "Role" },
            { key: "clearance", label: "Clearance", render: r => <Pill value={r.clearance} tone="info" /> },
            { key: "created_at", label: "Issued", render: r => fmtDate(r.created_at) },
            { key: "expires_at", label: "Expires", render: r => fmtDate(r.expires_at) },
            { key: "status", label: "Status", render: r => <Pill value={r.status} /> },
          ]}
        />
      </Panel>
      <Panel title="How verification works">
        <ol className="list-decimal pl-5 space-y-1 text-xs text-gray-400">
          <li>An admin issues a knock; only its HMAC hash is stored, and it expires after 72 hours.</li>
          <li>The invited tenant accepts; the claiming tenant must be the invited one.</li>
          <li>A knock is single-use: once accepted it cannot be replayed.</li>
        </ol>
      </Panel>
    </LivePage>
  );
}
