"use client";
import { useState } from "react";
import { LivePage, Panel, LiveTable, CommunityPicker, Pill } from "@/components/ui/live";
import { fmtDate } from "@/lib/live";

export default function DataPodsPage() {
  const [community, setCommunity] = useState("");
  return (
    <LivePage title="Data Pods" subtitle="Per-jurisdiction object storage — entities are routed to the pod of their legal boundary">
      <CommunityPicker value={community} onChange={setCommunity} />
      <div className="grid gap-4 lg:grid-cols-[1fr_280px]">
        <Panel title="Pods">
          <LiveTable
            what="Data pods"
            enabled={!!community}
            path="/sep/pods"
            params={{ community_id: community }}
            listKeys={["pods"]}
            empty="No data pods registered for this community."
            cols={[
              { key: "jurisdiction", label: "Jurisdiction", mono: true },
              { key: "minio_endpoint", label: "Endpoint", mono: true },
              { key: "bucket", label: "Bucket", mono: true },
              { key: "is_primary", label: "Primary", render: r => (r.is_primary ? "yes" : "—") },
              { key: "status", label: "Status", render: r => <Pill value={r.status} /> },
              { key: "created_at", label: "Added", render: r => fmtDate(r.created_at) },
            ]}
          />
        </Panel>
        <Panel title="Credentials">
          <p className="text-[11px] text-gray-500">
            Each pod keeps its own access key. Secret keys are Fernet-encrypted at rest and are
            never shown here.
          </p>
        </Panel>
      </div>
    </LivePage>
  );
}
