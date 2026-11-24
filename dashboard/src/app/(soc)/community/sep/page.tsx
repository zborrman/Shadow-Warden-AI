"use client";
import { useState } from "react";
import { LivePage, Panel, LiveTable, CommunityPicker } from "@/components/ui/live";
import { fmtDate } from "@/lib/live";

export default function SepHubPage() {
  const [community, setCommunity] = useState("");
  const [q, setQ] = useState("");
  const [submitted, setSubmitted] = useState("");
  return (
    <LivePage title="SEP Hub" subtitle="Syndicate Exchange Protocol — entities published by a community, addressed by UECIID">
      <CommunityPicker value={community} onChange={setCommunity} />
      <div className="grid gap-4 lg:grid-cols-[1fr_280px]">
        <Panel
          title="Hub entries"
          aside={
            <form className="flex gap-2" onSubmit={e => { e.preventDefault(); setSubmitted(q.trim()); }}>
              <input
                value={q}
                onChange={e => setQ(e.target.value)}
                placeholder="UECIID prefix or name…"
                aria-label="Search entries"
                className="bg-surface-3 border border-border rounded-md px-2 py-1 text-xs text-white w-56"
              />
              <button className="px-2 py-1 rounded-md border border-border text-xs text-gray-300 hover:text-white">
                Search
              </button>
            </form>
          }
        >
          <LiveTable
            what="SEP entries"
            enabled={!!community}
            path={submitted ? "/sep/search" : "/sep/list"}
            params={submitted ? { community_id: community, q: submitted } : { community_id: community }}
            listKeys={["items", "results"]}
            empty={submitted ? "No entry matches that search." : "This community has published no entries yet."}
            cols={[
              { key: "ueciid", label: "UECIID", mono: true },
              { key: "display_name", label: "Name" },
              { key: "content_type", label: "Type" },
              { key: "byte_size", label: "Bytes", mono: true },
              { key: "created_at", label: "Published", render: r => fmtDate(r.created_at) },
            ]}
          />
        </Panel>
        <Panel title="UECIID format">
          <p className="font-mono text-sm text-white">SEP-xxxxxxxxxxx</p>
          <p className="text-[11px] text-gray-500 mt-2">
            SEP- plus 11 base-62 characters encode a 64-bit Snowflake ID, so sorting IDs
            alphabetically sorts them by time.
          </p>
        </Panel>
      </div>
    </LivePage>
  );
}
