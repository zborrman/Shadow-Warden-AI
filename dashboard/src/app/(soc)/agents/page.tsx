"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { LivePage, Panel, Kpi, Pill, LiveTable, RecordsTable, Empty } from "@/components/ui/live";
import { DataUnavailable } from "@/components/ui/data-unavailable";
import { liveGet, fmtDate } from "@/lib/live";

type Session = {
  session_id: string;
  first_seen: string;
  last_seen: string;
  request_count: number;
  block_count: number;
  risk_score: number;
  tool_names_seen: string[];
  threats_detected: { pattern?: string; threat?: string; severity?: string; detected_at?: string }[] | string[];
  events?: unknown[];
};

type Verify = { valid: boolean; reason?: string };

export default function AgentMonitorPage() {
  const [sid, setSid] = useState("");
  const [lookup, setLookup] = useState("");
  const session = useQuery({
    queryKey: ["/api/agent/session", lookup],
    queryFn: () => liveGet<Session>(`/api/agent/session/${encodeURIComponent(lookup)}`),
    enabled: !!lookup,
    retry: false,
  });
  const verify = useQuery({
    queryKey: ["/api/agent/session/verify", lookup],
    queryFn: () => liveGet<Verify>(`/api/agent/session/${encodeURIComponent(lookup)}/verify`),
    enabled: !!lookup,
    retry: false,
  });
  const s = session.data;
  const threats = (s?.threats_detected ?? []).map(t =>
    typeof t === "string" ? { pattern: t } : t,
  ) as Record<string, unknown>[];

  return (
    <LivePage title="Agent Monitor" subtitle="Agentic sessions — threat patterns across tool calls, attestation chain per session">
      <Panel title="Agents (GSAM telemetry)">
        <LiveTable
          what="Agent telemetry"
          path="/gsam/heatmap"
          listKeys={["agents"]}
          empty="No agent telemetry recorded yet."
          cols={[
            { key: "agent_id", label: "Agent", mono: true },
            { key: "events", label: "Events", mono: true },
            { key: "drift", label: "Drift", mono: true },
            { key: "trust", label: "Trust", mono: true },
            { key: "latest_hour", label: "Last active", render: r => fmtDate(r.latest_hour) },
          ]}
        />
      </Panel>

      <Panel
        title="Session"
        aside={
          <form className="flex gap-2" onSubmit={e => { e.preventDefault(); setLookup(sid.trim()); }}>
            <input
              value={sid}
              onChange={e => setSid(e.target.value)}
              placeholder="session_id"
              aria-label="Session ID"
              className="bg-surface-3 border border-border rounded-md px-2 py-1 text-xs text-white font-mono w-64"
            />
            <button className="px-2 py-1 rounded-md border border-border text-xs text-gray-300 hover:text-white">Open</button>
          </form>
        }
      >
        {!lookup ? (
          <Empty text="Enter an agent session ID to inspect it." />
        ) : session.isError ? (
          <DataUnavailable what={`Session ${lookup}`} />
        ) : !s ? (
          <div className="h-20 rounded-lg bg-surface-3 animate-pulse" />
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              <Kpi label="Requests" value={s.request_count} />
              <Kpi label="Blocked" value={s.block_count} />
              <Kpi label="Risk score" value={Number(s.risk_score).toFixed(2)} />
              <Kpi
                label="Attestation"
                value={verify.data ? <Pill value={verify.data.valid ? "valid" : "broken"} tone={verify.data.valid ? "good" : "bad"} /> : "…"}
                sub={verify.data?.reason}
              />
            </div>
            <p className="text-[11px] text-gray-500">
              First seen {fmtDate(s.first_seen)} · last seen {fmtDate(s.last_seen)} · tools:{" "}
              <span className="font-mono text-gray-300">{s.tool_names_seen?.join(", ") || "—"}</span>
            </p>
            <RecordsTable
              empty="No threat patterns detected in this session."
              rows={threats}
              cols={[
                { key: "pattern", label: "Pattern", mono: true },
                { key: "severity", label: "Severity", render: r => <Pill value={r.severity} /> },
                { key: "detected_at", label: "Detected", render: r => fmtDate(r.detected_at) },
              ]}
            />
          </div>
        )}
      </Panel>
      <p className="text-[11px] text-gray-500">
        No prompt content or tool arguments are stored — only tool names, timestamps and decisions.
      </p>
    </LivePage>
  );
}
