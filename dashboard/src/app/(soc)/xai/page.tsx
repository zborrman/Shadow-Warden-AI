"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { LivePage, Panel, Kpi, Pill, RecordsTable, Empty } from "@/components/ui/live";
import { DataUnavailable } from "@/components/ui/data-unavailable";
import { liveGet } from "@/lib/live";

type Dashboard = {
  total: number;
  verdict_dist: Record<string, number>;
  top_primary_causes: { stage_id: string; count: number }[];
  stage_hit_rates: Record<string, { block: number; flag: number; pass: number; skip: number; block_rate: number }>;
  data_quality?: { complete: boolean; stages_without_evidence: string[]; note: string };
};

type ChainNode = { stage_id: string; stage_name: string; verdict: string; score: number | null; score_label: string };
type Chain = {
  request_id: string;
  final_verdict: string;
  risk_level: string;
  primary_cause_name: string;
  rationale: string;
  nodes: ChainNode[];
};

const HOURS = [24, 72, 168];

export default function XaiPage() {
  const [hours, setHours] = useState(24);
  const [rid, setRid] = useState("");
  const [lookup, setLookup] = useState("");

  const dash = useQuery({
    queryKey: ["/xai/dashboard", hours],
    queryFn: () => liveGet<Dashboard>("/xai/dashboard", { hours }),
    retry: false,
  });
  const chain = useQuery({
    queryKey: ["/xai/explain", lookup],
    queryFn: () => liveGet<Chain>(`/xai/explain/${encodeURIComponent(lookup)}`),
    enabled: !!lookup,
    retry: false,
  });
  const d = dash.data;

  return (
    <LivePage title="XAI Reports" subtitle="Why each verdict was reached, stage by stage">
      <div className="flex gap-2">
        {HOURS.map(h => (
          <button
            key={h}
            onClick={() => setHours(h)}
            className={h === hours ? "px-2 py-1 rounded-md text-xs bg-white/10 text-white" : "px-2 py-1 rounded-md text-xs text-gray-400 hover:text-white"}
          >
            {h === 168 ? "7d" : `${h}h`}
          </button>
        ))}
      </div>

      {dash.isError ? (
        <DataUnavailable what="XAI statistics" />
      ) : (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <Kpi label="Decisions explained" value={d ? d.total : "…"} />
            {["BLOCKED", "ALLOWED"].map(v => (
              <Kpi key={v} label={v} value={d ? (d.verdict_dist?.[v] ?? 0) : "…"} />
            ))}
            <Kpi label="Top cause" value={d?.top_primary_causes?.[0]?.stage_id ?? "—"} />
          </div>
          {d?.data_quality && !d.data_quality.complete && (
            <p className="text-[11px] text-yellow-400/90">
              {d.data_quality.note} Stages: {d.data_quality.stages_without_evidence.join(", ")}.
            </p>
          )}
          <Panel title="Stage hit rates">
            <RecordsTable
              empty="No decisions in this window."
              rows={Object.entries(d?.stage_hit_rates ?? {}).map(([stage, c]) => ({ stage, ...c }))}
              cols={[
                { key: "stage", label: "Stage", mono: true },
                { key: "block", label: "Block", mono: true },
                { key: "flag", label: "Flag", mono: true },
                { key: "pass", label: "Pass", mono: true },
                { key: "skip", label: "Skip", mono: true },
                { key: "block_rate", label: "Block rate", render: r => `${(Number(r.block_rate) * 100).toFixed(1)}%` },
              ]}
            />
          </Panel>
        </>
      )}

      <Panel
        title="Causal chain"
        aside={
          <form className="flex gap-2" onSubmit={e => { e.preventDefault(); setLookup(rid.trim()); }}>
            <input
              value={rid}
              onChange={e => setRid(e.target.value)}
              placeholder="request_id"
              aria-label="Request ID"
              className="bg-surface-3 border border-border rounded-md px-2 py-1 text-xs text-white font-mono w-64"
            />
            <button className="px-2 py-1 rounded-md border border-border text-xs text-gray-300 hover:text-white">Explain</button>
          </form>
        }
      >
        {!lookup ? (
          <Empty text="Enter a request ID from Filter Events to see its chain." />
        ) : chain.isError ? (
          <DataUnavailable what={`Explanation for ${lookup}`} />
        ) : chain.isLoading || !chain.data ? (
          <div className="h-20 rounded-lg bg-surface-3 animate-pulse" />
        ) : (
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-xs text-gray-400">
              <Pill value={chain.data.final_verdict} />
              <Pill value={chain.data.risk_level} />
              <span>Primary cause: <span className="text-gray-200">{chain.data.primary_cause_name || "—"}</span></span>
            </div>
            <RecordsTable
              empty="No stages recorded."
              rows={chain.data.nodes as unknown as Record<string, unknown>[]}
              cols={[
                { key: "stage_name", label: "Stage" },
                { key: "verdict", label: "Verdict", render: r => <Pill value={r.verdict} /> },
                { key: "score_label", label: "Score", mono: true },
              ]}
            />
            <div className="rounded-lg bg-surface-3 p-3">
              <p className="text-[10px] font-mono uppercase tracking-widest text-gray-500">Explanation</p>
              <p className="text-xs text-gray-300 mt-1">{chain.data.rationale}</p>
            </div>
            <div className="flex gap-3 text-xs">
              <a className="text-sky-400 hover:underline" href={`/api/warden/xai/report/${encodeURIComponent(lookup)}`} target="_blank" rel="noopener noreferrer">HTML report</a>
              <a className="text-sky-400 hover:underline" href={`/api/warden/xai/report/${encodeURIComponent(lookup)}/pdf`}>PDF report</a>
            </div>
          </div>
        )}
      </Panel>
    </LivePage>
  );
}
