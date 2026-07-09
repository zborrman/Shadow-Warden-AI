"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from "recharts";
import { Activity, ShieldAlert, TrendingUp, Search } from "lucide-react";
import { Header } from "@/components/layout/header";

// GSAM read APIs are queried directly (plain fetch) so this page stays
// decoupled from the typed api client. Pro+ tier is required server-side.
const API_BASE =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8001";
const TIER_HEADERS: Record<string, string> = { "X-Tenant-Tier": "pro" };

async function gsamGet<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { headers: TIER_HEADERS });
  if (!res.ok) throw new Error(`GSAM ${path} → ${res.status}`);
  return res.json() as Promise<T>;
}

interface HeatmapBucket { category: string; events: number; cost_usd: number; }
interface HeatmapResp { source: string; group_by: string; buckets: HeatmapBucket[]; }
interface AgentStats {
  agent_id: string; events: number; cost_usd: number; roi: number;
  drift: number; trust: number; quarantined: boolean;
  tokens_in: number; tokens_out: number;
}
interface ComplianceResp {
  score: number; critical: boolean; agents_scanned: number;
  quarantined_count: number; strong_patterns: string[]; weak_patterns: string[];
}

const BAR_COLOR = "#6366f1";

export default function GsamPage() {
  const [hours, setHours] = useState(24);
  const [agentId, setAgentId] = useState("");
  const [agentQuery, setAgentQuery] = useState("");

  const heatmap = useQuery({
    queryKey: ["gsam-heatmap", hours],
    queryFn: () => gsamGet<HeatmapResp>(`/gsam/heatmap?hours=${hours}`),
  });
  const compliance = useQuery({
    queryKey: ["gsam-compliance"],
    queryFn: () => gsamGet<ComplianceResp>("/gsam/compliance/score"),
  });
  const agent = useQuery({
    queryKey: ["gsam-agent", agentQuery],
    queryFn: () => gsamGet<AgentStats>(`/gsam/agents/${encodeURIComponent(agentQuery)}/stats`),
    enabled: agentQuery.length > 0,
  });

  const score = compliance.data?.score ?? 1;
  const scoreColor = score >= 0.9 ? "#10b981" : score >= 0.5 ? "#f59e0b" : "#ef4444";

  return (
    <div className="min-h-screen">
      <Header title="GSAM Marketplace" subtitle="Global Statistic Agentic Marketplace — economics, drift & anti-inflation" />

      <div className="p-6 space-y-6">
        {/* Compliance summary */}
        <section className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card icon={ShieldAlert} label="Compliance Score" value={score.toFixed(2)} accent={scoreColor} />
          <Card icon={Activity} label="Agents Scanned" value={String(compliance.data?.agents_scanned ?? 0)} />
          <Card icon={ShieldAlert} label="Quarantined" value={String(compliance.data?.quarantined_count ?? 0)} />
          <Card
            icon={TrendingUp}
            label="Status"
            value={compliance.data?.critical ? "CRITICAL" : score < 1 ? "SIGNALS" : "CLEAN"}
            accent={compliance.data?.critical ? "#ef4444" : scoreColor}
          />
        </section>

        {/* Demand heatmap */}
        <section className="rounded-xl border border-border bg-surface-1/60 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-white">Demand Heatmap</h2>
            <select
              value={hours}
              onChange={(e) => setHours(Number(e.target.value))}
              className="bg-surface-2 border border-border rounded px-2 py-1 text-xs text-gray-300"
            >
              <option value={24}>24h</option>
              <option value={72}>3d</option>
              <option value={168}>7d</option>
            </select>
          </div>
          {heatmap.data?.buckets?.length ? (
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={heatmap.data.buckets}>
                <XAxis dataKey="category" tick={{ fontSize: 11, fill: "#9ca3af" }} />
                <YAxis tick={{ fontSize: 11, fill: "#9ca3af" }} />
                <Tooltip contentStyle={{ background: "#0a0f1e", border: "1px solid #1f2937" }} />
                <Bar dataKey="events" radius={[4, 4, 0, 0]}>
                  {heatmap.data.buckets.map((_, i) => <Cell key={i} fill={BAR_COLOR} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-sm text-gray-500">No marketplace activity in the selected window.</p>
          )}
          {heatmap.data && (
            <p className="text-xs text-gray-600 mt-2">
              Source: {heatmap.data.source} · grouped by {heatmap.data.group_by}
            </p>
          )}
        </section>

        {/* Agent lookup */}
        <section className="rounded-xl border border-border bg-surface-1/60 p-5">
          <h2 className="text-sm font-semibold text-white mb-4">Agent Stats</h2>
          <div className="flex gap-2 mb-4">
            <input
              value={agentId}
              onChange={(e) => setAgentId(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && setAgentQuery(agentId.trim())}
              placeholder="agent-…"
              className="flex-1 bg-surface-2 border border-border rounded px-3 py-2 text-sm text-gray-200"
            />
            <button
              onClick={() => setAgentQuery(agentId.trim())}
              className="flex items-center gap-1 px-3 py-2 rounded bg-indigo-600 hover:bg-indigo-500 text-white text-sm"
            >
              <Search size={14} /> Lookup
            </button>
          </div>
          {agent.data && (
            <>
              {agent.data.quarantined && (
                <div className="mb-3 rounded border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
                  🚫 Agent under GSAM drift quarantine.
                </div>
              )}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <Stat label="Events" value={agent.data.events.toLocaleString()} />
                <Stat label="Cost (USD)" value={`$${agent.data.cost_usd.toFixed(4)}`} />
                <Stat label="ROI" value={agent.data.roi.toFixed(2)} />
                <Stat label="Drift" value={agent.data.drift.toFixed(3)} />
                <Stat label="Trust" value={agent.data.trust.toFixed(2)} />
                <Stat label="Tokens In" value={agent.data.tokens_in.toLocaleString()} />
                <Stat label="Tokens Out" value={agent.data.tokens_out.toLocaleString()} />
              </div>
            </>
          )}
          {agent.isError && <p className="text-sm text-red-400">Agent not found.</p>}
        </section>
      </div>
    </div>
  );
}

function Card({
  icon: Icon, label, value, accent,
}: { icon: React.ElementType; label: string; value: string; accent?: string }) {
  return (
    <div className="rounded-xl border border-border bg-surface-1/60 p-4">
      <div className="flex items-center gap-2 text-gray-400 text-xs mb-2">
        <Icon size={14} /> {label}
      </div>
      <div className="text-2xl font-semibold" style={{ color: accent ?? "#fff" }}>{value}</div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border bg-surface-2/40 p-3">
      <div className="text-xs text-gray-500">{label}</div>
      <div className="text-lg font-semibold text-white">{value}</div>
    </div>
  );
}
