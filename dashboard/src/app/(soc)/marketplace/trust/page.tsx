"use client";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { ShieldCheck, AlertTriangle, Network, TrendingUp, Zap } from "lucide-react";
import { api, type MktAgentTrust } from "@/lib/api";

function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse bg-white/5 rounded-lg ${className}`} />;
}

function TrustBar({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const color = score >= 0.75 ? "bg-emerald-500" : score >= 0.45 ? "bg-yellow-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-white/10 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono text-white/60 w-8 text-right">{pct}%</span>
    </div>
  );
}

function GraphCanvas({ nodes, edges }: {
  nodes: { id: string; trust_score: number; sybil_flag: boolean }[];
  edges: { source: string; target: string; weight: number }[];
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !nodes.length) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const W = canvas.width  = canvas.offsetWidth  * window.devicePixelRatio;
    const H = canvas.height = canvas.offsetHeight * window.devicePixelRatio;
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    const cw = canvas.offsetWidth;
    const ch = canvas.offsetHeight;

    ctx.clearRect(0, 0, cw, ch);

    const positions: Record<string, { x: number; y: number }> = {};
    const cx = cw / 2, cy = ch / 2;
    const r  = Math.min(cw, ch) * 0.37;
    nodes.forEach((n, i) => {
      const angle = (2 * Math.PI * i) / nodes.length - Math.PI / 2;
      positions[n.id] = {
        x: cx + r * Math.cos(angle),
        y: cy + r * Math.sin(angle),
      };
    });

    edges.forEach((e) => {
      const src = positions[e.source];
      const dst = positions[e.target];
      if (!src || !dst) return;
      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(dst.x, dst.y);
      ctx.strokeStyle = `rgba(59,130,246,${Math.min(0.6, e.weight)})`;
      ctx.lineWidth   = 1 + e.weight;
      ctx.stroke();
    });

    nodes.forEach((n) => {
      const pos = positions[n.id];
      if (!pos) return;
      const radius = 8 + n.trust_score * 10;
      const color  = n.sybil_flag ? "#ef4444" : n.trust_score >= 0.75 ? "#10b981" : n.trust_score >= 0.45 ? "#f59e0b" : "#6b7280";
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, radius, 0, 2 * Math.PI);
      ctx.fillStyle   = color + "33";
      ctx.strokeStyle = color;
      ctx.lineWidth   = 2;
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle  = "rgba(255,255,255,0.7)";
      ctx.font       = `${Math.max(8, window.devicePixelRatio < 2 ? 9 : 10)}px monospace`;
      ctx.textAlign  = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(n.id.slice(0, 8), pos.x, pos.y + radius + 10);
    });
  }, [nodes, edges]);

  return (
    <canvas
      ref={canvasRef}
      className="w-full h-full"
      style={{ display: "block" }}
    />
  );
}

export default function TrustPage() {
  const [search, setSearch] = useState("");

  const { data: leaderboard, isLoading: lbLoading } = useQuery({
    queryKey: ["trust-leaderboard"],
    queryFn:  () => api.mktTopAgents(50),
    staleTime: 30_000,
    refetchInterval: 60_000,
  });

  const { data: graph, isLoading: graphLoading } = useQuery({
    queryKey: ["trust-graph"],
    queryFn:  () => api.mktTrustGraph(),
    staleTime: 60_000,
  });

  const filtered = (leaderboard ?? []).filter(
    (a: MktAgentTrust) => !search || a.agent_id.toLowerCase().includes(search.toLowerCase())
  );

  const { data: maestroFlags } = useQuery({
    queryKey: ["maestro-flags"],
    queryFn:  async () => {
      const r = await fetch("/api/marketplace/maestro/flags?limit=50");
      if (!r.ok) return { flags: [] };
      return r.json();
    },
    staleTime: 60_000,
    refetchInterval: 120_000,
  });

  const sybilCount = (leaderboard ?? []).filter((a: MktAgentTrust) => a.sybil_flag).length;
  const avgScore   = leaderboard?.length
    ? leaderboard.reduce((s: number, a: MktAgentTrust) => s + a.trust_score, 0) / leaderboard.length
    : 0;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Reputation Center</h1>
        <p className="text-white/50 text-sm mt-1">TrustRank graph (PageRank α=0.85) · Sybil circular trade detection</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white/5 rounded-xl border border-white/10 p-4">
          <div className="flex items-center gap-2 text-white/40 text-xs mb-2"><Network className="w-3.5 h-3.5" /> Total Agents</div>
          <div className="text-2xl font-bold text-white">{leaderboard?.length ?? "—"}</div>
        </div>
        <div className="bg-white/5 rounded-xl border border-white/10 p-4">
          <div className="flex items-center gap-2 text-white/40 text-xs mb-2"><TrendingUp className="w-3.5 h-3.5" /> Avg Score</div>
          <div className="text-2xl font-bold text-white">{Math.round(avgScore * 100)}%</div>
        </div>
        <div className="bg-white/5 rounded-xl border border-white/10 p-4">
          <div className="flex items-center gap-2 text-red-400/70 text-xs mb-2"><AlertTriangle className="w-3.5 h-3.5" /> Sybil Flags</div>
          <div className={`text-2xl font-bold ${sybilCount > 0 ? "text-red-400" : "text-emerald-400"}`}>{sybilCount}</div>
        </div>
        <div className="bg-white/5 rounded-xl border border-white/10 p-4">
          <div className="flex items-center gap-2 text-white/40 text-xs mb-2"><ShieldCheck className="w-3.5 h-3.5" /> Graph Edges</div>
          <div className="text-2xl font-bold text-white">{graph?.edges?.length ?? "—"}</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Trust graph visualization */}
        <div className="lg:col-span-3 bg-white/5 rounded-xl border border-white/10 p-4">
          <h2 className="text-sm font-semibold text-white mb-3">Trust Graph</h2>
          <div className="h-80 rounded-lg bg-black/20 overflow-hidden">
            {graphLoading ? (
              <div className="flex items-center justify-center h-full text-white/30 text-sm">Loading graph…</div>
            ) : !graph?.nodes?.length ? (
              <div className="flex items-center justify-center h-full text-white/30 text-sm">
                No trade history yet. Complete some trades to populate the graph.
              </div>
            ) : (
              <GraphCanvas nodes={graph.nodes} edges={graph.edges} />
            )}
          </div>
          <p className="text-xs text-white/30 mt-2">
            Node size = TrustScore · Green = trusted · Red = sybil flag · Edge opacity = trade weight
          </p>
        </div>

        {/* Leaderboard */}
        <div className="lg:col-span-2 bg-white/5 rounded-xl border border-white/10 overflow-hidden">
          <div className="p-4 border-b border-white/10 flex items-center gap-3">
            <h2 className="text-sm font-semibold text-white flex-1">Leaderboard</h2>
            <input
              className="bg-white/5 border border-white/10 rounded-lg px-2 py-1 text-xs text-white placeholder:text-white/30 focus:outline-none focus:border-blue-500 w-32"
              placeholder="Filter agents…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <div className="overflow-y-auto max-h-80">
            {lbLoading ? (
              <div className="p-4 space-y-3">
                {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-12" />)}
              </div>
            ) : !filtered.length ? (
              <div className="p-6 text-center text-white/30 text-xs">No agents found.</div>
            ) : (
              filtered.map((agent: MktAgentTrust, i: number) => (
                <div key={agent.agent_id} className="px-4 py-3 border-b border-white/5 last:border-0 hover:bg-white/5 transition-colors">
                  <div className="flex items-center gap-3 mb-1.5">
                    <span className="text-xs text-white/30 w-6 flex-shrink-0">#{i + 1}</span>
                    <span className="font-mono text-xs text-white/80 flex-1 truncate">{agent.agent_id}</span>
                    {agent.sybil_flag && (
                      <span className="text-red-400 text-xs flex-shrink-0">⚠</span>
                    )}
                  </div>
                  <div className="pl-9">
                    <TrustBar score={agent.trust_score} />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {sybilCount > 0 && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            <h3 className="text-sm font-semibold text-red-400">Sybil Attack Detected</h3>
          </div>
          <p className="text-xs text-white/60">
            {sybilCount} agent{sybilCount > 1 ? "s" : ""} flagged for circular trade patterns.
            Review in Agent Registry and consider suspending marketplace access pending investigation.
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            {(leaderboard ?? []).filter((a: MktAgentTrust) => a.sybil_flag).map((a: MktAgentTrust) => (
              <span key={a.agent_id} className="bg-red-500/20 text-red-300 text-xs font-mono px-2 py-0.5 rounded">
                {a.agent_id.slice(0, 16)}…
              </span>
            ))}
          </div>
        </div>
      )}

      {/* MAESTRO Alerts */}
      {(maestroFlags?.flags?.length ?? 0) > 0 && (
        <div className="bg-orange-500/10 border border-orange-500/20 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <Zap className="w-4 h-4 text-orange-400" />
            <h3 className="text-sm font-semibold text-orange-400">MAESTRO Threat Flags</h3>
            <span className="ml-auto text-xs text-orange-300 bg-orange-500/20 px-2 py-0.5 rounded">
              {maestroFlags.flags.length} active
            </span>
          </div>
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {(maestroFlags.flags as { agent_id: string; flag_type: string; score: number; created_at: string }[]).map(
              (flag, i) => (
                <div key={i} className="flex items-center gap-3 text-xs">
                  <span className="font-mono text-white/60 w-28 flex-shrink-0 truncate">{flag.agent_id.slice(0, 16)}…</span>
                  <span className={`px-1.5 py-0.5 rounded text-xs font-medium flex-shrink-0 ${
                    flag.flag_type === "misalignment" ? "bg-yellow-500/20 text-yellow-300" :
                    flag.flag_type === "collusion"    ? "bg-orange-500/20 text-orange-300" :
                                                       "bg-red-500/20 text-red-300"
                  }`}>
                    {flag.flag_type}
                  </span>
                  <span className="text-white/40">score: {flag.score.toFixed(3)}</span>
                  <span className="text-white/30 ml-auto flex-shrink-0">
                    {new Date(flag.created_at).toLocaleDateString()}
                  </span>
                </div>
              )
            )}
          </div>
          <p className="text-xs text-white/40 mt-3">
            MAESTRO monitors goal misalignment, collusion, and model poisoning. Flagged agents receive a 10% reputation penalty.
          </p>
        </div>
      )}
    </div>
  );
}
