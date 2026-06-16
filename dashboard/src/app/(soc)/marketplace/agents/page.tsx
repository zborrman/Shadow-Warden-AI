"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ShieldCheck, AlertTriangle, TrendingUp, Users } from "lucide-react";
import { StatCard } from "@/components/ui/stat-card";
import { api, type MktAgentTrust } from "@/lib/api";

function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse bg-white/5 rounded-lg ${className}`} />;
}

function TrustBadge({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const color =
    score >= 0.75 ? "text-emerald-400 bg-emerald-400/10" :
    score >= 0.45 ? "text-yellow-400 bg-yellow-400/10" :
                    "text-red-400 bg-red-400/10";
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono font-semibold ${color}`}>
      {pct}%
    </span>
  );
}

function RankBadge({ rank }: { rank: number }) {
  const medal = rank === 1 ? "🥇" : rank === 2 ? "🥈" : rank === 3 ? "🥉" : `#${rank}`;
  return <span className="text-sm font-bold text-white/70">{medal}</span>;
}

export default function AgentsPage() {
  const [selected, setSelected] = useState<string | null>(null);

  const { data: leaderboard, isLoading: lbLoading } = useQuery({
    queryKey: ["mkt-top-agents"],
    queryFn: () => api.mktTopAgents(20),
    staleTime: 30_000,
  });

  const { data: summary, isLoading: sumLoading } = useQuery({
    queryKey: ["mkt-summary"],
    queryFn: () => api.mktSummary(),
    staleTime: 30_000,
  });

  const { data: trust } = useQuery({
    queryKey: ["mkt-agent-trust", selected],
    queryFn: () => selected ? api.mktAgentTrust(selected) : null,
    enabled: !!selected,
  });

  const topCount   = leaderboard?.length ?? 0;
  const sybilCount = (leaderboard ?? []).filter((a) => a.sybil_flag).length;
  const avgScore   = leaderboard && leaderboard.length > 0
    ? leaderboard.reduce((s, a) => s + a.trust_score, 0) / leaderboard.length
    : 0;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Agent Registry</h1>
        <p className="text-white/50 text-sm mt-1">TrustRank leaderboard — PageRank-weighted by verified trade history</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {sumLoading ? (
          Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24" />)
        ) : (
          <>
            <StatCard label="Active Agents" value={String(summary?.registered_agents ?? topCount)} icon={Users} />
            <StatCard label="Avg TrustScore" value={`${Math.round(avgScore * 100)}%`} icon={ShieldCheck} />
            <StatCard label="Sybil Flags" value={String(sybilCount)} icon={AlertTriangle} trend={sybilCount > 0 ? { value: sybilCount, positive: false } : undefined} />
            <StatCard label="Total Volume" value={`$${((summary?.total_volume_usd ?? 0) / 1000).toFixed(1)}k`} icon={TrendingUp} />
          </>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-white/5 rounded-xl border border-white/10 overflow-hidden">
          <div className="p-4 border-b border-white/10">
            <h2 className="text-sm font-semibold text-white">TrustRank Leaderboard</h2>
          </div>
          <div className="overflow-x-auto">
            {lbLoading ? (
              <div className="p-4 space-y-3">
                {Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-10" />)}
              </div>
            ) : !leaderboard?.length ? (
              <div className="p-8 text-center text-white/40 text-sm">No agents registered yet.</div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-white/40 text-xs border-b border-white/10">
                    <th className="px-4 py-2 text-left">Rank</th>
                    <th className="px-4 py-2 text-left">Agent ID</th>
                    <th className="px-4 py-2 text-right">Trust</th>
                    <th className="px-4 py-2 text-right">Trades</th>
                    <th className="px-4 py-2 text-right">Volume</th>
                    <th className="px-4 py-2 text-center">Sybil</th>
                  </tr>
                </thead>
                <tbody>
                  {leaderboard.map((agent, i) => (
                    <tr
                      key={agent.agent_id}
                      onClick={() => setSelected(agent.agent_id === selected ? null : agent.agent_id)}
                      className={`border-b border-white/5 cursor-pointer hover:bg-white/5 transition-colors ${
                        selected === agent.agent_id ? "bg-blue-500/10" : ""
                      }`}
                    >
                      <td className="px-4 py-3"><RankBadge rank={i + 1} /></td>
                      <td className="px-4 py-3 font-mono text-xs text-white/80 max-w-[180px] truncate">{agent.agent_id}</td>
                      <td className="px-4 py-3 text-right"><TrustBadge score={agent.trust_score} /></td>
                      <td className="px-4 py-3 text-right text-white/60">{agent.trust_rank}</td>
                      <td className="px-4 py-3 text-right text-white/60">—</td>
                      <td className="px-4 py-3 text-center">
                        {agent.sybil_flag
                          ? <span className="text-red-400 text-xs font-bold">⚠ YES</span>
                          : <span className="text-emerald-400 text-xs">✓</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        <div className="bg-white/5 rounded-xl border border-white/10 p-4">
          <h2 className="text-sm font-semibold text-white mb-4">Agent Detail</h2>
          {!selected ? (
            <p className="text-white/30 text-xs">Click a row to inspect an agent.</p>
          ) : !trust ? (
            <div className="space-y-3">
              {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-8" />)}
            </div>
          ) : (
            <div className="space-y-4 text-sm">
              <div>
                <p className="text-white/40 text-xs mb-1">Agent ID</p>
                <p className="font-mono text-xs text-white break-all">{trust.agent_id}</p>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-white/5 rounded-lg p-3">
                  <p className="text-white/40 text-xs">TrustScore</p>
                  <p className="text-lg font-bold text-white">{Math.round(trust.trust_score * 100)}%</p>
                </div>
                <div className="bg-white/5 rounded-lg p-3">
                  <p className="text-white/40 text-xs">Rank</p>
                  <p className="text-lg font-bold text-white">#{trust.trust_rank}</p>
                </div>
              </div>
              <div className={`rounded-lg p-3 ${trust.sybil_flag ? "bg-red-500/10 border border-red-500/20" : "bg-emerald-500/10 border border-emerald-500/20"}`}>
                <p className={`text-xs font-semibold ${trust.sybil_flag ? "text-red-400" : "text-emerald-400"}`}>
                  {trust.sybil_flag ? "⚠ Sybil Attack Suspected" : "✓ No Sybil Indicators"}
                </p>
                {trust.sybil_flag && (
                  <p className="text-white/50 text-xs mt-1">Circular trade pattern detected. Manual review required.</p>
                )}
              </div>
              {trust.recent_trades && (
                <div>
                  <p className="text-white/40 text-xs mb-2">Recent Trades</p>
                  <div className="space-y-1">
                    {trust.recent_trades.slice(0, 5).map((t: { trade_id: string; status: string; amount_usd: number }, i: number) => (
                      <div key={i} className="flex justify-between text-xs text-white/60 bg-white/5 rounded px-2 py-1">
                        <span className="font-mono truncate max-w-[100px]">{t.trade_id}</span>
                        <span className={t.status === "completed" ? "text-emerald-400" : "text-yellow-400"}>{t.status}</span>
                        <span>${t.amount_usd.toFixed(2)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
