"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from "recharts";
import { ArrowLeftRight, TrendingUp, ShoppingCart, Users, AlertTriangle } from "lucide-react";
import { StatCard } from "@/components/ui/stat-card";
import { api } from "@/lib/api";

const PERIOD_OPTIONS = [
  { label: "30d", days: 30 },
  { label: "60d", days: 60 },
  { label: "90d", days: 90 },
];

const BAR_COLORS = ["#3b82f6", "#8b5cf6", "#10b981", "#f59e0b", "#ef4444"];

function fmtUsd(v: number) {
  if (v >= 1000) return `$${(v / 1000).toFixed(1)}k`;
  return `$${v.toFixed(2)}`;
}

function shortDid(did: string) {
  if (did.length <= 18) return did;
  return did.slice(0, 14) + "…";
}

function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse bg-white/5 rounded-lg ${className}`} />;
}

export default function MarketplacePage() {
  const [period, setPeriod] = useState(30);

  const p = { period_days: String(period) };

  const { data: summary, isLoading: sumLoading } = useQuery({
    queryKey: ["mkt-summary", period],
    queryFn:  () => api.mktSummary(p),
    retry: false,
  });

  const { data: volume, isLoading: volLoading } = useQuery({
    queryKey: ["mkt-volume", period],
    queryFn:  () => api.mktVolume(p),
    retry: false,
  });

  const { data: agents } = useQuery({
    queryKey: ["mkt-agents"],
    queryFn:  () => api.mktAgents(),
    retry: false,
  });

  const disputePct = summary ? (summary.dispute_rate * 100).toFixed(1) : "–";
  const disputeHigh = summary ? summary.dispute_rate > 0.05 : false;

  return (
    <div className="p-6 space-y-6 max-w-[1400px]">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
            <ArrowLeftRight size={16} className="text-blue-400" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-white">M2M Marketplace Analytics</h1>
            <p className="text-xs text-gray-500">Agent commerce activity and trading metrics</p>
          </div>
        </div>
        {/* Period pills */}
        <div className="flex gap-1 bg-white/5 rounded-lg p-1">
          {PERIOD_OPTIONS.map(opt => (
            <button
              key={opt.days}
              onClick={() => setPeriod(opt.days)}
              className={`px-3 py-1 text-xs rounded-md font-medium transition-colors ${
                period === opt.days
                  ? "bg-blue-600 text-white"
                  : "text-gray-400 hover:text-white"
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>

      {/* Stat cards */}
      {sumLoading ? (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
      ) : summary ? (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            label="Total Volume"
            value={fmtUsd(summary.total_volume_usd)}
            sub={`${period}d period`}
            icon={TrendingUp}
            accent="green"
          />
          <StatCard
            label="Completed Trades"
            value={summary.total_trades}
            sub={`Avg ${fmtUsd(summary.avg_price_usd)} each`}
            icon={ShoppingCart}
            accent="blue"
          />
          <StatCard
            label="Registered Agents"
            value={summary.registered_agents}
            sub={`${summary.active_listings} active listings`}
            icon={Users}
            accent="purple"
          />
          <StatCard
            label="Dispute Rate"
            value={`${disputePct}%`}
            sub={disputeHigh ? "Above 5% threshold" : "Within normal range"}
            icon={AlertTriangle}
            accent={disputeHigh ? "red" : "cyan"}
          />
        </div>
      ) : null}

      {/* Volume chart + Asset types */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Volume area chart */}
        <div className="lg:col-span-2 rounded-xl bg-surface-2 border border-border p-5">
          <p className="text-xs text-gray-500 font-medium uppercase tracking-wider mb-4">Daily Trading Volume</p>
          {volLoading ? (
            <Skeleton className="h-48" />
          ) : volume && volume.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={volume}>
                <defs>
                  <linearGradient id="volGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#3b82f6" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}   />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" tick={{ fontSize: 10, fill: "#6b7280" }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 10, fill: "#6b7280" }} tickLine={false} axisLine={false} tickFormatter={v => `$${v}`} />
                <Tooltip
                  contentStyle={{ background: "#1a2035", border: "1px solid #2a3350", borderRadius: 8, fontSize: 12 }}
                  formatter={(v: number) => [`$${v.toFixed(2)}`, "Volume"]}
                />
                <Area type="monotone" dataKey="volume_usd" stroke="#3b82f6" fill="url(#volGrad)" strokeWidth={2} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-48 flex items-center justify-center text-gray-500 text-sm">No volume data</div>
          )}
        </div>

        {/* Asset type bar chart */}
        <div className="rounded-xl bg-surface-2 border border-border p-5">
          <p className="text-xs text-gray-500 font-medium uppercase tracking-wider mb-4">Trades by Asset Type</p>
          {sumLoading ? (
            <Skeleton className="h-48" />
          ) : summary && summary.top_asset_types.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={summary.top_asset_types} layout="vertical">
                <XAxis type="number" tick={{ fontSize: 10, fill: "#6b7280" }} tickLine={false} axisLine={false} />
                <YAxis dataKey="type" type="category" tick={{ fontSize: 11, fill: "#9ca3af" }} tickLine={false} axisLine={false} width={56} />
                <Tooltip
                  contentStyle={{ background: "#1a2035", border: "1px solid #2a3350", borderRadius: 8, fontSize: 12 }}
                  formatter={(v: number) => [v, "Trades"]}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {summary.top_asset_types.map((_, i) => (
                    <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-48 flex items-center justify-center text-gray-500 text-sm">No data</div>
          )}
        </div>
      </div>

      {/* Escrow pipeline + Trade count chart */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Escrow pipeline */}
        <div className="rounded-xl bg-surface-2 border border-border p-5">
          <p className="text-xs text-gray-500 font-medium uppercase tracking-wider mb-4">Escrow Pipeline (current)</p>
          {sumLoading ? (
            <Skeleton className="h-44" />
          ) : summary ? (() => {
            const pipe = summary.escrow_pipeline;
            const data = [
              { stage: "Funded",    count: pipe.funded,    fill: "#3b82f6" },
              { stage: "Delivered", count: pipe.delivered, fill: "#8b5cf6" },
              { stage: "Confirmed", count: pipe.confirmed, fill: "#10b981" },
              { stage: "Disputed",  count: pipe.disputed,  fill: "#ef4444" },
            ];
            return (
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={data}>
                  <XAxis dataKey="stage" tick={{ fontSize: 11, fill: "#9ca3af" }} tickLine={false} axisLine={false} />
                  <YAxis tick={{ fontSize: 10, fill: "#6b7280" }} tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ background: "#1a2035", border: "1px solid #2a3350", borderRadius: 8, fontSize: 12 }}
                    formatter={(v: number) => [v, "Escrows"]}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {data.map((d, i) => <Cell key={i} fill={d.fill} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            );
          })() : null}
        </div>

        {/* Trade count time-series */}
        <div className="rounded-xl bg-surface-2 border border-border p-5">
          <p className="text-xs text-gray-500 font-medium uppercase tracking-wider mb-4">Daily Trade Count</p>
          {volLoading ? (
            <Skeleton className="h-44" />
          ) : volume && volume.length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={volume}>
                <defs>
                  <linearGradient id="tradeGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#8b5cf6" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0}   />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" tick={{ fontSize: 10, fill: "#6b7280" }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 10, fill: "#6b7280" }} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ background: "#1a2035", border: "1px solid #2a3350", borderRadius: 8, fontSize: 12 }}
                  formatter={(v: number) => [v, "Trades"]}
                />
                <Area type="monotone" dataKey="trades" stroke="#8b5cf6" fill="url(#tradeGrad)" strokeWidth={2} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-44 flex items-center justify-center text-gray-500 text-sm">No data</div>
          )}
        </div>
      </div>

      {/* Agent leaderboard */}
      {agents && (agents.top_sellers.length > 0 || agents.top_buyers.length > 0) && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <AgentTable title="Top Sellers" rows={agents.top_sellers} accent="#3b82f6" />
          <AgentTable title="Top Buyers"  rows={agents.top_buyers}  accent="#8b5cf6" />
        </div>
      )}
    </div>
  );
}

function AgentTable({
  title, rows, accent,
}: {
  title: string;
  rows: { agent_id: string; trades: number; volume_usd: number }[];
  accent: string;
}) {
  return (
    <div className="rounded-xl bg-surface-2 border border-border p-5">
      <p className="text-xs text-gray-500 font-medium uppercase tracking-wider mb-4">{title}</p>
      <table className="w-full text-xs">
        <thead>
          <tr className="text-gray-500 text-left border-b border-white/5">
            <th className="pb-2 font-medium">Agent</th>
            <th className="pb-2 font-medium text-right">Trades</th>
            <th className="pb-2 font-medium text-right">Volume</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={r.agent_id} className="border-b border-white/5 last:border-0">
              <td className="py-2 text-gray-300 font-mono">
                <span className="text-gray-600 mr-2">{i + 1}.</span>
                {shortDid(r.agent_id)}
              </td>
              <td className="py-2 text-right font-semibold" style={{ color: accent }}>{r.trades}</td>
              <td className="py-2 text-right text-gray-300">{fmtUsd(r.volume_usd)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
