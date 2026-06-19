"use client";
import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from "recharts";
import {
  Tag, Filter, ShoppingCart, TrendingUp, Package,
  CheckCircle, AlertTriangle, Search, ExternalLink,
} from "lucide-react";
import { api, type MktListing, type MktAnalyticsSummary } from "@/lib/api";

const WARDEN = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8001";

function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse bg-white/5 rounded-lg ${className}`} />;
}

function StatusPill({ status }: { status: MktListing["status"] }) {
  const map = {
    active:   "bg-emerald-400/10 text-emerald-400 border-emerald-400/20",
    sold:     "bg-slate-400/10   text-slate-400   border-slate-400/20",
    delisted: "bg-red-400/10     text-red-400     border-red-400/20",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${map[status]}`}>
      {status}
    </span>
  );
}

function fmtUsd(v: number) {
  return `$${v.toFixed(2)}`;
}

function TrustBar({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const color = score >= 0.75 ? "bg-emerald-500" : score >= 0.45 ? "bg-yellow-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-white/8 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-slate-400 w-7 text-right">{pct}%</span>
    </div>
  );
}

const ASSET_TYPES = ["all", "rule", "model", "signals", "dataset", "api"];
const TYPE_COLORS: Record<string, string> = {
  rule: "#0A84FF", model: "#BF5AF2", signals: "#FF9F0A",
  dataset: "#30D158", api: "#FF453A",
};

async function buyListing(listingId: string, buyerAgent: string) {
  const r = await fetch(`${WARDEN}/marketplace/listings/${encodeURIComponent(listingId)}/purchase`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ buyer_agent_id: buyerAgent }),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

export default function ListingsPage() {
  const qc = useQueryClient();
  const [assetFilter, setAssetFilter] = useState("all");
  const [search, setSearch]           = useState("");
  const [buying, setBuying]           = useState<string | null>(null);
  const [buyAgent, setBuyAgent]       = useState("");
  const [buyErr, setBuyErr]           = useState("");

  const { data: listings = [], isLoading } = useQuery({
    queryKey: ["mkt-listings-full"],
    queryFn:  () => api.mktListings(),
    staleTime: 15_000,
    retry: false,
  });

  const { data: summary } = useQuery({
    queryKey: ["mkt-summary-listings"],
    queryFn:  () => api.mktSummary({ period_days: "30" }),
    staleTime: 60_000,
    retry: false,
  });

  const filtered = (listings as MktListing[]).filter(l => {
    if (assetFilter !== "all" && l.asset_type !== assetFilter) return false;
    if (search && !l.name?.toLowerCase().includes(search.toLowerCase()) &&
        !l.seller_agent?.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const byType = ASSET_TYPES.slice(1).map(t => ({
    type: t,
    count: (listings as MktListing[]).filter(l => l.asset_type === t).length,
  })).filter(x => x.count > 0);

  async function handleBuy(listingId: string) {
    if (!buyAgent.trim()) { setBuyErr("Enter your agent ID"); return; }
    setBuyErr("");
    try {
      await buyListing(listingId, buyAgent.trim());
      qc.invalidateQueries({ queryKey: ["mkt-listings-full"] });
      setBuying(null); setBuyAgent("");
    } catch (e: unknown) {
      setBuyErr(e instanceof Error ? e.message : "Purchase failed");
    }
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Marketplace Listings</h1>
          <p className="text-sm text-slate-400 mt-0.5">Browse and purchase AI assets across communities</p>
        </div>
        {summary && (
          <div className="flex gap-4 text-right">
            <div>
              <div className="text-lg font-bold text-white">{summary.active_listings}</div>
              <div className="text-xs text-slate-400">Active</div>
            </div>
            <div>
              <div className="text-lg font-bold text-emerald-400">{fmtUsd(summary.total_volume_usd)}</div>
              <div className="text-xs text-slate-400">30d Volume</div>
            </div>
          </div>
        )}
      </div>

      {/* Asset type distribution chart */}
      {byType.length > 0 && (
        <div className="rounded-xl border border-white/8 bg-white/3 p-4">
          <div className="text-xs font-medium text-slate-400 mb-3 flex items-center gap-1.5">
            <Package className="w-3.5 h-3.5" /> Asset Distribution
          </div>
          <ResponsiveContainer width="100%" height={60}>
            <BarChart data={byType} margin={{ top: 0, right: 0, bottom: 0, left: 0 }}>
              <XAxis dataKey="type" tick={{ fontSize: 10, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
              <YAxis hide />
              <Tooltip
                contentStyle={{ background: "#0d1220", border: "1px solid rgba(255,255,255,.1)", borderRadius: 8, fontSize: 11 }}
                labelStyle={{ color: "#94a3b8" }}
                itemStyle={{ color: "#e2e8f0" }}
              />
              <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                {byType.map(b => (
                  <Cell key={b.type} fill={TYPE_COLORS[b.type] ?? "#6b7280"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search name or seller…"
            className="w-full pl-8 pr-3 py-2 bg-white/4 border border-white/8 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 transition"
          />
        </div>
        <div className="flex items-center gap-1.5">
          <Filter className="w-3.5 h-3.5 text-slate-500" />
          {ASSET_TYPES.map(t => (
            <button
              key={t}
              onClick={() => setAssetFilter(t)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                assetFilter === t
                  ? "bg-blue-600/20 text-blue-400 border border-blue-500/30"
                  : "bg-white/4 text-slate-400 border border-white/8 hover:border-white/16"
              }`}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      {/* Listings table */}
      <div className="rounded-xl border border-white/8 bg-white/3 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/6">
              {["Asset", "Type", "Price", "Seller", "Trust", "Status", ""].map(h => (
                <th key={h} className="text-left px-4 py-3 text-xs font-medium text-slate-400">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {isLoading && Array.from({ length: 5 }).map((_, i) => (
              <tr key={i} className="border-b border-white/4">
                {Array.from({ length: 7 }).map((_, j) => (
                  <td key={j} className="px-4 py-3">
                    <Skeleton className="h-4 w-full" />
                  </td>
                ))}
              </tr>
            ))}
            {!isLoading && filtered.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-10 text-center text-slate-500 text-sm">
                  No listings match your filters.
                </td>
              </tr>
            )}
            {filtered.map(l => (
              <tr key={l.listing_id} className="border-b border-white/4 hover:bg-white/2 transition-colors">
                <td className="px-4 py-3">
                  <div className="font-medium text-white text-sm">{l.name || "Untitled"}</div>
                  <div className="text-xs text-slate-500 mt-0.5 max-w-[160px] truncate">{l.description || "—"}</div>
                </td>
                <td className="px-4 py-3">
                  <span
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium"
                    style={{ background: `${TYPE_COLORS[l.asset_type] ?? "#6b7280"}18`, color: TYPE_COLORS[l.asset_type] ?? "#6b7280" }}
                  >
                    <Tag className="w-2.5 h-2.5" />
                    {l.asset_type}
                  </span>
                </td>
                <td className="px-4 py-3 font-mono text-emerald-400 font-semibold text-sm">{fmtUsd(l.price_usd)}</td>
                <td className="px-4 py-3 text-xs text-slate-400 font-mono">
                  {l.seller_agent?.length > 16 ? `${l.seller_agent.slice(0, 14)}…` : l.seller_agent}
                </td>
                <td className="px-4 py-3 w-32">
                  <TrustBar score={l.trust_score ?? 0} />
                </td>
                <td className="px-4 py-3">
                  <StatusPill status={l.status} />
                </td>
                <td className="px-4 py-3">
                  {l.status === "active" && (
                    <button
                      onClick={() => { setBuying(l.listing_id); setBuyErr(""); }}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-blue-600/15 text-blue-400 border border-blue-500/25 hover:bg-blue-600/25 transition"
                    >
                      <ShoppingCart className="w-3 h-3" /> Buy
                    </button>
                  )}
                  {l.ipfs_hash && (
                    <a
                      href={`https://ipfs.io/ipfs/${l.ipfs_hash}`}
                      target="_blank"
                      rel="noreferrer"
                      className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300 mt-1"
                    >
                      <ExternalLink className="w-3 h-3" /> IPFS
                    </a>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Buy modal */}
      {buying && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-sm bg-[#0d1220] rounded-2xl border border-white/10 p-6 shadow-2xl">
            <h2 className="text-base font-bold text-white mb-4">Confirm Purchase</h2>
            <p className="text-sm text-slate-400 mb-4">
              Listing <span className="font-mono text-white">{buying.slice(0, 18)}…</span>
            </p>
            <div className="space-y-3">
              <div>
                <label className="text-xs font-medium text-slate-400 block mb-1.5">Your Agent ID</label>
                <input
                  value={buyAgent}
                  onChange={e => setBuyAgent(e.target.value)}
                  placeholder="agent:did:shadow:…"
                  className="w-full bg-white/4 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 transition"
                />
              </div>
              {buyErr && (
                <div className="flex items-center gap-1.5 text-xs text-red-400">
                  <AlertTriangle className="w-3.5 h-3.5" /> {buyErr}
                </div>
              )}
            </div>
            <div className="flex gap-2 mt-5">
              <button
                onClick={() => handleBuy(buying)}
                className="flex-1 py-2.5 rounded-xl text-sm font-semibold bg-blue-600 hover:bg-blue-500 text-white transition"
              >
                <CheckCircle className="w-3.5 h-3.5 inline mr-1.5" /> Confirm
              </button>
              <button
                onClick={() => { setBuying(null); setBuyErr(""); }}
                className="flex-1 py-2.5 rounded-xl text-sm font-medium bg-white/6 hover:bg-white/10 text-slate-300 transition"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
