"use client";
import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ShieldAlert, CheckCircle, XCircle, AlertTriangle,
  Clock, Scale, Link2, RefreshCw, Search,
} from "lucide-react";
import { api, type MktEscrow } from "@/lib/api";

const WARDEN = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8001";

function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse bg-white/5 rounded-lg ${className}`} />;
}

function StatePill({ state }: { state: MktEscrow["state"] }) {
  const map: Record<MktEscrow["state"], string> = {
    funded:    "bg-blue-400/10 text-blue-400 border-blue-400/20",
    delivered: "bg-violet-400/10 text-violet-400 border-violet-400/20",
    confirmed: "bg-emerald-400/10 text-emerald-400 border-emerald-400/20",
    disputed:  "bg-red-400/10 text-red-400 border-red-400/20",
    resolved:  "bg-slate-400/10 text-slate-400 border-slate-400/20",
    refunded:  "bg-amber-400/10 text-amber-400 border-amber-400/20",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${map[state]}`}>
      {state}
    </span>
  );
}

function fmtUsd(v: number) {
  return `$${v.toFixed(2)}`;
}

function fmtDate(s: string) {
  return new Date(s).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "2-digit" });
}

async function resolveDispute(escrowId: string, resolution: "refund" | "release") {
  const r = await fetch(`${WARDEN}/marketplace/disputes/${encodeURIComponent(escrowId)}/resolve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ resolution }),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

type AuditEntry = {
  seq: number;
  prev_hash: string;
  bundle_hash: string;
  transfer_id: string;
  community_id: string;
  created_at: string;
  status: string;
};

export default function ModerationPage() {
  const qc = useQueryClient();
  const [tab, setTab]         = useState<"queue" | "audit">("queue");
  const [search, setSearch]   = useState("");
  const [resolving, setResolving] = useState<string | null>(null);
  const [actionErr, setActionErr] = useState("");

  const { data: escrows = [], isLoading: escLoading, refetch: refetchEsc } = useQuery({
    queryKey: ["mod-escrows"],
    queryFn:  () => api.mktEscrowList({ state: "disputed" }),
    staleTime: 15_000,
    retry: false,
  });

  const { data: allEscrows = [] } = useQuery({
    queryKey: ["mod-all-escrows"],
    queryFn:  () => api.mktEscrowList(),
    staleTime: 30_000,
    retry: false,
  });

  const { data: auditChain = [] } = useQuery<AuditEntry[]>({
    queryKey: ["mod-audit-chain"],
    queryFn:  async () => {
      const r = await fetch(`${WARDEN}/sep/audit-chain?limit=50`, {
        headers: { "X-API-Key": "" },
      });
      if (!r.ok) return [];
      const d = await r.json();
      return d.entries ?? d ?? [];
    },
    staleTime: 60_000,
    retry: false,
    enabled: tab === "audit",
  });

  const disputed = (escrows as MktEscrow[]).filter(e => e.state === "disputed");
  const filtered = disputed.filter(e =>
    !search ||
    e.escrow_id.toLowerCase().includes(search.toLowerCase()) ||
    e.buyer_agent.toLowerCase().includes(search.toLowerCase()) ||
    e.seller_agent.toLowerCase().includes(search.toLowerCase())
  );

  const stats = {
    total:    (allEscrows as MktEscrow[]).length,
    disputed: disputed.length,
    resolved: (allEscrows as MktEscrow[]).filter(e => e.state === "resolved").length,
    confirmed:(allEscrows as MktEscrow[]).filter(e => e.state === "confirmed").length,
  };

  async function handleResolve(escrowId: string, resolution: "refund" | "release") {
    setResolving(escrowId);
    setActionErr("");
    try {
      await resolveDispute(escrowId, resolution);
      qc.invalidateQueries({ queryKey: ["mod-escrows"] });
      qc.invalidateQueries({ queryKey: ["mod-all-escrows"] });
    } catch (e: unknown) {
      setActionErr(e instanceof Error ? e.message : "Action failed");
    } finally {
      setResolving(null);
    }
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-red-400" /> Moderation Queue
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">Dispute resolution and STIX audit trail</p>
        </div>
        <button
          onClick={() => { refetchEsc(); }}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs bg-white/5 hover:bg-white/10 text-slate-400 border border-white/8 transition"
        >
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: "Total Escrows", value: stats.total, icon: Scale,        color: "#0A84FF" },
          { label: "Disputed",      value: stats.disputed, icon: AlertTriangle, color: "#FF453A" },
          { label: "Resolved",      value: stats.resolved, icon: CheckCircle,  color: "#30D158" },
          { label: "Confirmed",     value: stats.confirmed, icon: Clock,       color: "#BF5AF2" },
        ].map(s => {
          const Icon = s.icon;
          return (
            <div key={s.label} className="rounded-xl border border-white/8 bg-white/3 p-4">
              <div
                className="w-7 h-7 rounded-lg flex items-center justify-center mb-2"
                style={{ background: `${s.color}18`, border: `1px solid ${s.color}30` }}
              >
                <Icon className="w-3.5 h-3.5" style={{ color: s.color }} />
              </div>
              <div className="text-2xl font-bold text-white">{s.value}</div>
              <div className="text-xs text-slate-400">{s.label}</div>
            </div>
          );
        })}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-white/4 rounded-xl p-1 w-fit">
        {(["queue", "audit"] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-1.5 rounded-lg text-xs font-medium transition ${
              tab === t ? "bg-white/10 text-white" : "text-slate-400 hover:text-slate-300"
            }`}
          >
            {t === "queue" ? "Dispute Queue" : "STIX Audit Log"}
          </button>
        ))}
      </div>

      {/* Error banner */}
      {actionErr && (
        <div className="flex items-center gap-2 p-3 bg-red-400/8 border border-red-400/20 rounded-xl text-sm text-red-400">
          <AlertTriangle className="w-4 h-4 shrink-0" /> {actionErr}
        </div>
      )}

      {tab === "queue" && (
        <div className="space-y-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search escrow ID or agent…"
              className="w-full pl-8 pr-3 py-2 bg-white/4 border border-white/8 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-red-500/40 transition"
            />
          </div>

          <div className="rounded-xl border border-white/8 bg-white/3 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/6">
                  {["Escrow ID", "Buyer", "Seller", "Amount", "State", "Created", "Actions"].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-medium text-slate-400">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {escLoading && Array.from({ length: 3 }).map((_, i) => (
                  <tr key={i} className="border-b border-white/4">
                    {Array.from({ length: 7 }).map((_, j) => (
                      <td key={j} className="px-4 py-3"><Skeleton className="h-4" /></td>
                    ))}
                  </tr>
                ))}
                {!escLoading && filtered.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-4 py-10 text-center text-slate-500">
                      No disputed escrows.
                    </td>
                  </tr>
                )}
                {filtered.map(e => (
                  <tr key={e.escrow_id} className="border-b border-white/4 hover:bg-white/2 transition-colors">
                    <td className="px-4 py-3 font-mono text-xs text-white">
                      {e.escrow_id.slice(0, 16)}…
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400">
                      {e.buyer_agent.slice(0, 14)}…
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400">
                      {e.seller_agent.slice(0, 14)}…
                    </td>
                    <td className="px-4 py-3 font-mono text-emerald-400 font-semibold">
                      {fmtUsd(e.amount_usd)}
                    </td>
                    <td className="px-4 py-3"><StatePill state={e.state} /></td>
                    <td className="px-4 py-3 text-xs text-slate-400">{fmtDate(e.created_at)}</td>
                    <td className="px-4 py-3">
                      <div className="flex gap-2">
                        <button
                          disabled={resolving === e.escrow_id}
                          onClick={() => handleResolve(e.escrow_id, "release")}
                          className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-medium bg-emerald-600/15 text-emerald-400 border border-emerald-500/25 hover:bg-emerald-600/25 transition disabled:opacity-50"
                        >
                          <CheckCircle className="w-3 h-3" /> Release
                        </button>
                        <button
                          disabled={resolving === e.escrow_id}
                          onClick={() => handleResolve(e.escrow_id, "refund")}
                          className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-medium bg-red-600/15 text-red-400 border border-red-500/25 hover:bg-red-600/25 transition disabled:opacity-50"
                        >
                          <XCircle className="w-3 h-3" /> Refund
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === "audit" && (
        <div className="rounded-xl border border-white/8 bg-white/3 overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-white/6">
            <Link2 className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-xs font-medium text-slate-400">STIX 2.1 Tamper-Evident Chain</span>
            <span className="ml-auto text-xs text-slate-500">{auditChain.length} entries</span>
          </div>
          <div className="divide-y divide-white/4">
            {auditChain.length === 0 && (
              <div className="px-4 py-10 text-center text-slate-500 text-sm">
                No audit entries yet.
              </div>
            )}
            {auditChain.map((entry, i) => (
              <div key={entry.seq ?? i} className="px-4 py-3 hover:bg-white/2 transition-colors">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-mono text-violet-400">#{entry.seq}</span>
                      <span
                        className={`text-xs px-1.5 py-0.5 rounded ${
                          entry.status === "ALLOWED"
                            ? "bg-emerald-400/10 text-emerald-400"
                            : "bg-red-400/10 text-red-400"
                        }`}
                      >
                        {entry.status ?? "UNKNOWN"}
                      </span>
                      <span className="text-xs text-slate-500">{fmtDate(entry.created_at)}</span>
                    </div>
                    <div className="text-xs font-mono text-slate-500 truncate">
                      TX: {entry.transfer_id?.slice(0, 20)}…
                    </div>
                    <div className="text-xs font-mono text-slate-600 truncate mt-0.5">
                      hash: {entry.bundle_hash?.slice(0, 32)}…
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    <div className="text-xs text-slate-500">prev</div>
                    <div className="text-xs font-mono text-slate-600">
                      {entry.prev_hash?.slice(0, 12)}…
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
