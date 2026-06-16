"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { DollarSign, Clock, CheckCircle, AlertTriangle, XCircle, ArrowRight } from "lucide-react";
import { api, type MktEscrow } from "@/lib/api";

function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse bg-white/5 rounded-lg ${className}`} />;
}

const STATE_META: Record<string, { label: string; color: string; icon: React.ReactNode; step: number }> = {
  funded:    { label: "Funded",    color: "text-blue-400",    icon: <DollarSign className="w-4 h-4" />,    step: 1 },
  delivered: { label: "Delivered", color: "text-yellow-400",  icon: <Clock className="w-4 h-4" />,         step: 2 },
  confirmed: { label: "Confirmed", color: "text-emerald-400", icon: <CheckCircle className="w-4 h-4" />,   step: 3 },
  disputed:  { label: "Disputed",  color: "text-red-400",     icon: <AlertTriangle className="w-4 h-4" />, step: 2 },
  resolved:  { label: "Resolved",  color: "text-emerald-400", icon: <CheckCircle className="w-4 h-4" />,   step: 4 },
  refunded:  { label: "Refunded",  color: "text-purple-400",  icon: <XCircle className="w-4 h-4" />,       step: 4 },
};

const PIPELINE = ["Funded", "Delivered", "Confirmed"];

function PipelineBar({ state }: { state: string }) {
  const step = STATE_META[state]?.step ?? 0;
  return (
    <div className="flex items-center gap-0 mb-4">
      {PIPELINE.map((label, i) => (
        <div key={label} className="flex items-center flex-1 last:flex-none">
          <div className={`flex flex-col items-center ${i + 1 <= step ? "text-emerald-400" : "text-white/20"}`}>
            <div className={`w-6 h-6 rounded-full border-2 flex items-center justify-center text-xs font-bold transition-colors ${
              i + 1 < step  ? "bg-emerald-500 border-emerald-500 text-white" :
              i + 1 === step ? "bg-blue-500 border-blue-500 text-white" :
                               "bg-white/5 border-white/20"
            }`}>
              {i + 1 < step ? "✓" : i + 1}
            </div>
            <span className="text-xs mt-1 hidden sm:block">{label}</span>
          </div>
          {i < PIPELINE.length - 1 && (
            <div className={`h-px flex-1 mx-1 transition-colors ${i + 1 < step ? "bg-emerald-500/50" : "bg-white/10"}`} />
          )}
        </div>
      ))}
    </div>
  );
}

function EscrowCard({ escrow, onClick, selected }: { escrow: MktEscrow; onClick: () => void; selected: boolean }) {
  const meta = STATE_META[escrow.state] ?? STATE_META.funded;
  return (
    <div
      onClick={onClick}
      className={`p-4 rounded-xl border cursor-pointer transition-all ${
        selected ? "border-blue-500 bg-blue-500/10" : "border-white/10 bg-white/5 hover:border-white/20"
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-xs text-white/40 font-mono truncate">{escrow.escrow_id}</p>
          <p className="text-sm text-white font-semibold mt-0.5 truncate">{escrow.listing_id}</p>
        </div>
        <div className={`flex items-center gap-1 text-xs font-semibold flex-shrink-0 ${meta.color}`}>
          {meta.icon}
          {meta.label}
        </div>
      </div>
      <div className="flex justify-between text-xs text-white/50 mt-3">
        <span className="font-mono truncate max-w-[120px]">{escrow.buyer_agent}</span>
        <ArrowRight className="w-3 h-3 mx-1 flex-shrink-0" />
        <span className="font-mono truncate max-w-[120px]">{escrow.seller_agent}</span>
        <span className="ml-auto font-bold text-white">${escrow.amount_usd.toFixed(2)}</span>
      </div>
    </div>
  );
}

export default function EscrowPage() {
  const [selected, setSelected] = useState<string | null>(null);
  const [stateFilter, setFilter] = useState<string>("all");
  const [voteSubmitting, setVoting] = useState(false);
  const [voteResult, setVoteResult] = useState<string | null>(null);

  const { data: escrows, isLoading, refetch } = useQuery({
    queryKey: ["mkt-escrow", stateFilter],
    queryFn: () => api.mktEscrowList(stateFilter !== "all" ? { state: stateFilter } : undefined),
    staleTime: 15_000,
    refetchInterval: 30_000,
  });

  const { data: detail } = useQuery({
    queryKey: ["mkt-escrow-detail", selected],
    queryFn: () => selected ? api.mktEscrowGet(selected) : null,
    enabled: !!selected,
    staleTime: 10_000,
  });

  async function vote(vote: "approve" | "reject") {
    if (!selected) return;
    setVoting(true);
    setVoteResult(null);
    try {
      const API = process.env.NEXT_PUBLIC_API_URL ?? "https://api.shadow-warden-ai.com";
      const resp = await fetch(`${API}/marketplace/escrow/${selected}/dispute/vote`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ vote, voter_id: "soc_operator", rationale: "SOC dashboard vote" }),
      });
      const j = await resp.json().catch(() => ({}));
      setVoteResult(resp.ok ? `Vote cast: ${vote}` : (j.detail ?? "Error"));
      refetch();
    } finally {
      setVoting(false);
    }
  }

  const selectedEscrow = detail ?? escrows?.find((e) => e.escrow_id === selected);
  const counts = {
    funded:   (escrows ?? []).filter((e) => e.state === "funded").length,
    delivered: (escrows ?? []).filter((e) => e.state === "delivered").length,
    disputed: (escrows ?? []).filter((e) => e.state === "disputed").length,
    confirmed: (escrows ?? []).filter((e) => e.state === "confirmed").length,
  };

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Escrow Dashboard</h1>
          <p className="text-white/50 text-sm mt-1">Monitor purchase pipelines and dispute resolution</p>
        </div>
      </div>

      {/* Pipeline summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {(["funded","delivered","disputed","confirmed"] as const).map((s) => {
          const meta = STATE_META[s];
          return (
            <button
              key={s}
              onClick={() => setFilter(s === stateFilter ? "all" : s)}
              className={`p-4 rounded-xl border text-left transition-all ${
                stateFilter === s ? "border-blue-500 bg-blue-500/10" : "border-white/10 bg-white/5 hover:border-white/20"
              }`}
            >
              <div className={`text-sm font-semibold mb-1 ${meta.color}`}>{meta.label}</div>
              <div className="text-2xl font-bold text-white">{counts[s]}</div>
            </button>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Escrow list */}
        <div className="lg:col-span-2 space-y-2">
          {isLoading ? (
            Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-20" />)
          ) : !escrows?.length ? (
            <div className="bg-white/5 rounded-xl border border-white/10 p-8 text-center text-white/40 text-sm">
              No escrows found{stateFilter !== "all" ? ` in state "${stateFilter}"` : ""}.
            </div>
          ) : (
            escrows.map((e) => (
              <EscrowCard
                key={e.escrow_id}
                escrow={e}
                selected={selected === e.escrow_id}
                onClick={() => setSelected(e.escrow_id === selected ? null : e.escrow_id)}
              />
            ))
          )}
        </div>

        {/* Detail panel */}
        <div className="bg-white/5 rounded-xl border border-white/10 p-4">
          <h2 className="text-sm font-semibold text-white mb-4">Escrow Detail</h2>
          {!selected || !selectedEscrow ? (
            <p className="text-white/30 text-xs">Click an escrow to inspect.</p>
          ) : (
            <div className="space-y-4 text-sm">
              <PipelineBar state={selectedEscrow.state} />
              <div className="space-y-2">
                {[
                  ["ID",          selectedEscrow.escrow_id],
                  ["Listing",     selectedEscrow.listing_id],
                  ["Buyer",       selectedEscrow.buyer_agent],
                  ["Seller",      selectedEscrow.seller_agent],
                  ["Amount",      `$${selectedEscrow.amount_usd.toFixed(2)}`],
                  ["Created",     new Date(selectedEscrow.created_at).toLocaleString()],
                  ...(selectedEscrow.chain_tx_hash ? [["TX Hash", selectedEscrow.chain_tx_hash.slice(0, 20) + "…"]] : []),
                ].map(([k, v]) => (
                  <div key={k} className="flex justify-between text-xs gap-2">
                    <span className="text-white/40 flex-shrink-0">{k}</span>
                    <span className="text-white font-mono text-right truncate">{v}</span>
                  </div>
                ))}
              </div>

              {selectedEscrow.state === "disputed" && (
                <div className="space-y-2 pt-2 border-t border-white/10">
                  <p className="text-xs text-red-400 font-semibold">⚠ Dispute Active — Cast DAO Vote</p>
                  {voteResult && (
                    <p className="text-xs text-emerald-400">{voteResult}</p>
                  )}
                  <div className="flex gap-2">
                    <button
                      onClick={() => vote("approve")}
                      disabled={voteSubmitting}
                      className="flex-1 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded-lg disabled:opacity-50 transition-colors"
                    >
                      Release to Seller
                    </button>
                    <button
                      onClick={() => vote("reject")}
                      disabled={voteSubmitting}
                      className="flex-1 py-2 bg-red-600 hover:bg-red-500 text-white text-xs font-semibold rounded-lg disabled:opacity-50 transition-colors"
                    >
                      Refund Buyer
                    </button>
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
