"use client";

import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Shield, Search, Clock, ExternalLink, Share2, Loader2, Users } from "lucide-react";
import { api, type CommunityFeedItem, type CommunityLookupResponse } from "@/lib/api";
import { cn } from "@/lib/utils";

const RISK_COLOR: Record<string, string> = {
  CRITICAL: "text-accent-red   bg-accent-red/10   border-accent-red/30",
  HIGH:     "text-accent-orange bg-accent-orange/10 border-accent-orange/30",
  MEDIUM:   "text-accent-yellow bg-accent-yellow/10 border-accent-yellow/30",
  LOW:      "text-accent-green  bg-accent-green/10  border-accent-green/30",
};

function RiskPill({ level }: { level: string }) {
  const cls = RISK_COLOR[level.toUpperCase()] ?? RISK_COLOR.LOW;
  return (
    <span className={cn("px-1.5 py-0.5 rounded text-[10px] font-semibold border font-mono", cls)}>
      {level}
    </span>
  );
}

function FeedRow({ item }: { item: CommunityFeedItem }) {
  const label = item.display_name.length > 52 ? item.display_name.slice(0, 52) + "…" : item.display_name;
  return (
    <div className="flex flex-col gap-1 py-2.5 border-b border-border/50 last:border-0 group">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <RiskPill level={item.risk_level} />
          <span className="text-xs text-gray-300 truncate">{label}</span>
        </div>
        <span className="text-[10px] text-gray-600 font-mono flex items-center gap-1 shrink-0">
          <Clock size={9} />
          {item.created_at.slice(0, 10)}
        </span>
      </div>
      <div className="flex items-center justify-between">
        <span className="text-[10px] text-gray-600 font-mono">{item.ueciid}</span>
        <a
          href={`/sep/${item.ueciid}`}
          className="text-[10px] text-accent-cyan hover:underline flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity"
        >
          <ExternalLink size={9} /> Details
        </a>
      </div>
    </div>
  );
}

function RecsPanel({ data }: { data: CommunityLookupResponse }) {
  return (
    <div className="mt-3 p-3 rounded-lg bg-surface-3 border border-border space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-white">
          SOVA found {data.total} entries for &quot;{data.query}&quot;
        </span>
        <span className="text-[10px] text-gray-500 font-mono">{data.source}</span>
      </div>
      {data.recommendations.length > 0 && (
        <ul className="space-y-1">
          {data.recommendations.slice(0, 4).map((r, i) => (
            <li key={i} className="text-xs text-gray-400 flex gap-2">
              <span className="text-accent-cyan shrink-0">›</span>
              <span>{r}</span>
            </li>
          ))}
        </ul>
      )}
      {data.ueciid && (
        <p className="text-[10px] text-accent-green font-mono">
          Published: {data.ueciid}
        </p>
      )}
    </div>
  );
}

export function CommunityDefenseWidget() {
  const [query, setQuery] = useState("");
  const [lastResult, setLastResult] = useState<CommunityLookupResponse | null>(null);

  const { data: feed, isLoading: feedLoading } = useQuery({
    queryKey:       ["community-feed", "recent"],
    queryFn:        () => api.communityFeed("jailbreak prompt injection", 6),
    refetchInterval: 90_000,
    retry: false,
  });

  const lookup = useMutation({
    mutationFn: (q: string) => api.communityLookup({ query: q, auto_publish: false }),
    onSuccess:  (data) => setLastResult(data),
  });

  const handleSearch = () => {
    const q = query.trim();
    if (q) lookup.mutate(q);
  };

  const items: CommunityFeedItem[] = feed?.results ?? [];

  return (
    <div className="rounded-xl bg-surface-2 border border-border p-5 flex flex-col gap-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="flex items-center justify-center w-7 h-7 rounded-lg bg-accent-cyan/10">
            <Users size={14} className="text-accent-cyan" />
          </div>
          <div>
            <p className="text-sm font-semibold text-white">Collective Defense</p>
            <p className="text-[10px] text-gray-500">SEP community threat feed</p>
          </div>
        </div>
        <span className="flex items-center gap-1.5 text-[10px] font-mono text-accent-green">
          <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse2" />
          LIVE
        </span>
      </div>

      {/* Search */}
      <div className="flex gap-2">
        <input
          type="text"
          placeholder="Search community feed…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSearch()}
          className="flex-1 h-8 px-3 rounded-lg bg-surface-3 border border-border text-xs text-white placeholder:text-gray-600 focus:outline-none focus:border-accent-cyan/50"
        />
        <button
          onClick={handleSearch}
          disabled={lookup.isPending || !query.trim()}
          className="h-8 px-3 rounded-lg bg-accent-cyan/10 border border-accent-cyan/30 text-accent-cyan hover:bg-accent-cyan/20 disabled:opacity-40 transition-colors"
        >
          {lookup.isPending ? <Loader2 size={13} className="animate-spin" /> : <Search size={13} />}
        </button>
      </div>

      {/* Results from lookup */}
      {lastResult && <RecsPanel data={lastResult} />}

      {/* Recent feed */}
      <div>
        <p className="text-[10px] uppercase tracking-wider text-gray-600 mb-2">Recent community reports</p>
        {feedLoading ? (
          <div className="space-y-2">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-8 rounded bg-surface-3 animate-pulse" />
            ))}
          </div>
        ) : items.length === 0 ? (
          <p className="text-xs text-gray-600 text-center py-3">No community reports yet.</p>
        ) : (
          <div>
            {items.map((item) => <FeedRow key={item.ueciid} item={item} />)}
          </div>
        )}
      </div>

      {/* Ask SOVA button */}
      <button
        onClick={() => lookup.mutate("recent threats jailbreak exfiltration")}
        disabled={lookup.isPending}
        className="flex items-center justify-center gap-2 w-full h-8 rounded-lg border border-border text-xs text-gray-400 hover:text-white hover:border-gray-600 disabled:opacity-40 transition-colors"
      >
        {lookup.isPending
          ? <><Loader2 size={12} className="animate-spin" /> Asking SOVA…</>
          : <><Share2 size={12} /> Ask SOVA for recommendations</>}
      </button>
    </div>
  );
}
