"use client";
import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { Users, Globe, Lock, FolderOpen, ChevronRight, Activity } from "lucide-react";
import { Header } from "@/components/layout/header";
import { StatCard } from "@/components/ui/stat-card";
import { api, type HubCommunity } from "@/lib/api";
import { cn } from "@/lib/utils";

const TENANT_ID = process.env.NEXT_PUBLIC_TENANT_ID ?? "default";

function fmtDate(iso: string) {
  try { return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }); }
  catch { return iso.slice(0, 10); }
}

function VisBadge({ vis }: { vis: string }) {
  const isPublic = vis === "public";
  return (
    <span className={cn(
      "inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded-md",
      isPublic ? "bg-emerald-500/15 text-emerald-400" : "bg-gray-500/15 text-gray-400",
    )}>
      {isPublic ? <Globe size={9} /> : <Lock size={9} />}
      {vis}
    </span>
  );
}

function StatusDot({ status }: { status: string }) {
  return (
    <span className={cn(
      "w-1.5 h-1.5 rounded-full inline-block",
      status === "active" ? "bg-emerald-400" : "bg-gray-500",
    )} />
  );
}

export default function CommunityListPage() {
  const router = useRouter();

  const { data: stats } = useQuery({
    queryKey: ["hub-stats"],
    queryFn: api.hubStats,
    retry: false,
  });

  const { data: communities = [], isLoading } = useQuery({
    queryKey: ["hub-list", TENANT_ID],
    queryFn: () => api.hubList(TENANT_ID),
    retry: false,
  });

  return (
    <div className="flex flex-col min-h-screen">
      <Header title="Community Hub" subtitle="Manage and monitor shared AI communities" />

      <div className="p-6 space-y-6 animate-fade-in">
        {/* KPI row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard label="Total"     value={String(stats?.total     ?? 0)} icon={Users}    accent="purple" sub="communities" />
          <StatCard label="Active"    value={String(stats?.active    ?? 0)} icon={Activity} accent="green"  sub="running" />
          <StatCard label="Public"    value={String(stats?.public    ?? 0)} icon={Globe}    accent="blue"   sub="discoverable" />
          <StatCard label="Suspended" value={String(stats?.suspended ?? 0)} icon={Lock}     accent="red"    sub="paused" />
        </div>

        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">Communities</h2>
          {!isLoading && (
            <span className="text-xs text-gray-500">{communities.length} total</span>
          )}
        </div>

        {isLoading ? (
          <div className="text-center py-16 text-gray-500 text-sm">Loading communities…</div>
        ) : communities.length === 0 ? (
          <div className="flex flex-col items-center py-20 gap-3 text-gray-600">
            <FolderOpen size={40} />
            <p className="text-sm">No communities found for this tenant.</p>
          </div>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
            {communities.map((c: HubCommunity) => (
              <button
                key={c.community_id}
                onClick={() => router.push(`/community/${c.community_id}`)}
                className="rounded-xl bg-surface-2 border border-border p-4 text-left group hover:border-accent-purple/40 transition-all duration-150 focus:outline-none"
              >
                {/* Top row */}
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <StatusDot status={c.status} />
                      <p className="text-sm font-semibold text-white truncate">{c.name}</p>
                    </div>
                    <p className="text-[10px] text-gray-600 font-mono mt-0.5">{c.community_id.slice(0, 14)}…</p>
                  </div>
                  <VisBadge vis={c.visibility} />
                </div>

                {/* Description */}
                {c.description && (
                  <p className="text-xs text-gray-400 line-clamp-2 mb-3">{c.description}</p>
                )}

                {/* Meta */}
                <div className="flex items-center gap-3 text-[10px] text-gray-500 border-t border-border pt-2 mt-auto">
                  <span className="flex items-center gap-1">
                    <Users size={10} /> {c.member_count ?? 0}
                  </span>
                  <span>{c.join_policy}</span>
                  {c.data_stats && (
                    <span>{c.data_stats.total_files} files</span>
                  )}
                  <span className="ml-auto flex items-center gap-1 text-accent-purple group-hover:opacity-100 opacity-60 transition-opacity">
                    {fmtDate(c.created_at)} <ChevronRight size={10} />
                  </span>
                </div>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
