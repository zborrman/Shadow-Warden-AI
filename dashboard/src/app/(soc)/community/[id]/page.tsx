"use client";
import { useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import {
  Users, FileText, Shield, Zap, BarChart2, ChevronLeft,
  Globe, CheckCircle, XCircle, AlertTriangle, Download,
} from "lucide-react";
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
} from "recharts";
import { Header } from "@/components/layout/header";
import {
  api,
  type HubCommunity, type HubMember, type HubFile,
  type HubCompliance, type HubEvolutionStats, type HubBundle,
  type MktAgentTrust,
} from "@/lib/api";
import { cn, fmtNum } from "@/lib/utils";

import { useCommunityWebSocket, type WsStatus } from "@/hooks/useCommunityWebSocket";

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDate(iso: string) {
  try {
    const d = new Date(iso);
    const dd = String(d.getDate()).padStart(2, "0");
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const yy = String(d.getFullYear()).slice(-2);
    return `${dd}/${mm}/${yy}`;
  } catch { return iso.slice(0, 10); }
}

function WsIndicator({ status }: { status: WsStatus }) {
  const color = status === "open" ? "bg-emerald-400" : status === "error" ? "bg-red-400" : "bg-gray-500";
  const label = status === "open" ? "Live" : status === "error" ? "WS error" : status === "connecting" ? "Connecting…" : "Offline";
  return (
    <span className="inline-flex items-center gap-1.5 text-[10px] text-gray-400">
      <span className={`w-1.5 h-1.5 rounded-full ${color} ${status === "open" ? "animate-pulse" : ""}`} />
      {label}
    </span>
  );
}

function fmtBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 ** 2).toFixed(1)} MB`;
}

// ── Role / Status badges ──────────────────────────────────────────────────────

const ROLE_COLOR: Record<string, string> = {
  owner:    "bg-purple-500/20 text-purple-300",
  admin:    "bg-blue-500/20 text-blue-300",
  member:   "bg-gray-500/15 text-gray-300",
  observer: "bg-gray-600/15 text-gray-400",
};

function RoleBadge({ role }: { role: string }) {
  return (
    <span className={cn("text-[10px] font-semibold px-1.5 py-0.5 rounded-md", ROLE_COLOR[role] ?? ROLE_COLOR.member)}>
      {role}
    </span>
  );
}

const STATUS_COLOR: Record<string, string> = {
  pending_review: "bg-yellow-500/15 text-yellow-400",
  approved:       "bg-emerald-500/15 text-emerald-400",
  rejected:       "bg-red-500/15 text-red-400",
  imported:       "bg-blue-500/15 text-blue-400",
};

function StatusBadge({ status }: { status: string }) {
  return (
    <span className={cn("text-[10px] font-semibold px-1.5 py-0.5 rounded-md", STATUS_COLOR[status] ?? "bg-gray-500/15 text-gray-400")}>
      {status.replace("_", " ")}
    </span>
  );
}

// ── Compliance score ring ─────────────────────────────────────────────────────

function ScoreRing({ score, status }: { score: number; status: string }) {
  const r = 36, circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;
  const color = score >= 80 ? "#10b981" : score >= 50 ? "#f59e0b" : "#ef4444";
  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="96" height="96" viewBox="0 0 96 96">
        <circle cx="48" cy="48" r={r} fill="none" stroke="#1e2a42" strokeWidth="10" />
        <circle cx="48" cy="48" r={r} fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
          transform="rotate(-90 48 48)" />
        <text x="48" y="48" textAnchor="middle" dominantBaseline="central"
          fill="white" fontSize="18" fontWeight="700">{score}%</text>
      </svg>
      <span className={cn("text-xs font-semibold",
        status === "COMPLIANT" ? "text-emerald-400" : status === "PARTIAL" ? "text-yellow-400" : "text-red-400")}>
        {status}
      </span>
    </div>
  );
}

// ── Tab components ────────────────────────────────────────────────────────────

function OverviewTab({ c }: { c: HubCommunity }) {
  const meta = [
    { label: "Status",      value: c.status },
    { label: "Visibility",  value: c.visibility },
    { label: "Join Policy", value: c.join_policy },
    { label: "Created",     value: fmtDate(c.created_at) },
    { label: "Members",     value: String(c.member_count ?? 0) },
    { label: "Files",       value: String(c.data_stats?.total_files ?? 0) },
    { label: "Total Size",  value: c.data_stats ? `${c.data_stats.total_mb.toFixed(1)} MB` : "—" },
    { label: "Downloads",   value: String(c.data_stats?.total_downloads ?? 0) },
  ];
  return (
    <div className="space-y-4">
      {c.description && (
        <div className="rounded-xl bg-surface-2 border border-border p-4">
          <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Description</p>
          <p className="text-sm text-gray-200">{c.description}</p>
        </div>
      )}
      <div className="rounded-xl bg-surface-2 border border-border p-4">
        <p className="text-xs text-gray-500 uppercase tracking-wider mb-3">Community Details</p>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {meta.map(({ label, value }) => (
            <div key={label} className="bg-surface-3 rounded-lg px-3 py-2">
              <p className="text-[10px] text-gray-500 uppercase tracking-wider">{label}</p>
              <p className="text-sm font-semibold text-white mt-0.5">{value}</p>
            </div>
          ))}
        </div>
      </div>
      <div className="rounded-xl bg-surface-2 border border-border p-4">
        <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Community ID</p>
        <p className="text-xs font-mono text-gray-300 break-all">{c.community_id}</p>
      </div>
    </div>
  );
}

function MembersTab({ communityId }: { communityId: string }) {
  const { data: members = [], isLoading } = useQuery({
    queryKey: ["hub-members", communityId],
    queryFn:  () => api.hubMembers(communityId),
    retry: false,
  });

  if (isLoading) return <div className="text-center py-12 text-gray-500 text-sm">Loading members…</div>;

  const sorted = [...members].sort((a, b) => b.joined_at.localeCompare(a.joined_at));

  const roleCounts = members.reduce<Record<string, number>>((acc, m) => {
    acc[m.role] = (acc[m.role] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {["owner", "admin", "member", "observer"].map(role => (
          <div key={role} className="rounded-xl bg-surface-2 border border-border px-3 py-2 text-center">
            <p className="text-xl font-bold text-white">{roleCounts[role] ?? 0}</p>
            <p className="text-[10px] text-gray-500 mt-0.5 capitalize">{role}s</p>
          </div>
        ))}
      </div>
      <div className="rounded-xl bg-surface-2 border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-surface-3">
              <th className="text-left px-4 py-2.5 text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Member</th>
              <th className="text-left px-4 py-2.5 text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Role</th>
              <th className="text-left px-4 py-2.5 text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Joined</th>
              <th className="text-left px-4 py-2.5 text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Status</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((m: HubMember) => (
              <tr key={m.member_id} className="border-b border-border/50 hover:bg-surface-3 transition-colors">
                <td className="px-4 py-2.5">
                  <p className="text-white text-xs font-medium">{m.display_name || m.tenant_id.slice(0, 12) + "…"}</p>
                  <p className="text-[10px] text-gray-600 font-mono">{m.tenant_id.slice(0, 16)}…</p>
                </td>
                <td className="px-4 py-2.5"><RoleBadge role={m.role} /></td>
                <td className="px-4 py-2.5 text-xs text-gray-400 font-mono">{fmtDate(m.joined_at)}</td>
                <td className="px-4 py-2.5">
                  <span className={cn("text-[10px] font-semibold",
                    m.status === "active" ? "text-emerald-400" : "text-gray-500")}>
                    {m.status}
                  </span>
                </td>
              </tr>
            ))}
            {members.length === 0 && (
              <tr><td colSpan={4} className="text-center py-8 text-gray-600 text-xs">No members found.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function DataTab({ communityId }: { communityId: string }) {
  const { data: files = [], isLoading } = useQuery({
    queryKey: ["hub-files", communityId],
    queryFn:  () => api.hubFiles(communityId),
    retry: false,
  });

  if (isLoading) return <div className="text-center py-12 text-gray-500 text-sm">Loading files…</div>;

  const totalBytes = files.reduce((s, f) => s + f.size_bytes, 0);
  const totalDls   = files.reduce((s, f) => s + f.download_count, 0);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: "Files",       value: String(files.length) },
          { label: "Total Size",  value: fmtBytes(totalBytes)  },
          { label: "Downloads",   value: fmtNum(totalDls)      },
        ].map(({ label, value }) => (
          <div key={label} className="rounded-xl bg-surface-2 border border-border px-3 py-2 text-center">
            <p className="text-xl font-bold text-white">{value}</p>
            <p className="text-[10px] text-gray-500 mt-0.5">{label}</p>
          </div>
        ))}
      </div>
      <div className="rounded-xl bg-surface-2 border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-surface-3">
              <th className="text-left px-4 py-2.5 text-[10px] text-gray-500 uppercase tracking-wider font-semibold">File</th>
              <th className="text-left px-4 py-2.5 text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Size</th>
              <th className="text-left px-4 py-2.5 text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Downloads</th>
              <th className="text-left px-4 py-2.5 text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Uploaded</th>
              <th className="text-left px-4 py-2.5 text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Context</th>
            </tr>
          </thead>
          <tbody>
            {files.map((f: HubFile) => (
              <tr key={f.file_id} className="border-b border-border/50 hover:bg-surface-3 transition-colors">
                <td className="px-4 py-2.5">
                  <p className="text-white text-xs font-medium truncate max-w-[180px]">{f.filename}</p>
                  <p className="text-[10px] text-gray-600">{f.content_type}</p>
                </td>
                <td className="px-4 py-2.5 text-xs text-gray-400 font-mono">{fmtBytes(f.size_bytes)}</td>
                <td className="px-4 py-2.5 text-xs text-gray-400 flex items-center gap-1">
                  <Download size={10} /> {f.download_count}
                </td>
                <td className="px-4 py-2.5 text-xs text-gray-400">{fmtDate(f.uploaded_at)}</td>
                <td className="px-4 py-2.5 text-xs text-gray-400 max-w-[160px] truncate">{f.context || "—"}</td>
              </tr>
            ))}
            {files.length === 0 && (
              <tr><td colSpan={5} className="text-center py-8 text-gray-600 text-xs">No files uploaded yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ComplianceTab({ communityId }: { communityId: string }) {
  const { data: comp, isLoading } = useQuery({
    queryKey: ["hub-compliance", communityId],
    queryFn:  () => api.hubCompliance(communityId),
    retry: false,
  });

  if (isLoading) return <div className="text-center py-12 text-gray-500 text-sm">Loading compliance…</div>;
  if (!comp) return <div className="text-center py-12 text-gray-600 text-sm">Compliance data unavailable.</div>;

  const statusIcon = (s: string) => {
    if (s === "PASS")   return <CheckCircle size={13} className="text-emerald-400" />;
    if (s === "WARN")   return <AlertTriangle size={13} className="text-yellow-400" />;
    return <XCircle size={13} className="text-red-400" />;
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row gap-6 rounded-xl bg-surface-2 border border-border p-5">
        <div className="shrink-0 flex items-center justify-center">
          <ScoreRing score={Math.round(comp.score)} status={comp.status} />
        </div>
        <div className="flex-1 space-y-1.5">
          <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Control Status</p>
          {comp.controls.slice(0, 8).map(ctrl => (
            <div key={ctrl.control} className="flex items-center gap-2">
              {statusIcon(ctrl.status)}
              <span className="text-xs text-gray-300 flex-1">{ctrl.control}</span>
              <span className="text-[10px] text-gray-500 truncate max-w-[200px]">{ctrl.detail}</span>
            </div>
          ))}
        </div>
      </div>
      {comp.gaps.length > 0 && (
        <div className="rounded-xl bg-surface-2 border border-red-500/20 p-4">
          <p className="text-xs font-semibold text-red-400 mb-3 flex items-center gap-1.5">
            <AlertTriangle size={12} /> {comp.gaps.length} Compliance Gap{comp.gaps.length !== 1 ? "s" : ""}
          </p>
          <div className="space-y-2">
            {comp.gaps.map((g, i) => (
              <div key={i} className="flex gap-2 text-xs">
                <span className="text-red-400 font-mono shrink-0">{g.control}</span>
                <span className="text-gray-400">{g.detail}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      <p className="text-[10px] text-gray-600 text-right">Generated: {fmtDate(comp.generated_at)}</p>
    </div>
  );
}

function EvolutionTab({ communityId }: { communityId: string }) {
  const { data: stats } = useQuery({
    queryKey: ["hub-evo-stats", communityId],
    queryFn:  () => api.hubEvolutionStats(communityId),
    retry: false,
  });
  const { data: bundles = [], isLoading } = useQuery({
    queryKey: ["hub-bundles", communityId],
    queryFn:  () => api.hubBundles(communityId),
    retry: false,
  });

  const barData = stats ? [
    { name: "Total",    value: stats.total },
    { name: "Approved", value: stats.approved },
    { name: "Pending",  value: stats.pending },
    { name: "Rejected", value: stats.rejected },
    { name: "Imports",  value: stats.total_imports },
  ] : [];

  return (
    <div className="space-y-4">
      {stats && (
        <div className="rounded-xl bg-surface-2 border border-border p-4">
          <p className="text-xs text-gray-500 uppercase tracking-wider mb-3">Rule Bundle Stats</p>
          <ResponsiveContainer width="100%" height={130}>
            <BarChart data={barData} barSize={28}>
              <XAxis dataKey="name" tick={{ fill: "#6b7280", fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: "#6b7280", fontSize: 10 }} axisLine={false} tickLine={false} width={28} />
              <Tooltip
                contentStyle={{ background: "#0d1220", border: "1px solid #1e2a42", borderRadius: 8, fontSize: 12 }}
                cursor={{ fill: "rgba(255,255,255,0.04)" }}
              />
              <Bar dataKey="value" fill="#BF5AF2" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
      <div className="rounded-xl bg-surface-2 border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-surface-3">
              <th className="text-left px-4 py-2.5 text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Rule Type</th>
              <th className="text-left px-4 py-2.5 text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Status</th>
              <th className="text-right px-4 py-2.5 text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Threat Score</th>
              <th className="text-left px-4 py-2.5 text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Published</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr><td colSpan={4} className="text-center py-8 text-gray-500 text-xs">Loading…</td></tr>
            ) : bundles.length === 0 ? (
              <tr><td colSpan={4} className="text-center py-8 text-gray-600 text-xs">No bundles published yet.</td></tr>
            ) : bundles.map((b: HubBundle) => (
              <tr key={b.bundle_id} className="border-b border-border/50 hover:bg-surface-3 transition-colors">
                <td className="px-4 py-2.5">
                  <p className="text-white text-xs font-medium">{b.rule_type}</p>
                  <p className="text-[10px] text-gray-600 font-mono">{b.bundle_id.slice(0, 12)}…</p>
                </td>
                <td className="px-4 py-2.5"><StatusBadge status={b.status} /></td>
                <td className="px-4 py-2.5 text-right">
                  <span className={cn("text-xs font-mono",
                    b.threat_score >= 0.7 ? "text-red-400" : b.threat_score >= 0.4 ? "text-yellow-400" : "text-emerald-400")}>
                    {(b.threat_score * 100).toFixed(0)}%
                  </span>
                </td>
                <td className="px-4 py-2.5 text-xs text-gray-400">{fmtDate(b.published_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function TopTrustedAgentsWidget({ communityId }: { communityId: string }) {
  const { data: agentList, isLoading } = useQuery({
    queryKey: ["mkt-agent-list", communityId],
    queryFn:  () => api.mktAgentList({ community_id: communityId, limit: "10" }),
    retry: false,
  });

  const [trustScores, setTrustScores] = useState<MktAgentTrust[]>([]);

  // Fetch trust for first 5 agents once the list is available
  useQuery({
    queryKey: ["mkt-trust-batch", communityId, agentList?.map(a => a.agent_id).join(",")],
    queryFn: async () => {
      if (!agentList || agentList.length === 0) return [];
      const top5 = agentList.slice(0, 5);
      const results = await Promise.all(
        top5.map(a => api.mktAgentTrust(a.agent_id).catch(() => null))
      );
      const valid = results.filter((r): r is MktAgentTrust => r !== null);
      valid.sort((a, b) => b.trust_score - a.trust_score);
      setTrustScores(valid);
      return valid;
    },
    enabled: !!agentList && agentList.length > 0,
    retry: false,
  });

  if (isLoading) {
    return (
      <div className="rounded-xl bg-surface-2 border border-border p-4 animate-pulse">
        <div className="h-3 w-32 bg-surface-4 rounded mb-3" />
        <div className="space-y-2">
          {[1,2,3].map(i => <div key={i} className="h-8 bg-surface-4 rounded" />)}
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-xl bg-surface-2 border border-border p-4">
      <p className="text-xs text-gray-500 uppercase tracking-wider mb-3 flex items-center gap-1.5">
        <Zap size={11} className="text-yellow-400" /> Top Trusted Agents
      </p>
      {trustScores.length === 0 ? (
        <p className="text-xs text-gray-600">No marketplace agents in this community yet.</p>
      ) : (
        <div className="space-y-2">
          {trustScores.map((agent, idx) => (
            <div key={agent.agent_id} className="flex items-center gap-3">
              <span className="text-[10px] font-mono text-gray-600 w-4">{idx + 1}</span>
              <div className="flex-1 min-w-0">
                <p className="text-xs text-gray-300 font-mono truncate">
                  {agent.agent_id.slice(0, 22)}…
                </p>
              </div>
              {agent.sybil_flag && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 font-semibold">
                  Sybil
                </span>
              )}
              <div className="flex items-center gap-1.5 shrink-0">
                <div className="w-16 h-1.5 rounded-full bg-surface-4 overflow-hidden">
                  <div
                    className={cn(
                      "h-full rounded-full",
                      agent.trust_score >= 0.7 ? "bg-emerald-400" :
                      agent.trust_score >= 0.4 ? "bg-yellow-400" : "bg-red-400"
                    )}
                    style={{ width: `${agent.trust_score * 100}%` }}
                  />
                </div>
                <span className={cn(
                  "text-[11px] font-mono font-semibold",
                  agent.trust_score >= 0.7 ? "text-emerald-400" :
                  agent.trust_score >= 0.4 ? "text-yellow-400" : "text-red-400"
                )}>
                  {(agent.trust_score * 100).toFixed(0)}%
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function AnalyticsTab({ communityId }: { communityId: string }) {
  const { data: supplier } = useQuery({
    queryKey: ["supplier-report", communityId],
    queryFn:  () => api.supplierReport(communityId),
    retry: false,
  });
  const { data: training } = useQuery({
    queryKey: ["training-compliance", communityId],
    queryFn:  () => api.trainingCompliance(communityId),
    retry: false,
  });
  const { data: prompts } = useQuery({
    queryKey: ["prompts", communityId],
    queryFn:  () => api.prompts(communityId),
    retry: false,
  });

  const radarData = supplier ? Object.entries(supplier.by_risk_label).map(([k, v]) => ({
    subject: k, count: v,
  })) : [];

  return (
    <div className="space-y-4">
      {/* Top Trusted Agents */}
      <TopTrustedAgentsWidget communityId={communityId} />

      {/* Training compliance */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="rounded-xl bg-surface-2 border border-border p-4">
          <p className="text-xs text-gray-500 uppercase tracking-wider mb-3 flex items-center gap-1.5">
            <Shield size={11} /> Training Compliance
          </p>
          {training ? (
            <div className="space-y-2">
              <div className="flex items-end gap-2">
                <span className="text-3xl font-bold text-white">{training.compliant_pct.toFixed(0)}%</span>
                <span className="text-xs text-gray-400 mb-1">compliant</span>
              </div>
              <div className="h-2 rounded-full bg-surface-4 overflow-hidden">
                <div className="h-full rounded-full bg-accent-green transition-all"
                  style={{ width: `${training.compliant_pct}%` }} />
              </div>
              <div className="flex gap-4 text-[10px] text-gray-500 mt-1">
                <span>{training.total_employees} employees</span>
                <span className="text-yellow-400">{training.expiring_count} expiring</span>
                <span className="text-red-400">{training.overdue_count} overdue</span>
              </div>
            </div>
          ) : (
            <p className="text-xs text-gray-600">No training data available.</p>
          )}
        </div>

        {/* Prompt library */}
        <div className="rounded-xl bg-surface-2 border border-border p-4">
          <p className="text-xs text-gray-500 uppercase tracking-wider mb-3 flex items-center gap-1.5">
            <FileText size={11} /> Prompt Library
          </p>
          {prompts ? (
            <div className="space-y-1.5">
              <p className="text-3xl font-bold text-white">{prompts.prompts.length}</p>
              <p className="text-xs text-gray-400">shared prompts</p>
              <div className="space-y-1 mt-2">
                {prompts.prompts.slice(0, 4).map(p => (
                  <div key={p.prompt_id} className="flex items-center justify-between text-xs">
                    <span className="text-gray-300 truncate max-w-[140px]">{p.title}</span>
                    <span className="text-gray-600 ml-2 shrink-0">{p.use_count} uses</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <p className="text-xs text-gray-600">No prompt library data.</p>
          )}
        </div>
      </div>

      {/* Supplier risk radar */}
      <div className="rounded-xl bg-surface-2 border border-border p-4">
        <p className="text-xs text-gray-500 uppercase tracking-wider mb-3 flex items-center gap-1.5">
          <BarChart2 size={11} /> Supplier Risk Distribution
        </p>
        {supplier && radarData.length > 0 ? (
          <div className="flex flex-col sm:flex-row gap-4 items-center">
            <ResponsiveContainer width={180} height={160}>
              <RadarChart data={radarData}>
                <PolarGrid stroke="#1e2a42" />
                <PolarAngleAxis dataKey="subject" tick={{ fill: "#6b7280", fontSize: 10 }} />
                <PolarRadiusAxis tick={false} axisLine={false} />
                <Radar dataKey="count" stroke="#BF5AF2" fill="#BF5AF2" fillOpacity={0.25} />
              </RadarChart>
            </ResponsiveContainer>
            <div className="flex-1 space-y-1.5">
              {Object.entries(supplier.by_risk_label).map(([label, count]) => (
                <div key={label} className="flex items-center justify-between text-xs">
                  <span className={cn(
                    label === "CRITICAL" ? "text-red-400" : label === "HIGH" ? "text-orange-400" :
                    label === "MEDIUM" ? "text-yellow-400" : "text-emerald-400"
                  )}>{label}</span>
                  <span className="text-gray-300 font-mono">{count as number}</span>
                </div>
              ))}
              <p className="text-[10px] text-gray-600 pt-1">{supplier.total} assessments total</p>
            </div>
          </div>
        ) : (
          <p className="text-xs text-gray-600">No supplier risk data for this community.</p>
        )}
      </div>
    </div>
  );
}

// ── Tab definition ────────────────────────────────────────────────────────────

const TABS = [
  { id: "overview",    label: "Overview",    icon: Globe     },
  { id: "members",     label: "Members",     icon: Users     },
  { id: "data",        label: "Data",        icon: FileText  },
  { id: "compliance",  label: "Compliance",  icon: Shield    },
  { id: "evolution",   label: "Evolution",   icon: Zap       },
  { id: "analytics",   label: "Analytics",   icon: BarChart2 },
] as const;
type TabId = typeof TABS[number]["id"];

// ── Main page ─────────────────────────────────────────────────────────────────

export default function CommunityDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router  = useRouter();
  const [tab, setTab] = useState<TabId>("overview");

  const { liveData, wsStatus } = useCommunityWebSocket(id ?? "");

  const { data: community, isLoading, isError } = useQuery({
    queryKey: ["hub-community", id],
    queryFn:  () => api.hubGet(id),
    enabled:  !!id,
    retry: false,
  });

  if (isLoading) {
    return (
      <div className="flex flex-col min-h-screen">
        <Header title="Community" subtitle="Loading…" />
        <div className="flex items-center justify-center flex-1 text-gray-500 text-sm">Loading…</div>
      </div>
    );
  }

  if (isError || !community) {
    return (
      <div className="flex flex-col min-h-screen">
        <Header title="Community" subtitle="Not found" />
        <div className="flex flex-col items-center justify-center flex-1 gap-3">
          <p className="text-gray-500 text-sm">Community not found or unavailable.</p>
          <button onClick={() => router.push("/community")}
            className="text-xs text-accent-purple hover:underline flex items-center gap-1">
            <ChevronLeft size={12} /> Back to list
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col min-h-screen">
      <Header
        title={community.name}
        subtitle={`${community.visibility} · ${community.join_policy} · ${community.status}`}
      />

      {/* WS live banner */}
      <div className="px-6 py-1.5 border-b border-border bg-surface-1/40 flex items-center gap-3 text-[11px] text-gray-500">
        <WsIndicator status={wsStatus} />
        {liveData && (
          <>
            <span className="text-gray-600">·</span>
            <span>{liveData.member_count} members</span>
            {liveData.compliance_score !== undefined && (
              <><span className="text-gray-600">·</span><span>Compliance: {Math.round(liveData.compliance_score * 100)}%</span></>
            )}
            {liveData.last_activity && (
              <><span className="text-gray-600">·</span><span>Last active: {fmtDate(liveData.last_activity as string)}</span></>
            )}
          </>
        )}
      </div>

      <div className="p-6 space-y-5 animate-fade-in">
        {/* Back + Open in Hub */}
        <div className="flex items-center justify-between">
          <button onClick={() => router.push("/community")}
            className="flex items-center gap-1 text-xs text-gray-400 hover:text-white transition-colors">
            <ChevronLeft size={12} /> Communities
          </button>
          <a
            href={`https://app.shadow-warden-ai.com/community-hub/hub/${id}`}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-accent-purple/15 text-accent-purple hover:bg-accent-purple/25 transition-colors font-medium"
          >
            Open in Hub ↗
          </a>
        </div>

        {/* Tab bar */}
        <div className="flex gap-1 bg-surface-3 rounded-xl p-1 w-fit">
          {TABS.map(t => {
            const Icon = t.icon;
            const active = tab === t.id;
            return (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={cn(
                  "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-medium transition-all duration-150",
                  active ? "bg-surface-2 text-white shadow" : "text-gray-500 hover:text-gray-300",
                )}
              >
                <Icon size={11} />
                {t.label}
              </button>
            );
          })}
        </div>

        {/* Tab content */}
        <div className="min-h-[300px]">
          {tab === "overview"   && <OverviewTab c={community} />}
          {tab === "members"    && <MembersTab  communityId={id} />}
          {tab === "data"       && <DataTab     communityId={id} />}
          {tab === "compliance" && <ComplianceTab communityId={id} />}
          {tab === "evolution"  && <EvolutionTab  communityId={id} />}
          {tab === "analytics"  && <AnalyticsTab  communityId={id} />}
        </div>
      </div>
    </div>
  );
}
