"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
} from "recharts";
import {
  Shield, AlertTriangle, Users, GitBranch, FileText, CheckCircle,
  XCircle, Activity, ChevronDown,
} from "lucide-react";
import { StatCard } from "@/components/ui/stat-card";
import { api, type HubCommunity, type CommunityIntelReport } from "@/lib/api";

const TENANT_ID = process.env.NEXT_PUBLIC_TENANT_ID ?? "default";

const RISK_COLORS: Record<string, string> = {
  SAFE:     "#10b981",
  LOW:      "#34d399",
  MEDIUM:   "#f59e0b",
  HIGH:     "#ef4444",
  CRITICAL: "#dc2626",
};

const SEVERITY_COLORS: Record<string, string> = {
  NORMAL:   "#6b7280",
  ELEVATED: "#f59e0b",
  CRITICAL: "#ef4444",
};

function pct(v: number) { return `${(v * 100).toFixed(1)}%`; }

function fmtDate(iso: string) {
  try {
    return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
  } catch { return iso.slice(0, 10); }
}

function SeverityBadge({ s }: { s: string }) {
  const color = SEVERITY_COLORS[s] ?? "#6b7280";
  return (
    <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded" style={{ background: color + "22", color }}>
      {s}
    </span>
  );
}

function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse bg-white/5 rounded-lg ${className}`} />;
}

function EmptyState({ label }: { label: string }) {
  return <div className="h-32 flex items-center justify-center text-gray-500 text-sm">{label}</div>;
}

function RiskRing({ score, label }: { score: number; label: string }) {
  const pctInt = Math.round(score * 100);
  const r = 36;
  const circ = 2 * Math.PI * r;
  const dash = circ * (1 - score);
  const color = RISK_COLORS[label] ?? "#6b7280";
  return (
    <div className="flex flex-col items-center gap-2">
      <svg width={96} height={96} viewBox="0 0 96 96">
        <circle cx={48} cy={48} r={r} fill="none" stroke="#ffffff0d" strokeWidth={8} />
        <circle
          cx={48} cy={48} r={r} fill="none" stroke={color} strokeWidth={8}
          strokeDasharray={circ} strokeDashoffset={dash}
          strokeLinecap="round" transform="rotate(-90 48 48)"
          style={{ transition: "stroke-dashoffset 0.6s ease" }}
        />
        <text x={48} y={44} textAnchor="middle" fill={color} fontSize={18} fontWeight={700}>{pctInt}</text>
        <text x={48} y={60} textAnchor="middle" fill="#9ca3af" fontSize={10}>/ 100</text>
      </svg>
      <span className="text-xs font-semibold" style={{ color }}>{label}</span>
    </div>
  );
}

function CommunitySelect({
  communities,
  selected,
  onSelect,
}: {
  communities: HubCommunity[];
  selected: string;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="relative inline-flex items-center">
      <select
        value={selected}
        onChange={e => onSelect(e.target.value)}
        className="appearance-none bg-white/5 border border-border rounded-lg pl-3 pr-8 py-1.5 text-sm text-white cursor-pointer focus:outline-none focus:ring-1 focus:ring-purple-500"
      >
        <option value="">Select community…</option>
        {communities.map(c => (
          <option key={c.community_id} value={c.community_id}>{c.name}</option>
        ))}
      </select>
      <ChevronDown size={13} className="absolute right-2 text-gray-400 pointer-events-none" />
    </div>
  );
}

function IntelPanel({ report }: { report: CommunityIntelReport }) {
  const { risk, transfers, peerings, governance, recent_anomalies, recommendations } = report;

  const radarData = [
    { factor: "Anomaly", value: Math.round(risk.anomaly_score * 100) },
    { factor: "Rejection", value: Math.round(risk.transfer_rejection_rate * 100) },
    { factor: "Gov Gap", value: Math.round(risk.governance_gap * 100) },
  ];

  const transferBar = [
    { name: "Accepted", count: transfers.accepted, fill: "#10b981" },
    { name: "Rejected", count: transfers.rejected, fill: "#ef4444" },
  ];

  const policyBar = Object.entries(peerings.by_policy).map(([name, count]) => ({ name, count }));

  return (
    <div className="space-y-6">
      {/* Stat row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="rounded-xl bg-surface-2 border border-border p-5 flex flex-col items-center justify-center gap-2">
          <RiskRing score={risk.overall} label={risk.label} />
          <p className="text-[10px] text-gray-500 uppercase tracking-wider">Overall Risk</p>
        </div>
        <StatCard
          label="Charter"
          value={governance.charter_active ? `v${governance.charter_version}` : "None"}
          sub={governance.charter_active ? `${pct(governance.acceptance_rate)} accepted` : "No active charter"}
          icon={FileText}
          accent={governance.charter_active ? "green" : "red"}
        />
        <StatCard
          label="Transfers"
          value={transfers.total}
          sub={`${transfers.accepted} accepted / ${transfers.rejected} rejected`}
          icon={GitBranch}
          accent="blue"
        />
        <StatCard
          label="Peerings"
          value={peerings.active}
          sub={`${peerings.total} total, ${peerings.revoked} revoked`}
          icon={Users}
          accent="purple"
        />
      </div>

      {/* Risk factors + Transfer breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="rounded-xl bg-surface-2 border border-border p-5">
          <p className="text-xs text-gray-500 font-medium uppercase tracking-wider mb-4">Risk Factor Breakdown</p>
          <ResponsiveContainer width="100%" height={200}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="#ffffff10" />
              <PolarAngleAxis dataKey="factor" tick={{ fontSize: 11, fill: "#9ca3af" }} />
              <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fontSize: 9, fill: "#6b7280" }} />
              <Radar name="Risk" dataKey="value" stroke={RISK_COLORS[risk.label] ?? "#6b7280"} fill={RISK_COLORS[risk.label] ?? "#6b7280"} fillOpacity={0.25} />
              <Tooltip contentStyle={{ background: "#1a2035", border: "1px solid #2a3350", borderRadius: 8, fontSize: 12 }} formatter={(v: number) => [`${v}%`, "Score"]} />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        <div className="rounded-xl bg-surface-2 border border-border p-5 space-y-4">
          <div>
            <p className="text-xs text-gray-500 font-medium uppercase tracking-wider mb-3">Transfer Outcome</p>
            {transfers.total === 0 ? (
              <EmptyState label="No transfers yet" />
            ) : (
              <ResponsiveContainer width="100%" height={90}>
                <BarChart data={transferBar} layout="vertical">
                  <XAxis type="number" tick={{ fontSize: 10, fill: "#6b7280" }} tickLine={false} axisLine={false} />
                  <YAxis dataKey="name" type="category" tick={{ fontSize: 11, fill: "#9ca3af" }} tickLine={false} axisLine={false} width={60} />
                  <Tooltip contentStyle={{ background: "#1a2035", border: "1px solid #2a3350", borderRadius: 8, fontSize: 12 }} formatter={(v: number) => [v, "Transfers"]} />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {transferBar.map((d, i) => <Cell key={i} fill={d.fill} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
          {policyBar.length > 0 && (
            <div>
              <p className="text-xs text-gray-500 font-medium uppercase tracking-wider mb-3">Peering Policy Mix</p>
              <div className="flex gap-3 flex-wrap">
                {policyBar.map(({ name, count }) => (
                  <div key={name} className="bg-white/5 border border-border rounded-lg px-3 py-2 text-center min-w-[80px]">
                    <div className="text-base font-bold text-white">{count}</div>
                    <div className="text-[10px] text-gray-500 mt-0.5">{name}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Anomaly log */}
      {recent_anomalies.length > 0 && (
        <div className="rounded-xl bg-surface-2 border border-border p-5">
          <p className="text-xs text-gray-500 font-medium uppercase tracking-wider mb-4">Recent Behavioral Anomalies</p>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-gray-500 text-left border-b border-white/5">
                <th className="pb-2 font-medium">Severity</th>
                <th className="pb-2 font-medium">Member</th>
                <th className="pb-2 font-medium">Event</th>
                <th className="pb-2 font-medium text-right">Z-Score</th>
                <th className="pb-2 font-medium text-right">Detected</th>
              </tr>
            </thead>
            <tbody>
              {recent_anomalies.map((a, i) => (
                <tr key={i} className="border-b border-white/5 last:border-0">
                  <td className="py-2"><SeverityBadge s={a.severity} /></td>
                  <td className="py-2 text-gray-300 font-mono">{a.member_id.slice(0, 16)}…</td>
                  <td className="py-2 text-gray-400">{a.event_type}</td>
                  <td className="py-2 text-right font-semibold text-white">{a.z_score.toFixed(2)}</td>
                  <td className="py-2 text-right text-gray-500">{fmtDate(a.detected_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Recommendations */}
      {recommendations.length > 0 && (
        <div className="rounded-xl bg-surface-2 border border-border p-5">
          <p className="text-xs text-gray-500 font-medium uppercase tracking-wider mb-4">Recommendations</p>
          <ul className="space-y-2">
            {recommendations.map((r, i) => (
              <li key={i} className="flex gap-2 text-sm text-gray-300">
                <CheckCircle size={14} className="text-emerald-400 shrink-0 mt-0.5" />
                {r}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default function GovernancePage() {
  const [communityId, setCommunityId] = useState("");

  const { data: communities = [], isLoading: commLoading } = useQuery({
    queryKey: ["hub-list", TENANT_ID],
    queryFn:  () => api.hubList(TENANT_ID),
    retry: false,
  });

  const { data: intel, isLoading: intelLoading, error: intelError } = useQuery({
    queryKey: ["community-intel", communityId],
    queryFn:  () => api.communityIntel(communityId, TENANT_ID),
    enabled:  !!communityId,
    retry: false,
  });

  return (
    <div className="p-6 space-y-6 max-w-[1400px]">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center">
            <Shield size={16} className="text-purple-400" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-white">Community Governance</h1>
            <p className="text-xs text-gray-500">Risk intelligence, charter compliance, and behavioral monitoring</p>
          </div>
        </div>

        {commLoading ? (
          <Skeleton className="h-9 w-48" />
        ) : (
          <CommunitySelect
            communities={communities}
            selected={communityId}
            onSelect={setCommunityId}
          />
        )}
      </div>

      {/* Body */}
      {!communityId ? (
        <div className="rounded-xl bg-surface-2 border border-border p-12 flex flex-col items-center gap-3 text-center">
          <Shield size={32} className="text-purple-400/40" />
          <p className="text-white font-medium">Select a community to view governance data</p>
          <p className="text-sm text-gray-500">Risk score, charter compliance, anomaly log, and recommendations</p>
        </div>
      ) : intelLoading ? (
        <div className="space-y-4">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-32" />)}
          </div>
          <Skeleton className="h-64" />
          <Skeleton className="h-48" />
        </div>
      ) : intelError ? (
        <div className="rounded-xl bg-surface-2 border border-border p-12 flex flex-col items-center gap-3 text-center">
          <XCircle size={28} className="text-red-400" />
          <p className="text-white font-medium">Failed to load governance data</p>
          <p className="text-sm text-gray-500">The community-intel service may be unavailable</p>
        </div>
      ) : intel ? (
        <IntelPanel report={intel} />
      ) : null}
    </div>
  );
}
