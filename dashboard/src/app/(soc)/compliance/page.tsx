"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell, LabelList,
} from "recharts";
import { Shield, Download, ExternalLink, CheckCircle, AlertTriangle, XCircle, RefreshCw } from "lucide-react";
import { Header } from "@/components/layout/header";
import { api, type PostureResponse, type PostureStandard, type ComplianceHistoryResponse } from "@/lib/api";
import { cn, fmtNum } from "@/lib/utils";

// ── Constants ─────────────────────────────────────────────────────────────────

const PERIOD_OPTIONS = [
  { label: "24h",  value: 1  },
  { label: "7d",   value: 7  },
  { label: "30d",  value: 30 },
  { label: "90d",  value: 90 },
];

const STANDARD_META: Record<string, { color: string; description: string; reportPath: string }> = {
  soc2:    { color: "#6366f1", description: "CC6.1–CC9.2 Trust Service Criteria",        reportPath: "/compliance/soc2-bundle"    },
  gdpr:    { color: "#10b981", description: "Art.5 Principles · Art.30 ROPA · Art.35 DPIA", reportPath: "/compliance/smb-report/html" },
  iso27001:{ color: "#f59e0b", description: "ISO/IEC 27001:2022 Annex A Controls",        reportPath: "/compliance/iso27001/html"  },
  hipaa:   { color: "#ef4444", description: "HIPAA Security Rule Safeguards",             reportPath: "/compliance/hipaa/html"     },
  nis2:    { color: "#06b6d4", description: "EU NIS2 Directive Security Measures",        reportPath: "/compliance/nis2/html"      },
};

const ATTEST_COLOR: Record<string, string> = {
  PASS:    "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
  PARTIAL: "text-amber-400  bg-amber-500/10  border-amber-500/20",
  FAIL:    "text-red-400    bg-red-500/10    border-red-500/20",
};

const ATTEST_ICON: Record<string, React.ElementType> = {
  PASS:    CheckCircle,
  PARTIAL: AlertTriangle,
  FAIL:    XCircle,
};

// ── Score Ring ────────────────────────────────────────────────────────────────

function ScoreRing({ score, status }: { score: number; status: string }) {
  const r = 56;
  const circ = 2 * Math.PI * r;
  const fill = circ * (score / 100);
  const gap  = circ - fill;
  const color = score >= 90 ? "#10b981" : score >= 70 ? "#f59e0b" : "#ef4444";
  const label = score >= 90 ? "Compliant" : score >= 70 ? "Partial" : "At Risk";

  return (
    <div className="flex flex-col items-center gap-2">
      <svg width="144" height="144" viewBox="0 0 144 144">
        {/* Track */}
        <circle cx="72" cy="72" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10" />
        {/* Fill — rotated so gap starts at top */}
        <circle
          cx="72" cy="72" r={r} fill="none"
          stroke={color} strokeWidth="10"
          strokeDasharray={`${fill} ${gap}`}
          strokeLinecap="round"
          transform="rotate(-90 72 72)"
          style={{ transition: "stroke-dasharray 0.8s ease" }}
        />
        {/* Label */}
        <text x="72" y="67" textAnchor="middle" fill="white" fontSize="28" fontWeight="700" fontFamily="monospace">
          {score.toFixed(0)}
        </text>
        <text x="72" y="84" textAnchor="middle" fill="rgba(255,255,255,0.4)" fontSize="11">
          / 100
        </text>
      </svg>
      <span className={cn("text-xs font-semibold px-2.5 py-0.5 rounded-full border", ATTEST_COLOR[status] ?? ATTEST_COLOR.PARTIAL)}>
        {label}
      </span>
    </div>
  );
}

// ── Standard Card ─────────────────────────────────────────────────────────────

function StandardCard({ std }: { std: PostureStandard }) {
  const meta  = STANDARD_META[std.short] ?? { color: "#6b7280", description: "", reportPath: "#" };
  const Icon  = ATTEST_ICON[std.attestation] ?? AlertTriangle;
  const passPct    = std.total > 0 ? (std.passed  / std.total * 100) : 0;
  const partialPct = std.total > 0 ? (std.partial / std.total * 100) : 0;
  const failPct    = std.total > 0 ? (std.failed  / std.total * 100) : 0;

  return (
    <div className="rounded-xl border border-border bg-surface-2 p-4 flex flex-col gap-3 hover:border-white/10 transition-colors">
      {/* Header row */}
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="text-sm font-semibold text-white">{std.standard}</div>
          <div className="text-[11px] text-gray-500 mt-0.5">{meta.description}</div>
        </div>
        <span className={cn("flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-full border shrink-0", ATTEST_COLOR[std.attestation])}>
          <Icon size={11} />
          {std.attestation}
        </span>
      </div>

      {/* Score */}
      <div className="flex items-end gap-2">
        <span className="text-3xl font-black tabular-nums" style={{ color: meta.color }}>
          {std.score.toFixed(0)}
          <span className="text-sm font-normal text-gray-500">%</span>
        </span>
        <span className="text-xs text-gray-500 mb-1">compliance score</span>
      </div>

      {/* Stacked bar */}
      <div className="h-2 rounded-full overflow-hidden flex" style={{ background: "rgba(255,255,255,0.06)" }}>
        {passPct    > 0 && <div className="h-full bg-emerald-500 transition-all duration-700" style={{ width: `${passPct}%` }} />}
        {partialPct > 0 && <div className="h-full bg-amber-500  transition-all duration-700" style={{ width: `${partialPct}%` }} />}
        {failPct    > 0 && <div className="h-full bg-red-500    transition-all duration-700" style={{ width: `${failPct}%` }} />}
      </div>

      {/* Counts */}
      <div className="flex items-center gap-3 text-[11px]">
        <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-emerald-500 inline-block" /><span className="text-gray-400">{std.passed} pass</span></span>
        {std.partial > 0 && <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-amber-500  inline-block" /><span className="text-gray-400">{std.partial} partial</span></span>}
        {std.failed  > 0 && <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-red-500    inline-block" /><span className="text-gray-400">{std.failed} fail</span></span>}
        <span className="text-gray-600 ml-auto">{std.total} controls</span>
      </div>
    </div>
  );
}

// ── Tooltip for timeline ──────────────────────────────────────────────────────

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: { value: number }[]; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg px-3 py-2 text-xs border border-border bg-surface-3 shadow-xl">
      <div className="text-gray-400 mb-1">{label}</div>
      <div className="text-white font-semibold">{payload[0].value.toFixed(1)}% overall</div>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function CompliancePage() {
  const [days, setDays] = useState(7);
  const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "https://api.shadow-warden-ai.com";

  const { data: posture, isFetching, dataUpdatedAt } = useQuery({
    queryKey:        ["posture", days],
    queryFn:         () => api.posture(days),
    refetchInterval: 30_000,
    retry:           false,
  });

  const { data: history } = useQuery({
    queryKey:        ["complianceHistory", 24],
    queryFn:         () => api.complianceHistory(24),
    refetchInterval: 60_000,
    retry:           false,
  });

  const p = posture as PostureResponse | undefined;
  const h = history as ComplianceHistoryResponse | undefined;

  const updatedAt = dataUpdatedAt
    ? new Date(dataUpdatedAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : null;

  // Timeline data from history snapshots
  const timeline = (h?.snapshots ?? []).map(s => ({
    t:     new Date(s.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    score: s.overall_score,
  }));

  // If no history yet, synthesise a single point from current posture
  const chartData = timeline.length > 0
    ? timeline
    : p ? [{ t: "Now", score: p.overall_score }] : [];

  // Summary counts across all standards
  const totalControls = p?.standards.reduce((a, s) => a + s.total, 0) ?? 0;
  const totalPass     = p?.standards.reduce((a, s) => a + s.passed, 0) ?? 0;
  const totalPartial  = p?.standards.reduce((a, s) => a + s.partial, 0) ?? 0;
  const totalFail     = p?.standards.reduce((a, s) => a + s.failed, 0) ?? 0;

  // Bar chart data for standard comparison
  const barData = (p?.standards ?? []).map(s => ({
    name:  s.short.toUpperCase(),
    score: s.score,
    color: STANDARD_META[s.short]?.color ?? "#6b7280",
  }));

  return (
    <div className="flex flex-col min-h-screen">
      <Header
        title="Compliance Dashboard"
        subtitle="Real-time SOC 2 · GDPR · ISO 27001 · HIPAA · NIS2 posture"
      />

      <div className="flex-1 p-6 space-y-6">

        {/* Period selector + live indicator */}
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-1 rounded-lg border border-border bg-surface-2 p-1">
            {PERIOD_OPTIONS.map(opt => (
              <button
                key={opt.value}
                onClick={() => setDays(opt.value)}
                className={cn(
                  "px-3 py-1.5 text-xs font-medium rounded-md transition-colors",
                  days === opt.value
                    ? "bg-accent-purple text-white"
                    : "text-gray-400 hover:text-white"
                )}
              >
                {opt.label}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2 text-xs text-gray-500">
            {isFetching
              ? <RefreshCw size={12} className="animate-spin text-accent-purple" />
              : <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse inline-block" />
            }
            {updatedAt ? `Updated ${updatedAt}` : "Loading…"}
            <span className="text-gray-600">· auto-refresh 30s</span>
          </div>
        </div>

        {/* Row 1: Score ring + summary + timeline */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

          {/* Overall score */}
          <div className="rounded-xl border border-border bg-surface-2 p-6 flex flex-col items-center justify-center gap-4">
            <div className="text-xs font-semibold tracking-widest uppercase text-gray-500">Overall Posture</div>
            <ScoreRing
              score={p?.overall_score ?? 0}
              status={p?.overall_status ?? "PARTIAL"}
            />
            <div className="grid grid-cols-3 gap-2 w-full text-center">
              <div>
                <div className="text-lg font-bold text-emerald-400 tabular-nums">{fmtNum(totalPass)}</div>
                <div className="text-[10px] text-gray-500 uppercase tracking-wide">Pass</div>
              </div>
              <div>
                <div className="text-lg font-bold text-amber-400 tabular-nums">{fmtNum(totalPartial)}</div>
                <div className="text-[10px] text-gray-500 uppercase tracking-wide">Partial</div>
              </div>
              <div>
                <div className="text-lg font-bold text-red-400 tabular-nums">{fmtNum(totalFail)}</div>
                <div className="text-[10px] text-gray-500 uppercase tracking-wide">Fail</div>
              </div>
            </div>
            <div className="text-[11px] text-gray-600">{fmtNum(totalControls)} controls across {p?.standards.length ?? 5} standards</div>
          </div>

          {/* Standard comparison bar */}
          <div className="rounded-xl border border-border bg-surface-2 p-5 flex flex-col gap-3">
            <div className="text-xs font-semibold tracking-widest uppercase text-gray-500">Score by Standard</div>
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={barData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" tick={{ fontSize: 10, fill: "#6b7280" }} axisLine={false} tickLine={false} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: "#6b7280" }} axisLine={false} tickLine={false} />
                <Tooltip
                  content={({ active, payload }) =>
                    active && payload?.length ? (
                      <div className="rounded-lg px-3 py-2 text-xs border border-border bg-surface-3 shadow-xl">
                        <span className="text-white font-semibold">{(payload[0].value as number).toFixed(1)}%</span>
                      </div>
                    ) : null
                  }
                />
                <Bar dataKey="score" radius={[4, 4, 0, 0]}>
                  {barData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} fillOpacity={0.85} />
                  ))}
                  <LabelList dataKey="score" position="top" formatter={(v: number) => `${v.toFixed(0)}%`} style={{ fontSize: 10, fill: "#9ca3af" }} />
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* 24h timeline */}
          <div className="rounded-xl border border-border bg-surface-2 p-5 flex flex-col gap-3">
            <div className="text-xs font-semibold tracking-widest uppercase text-gray-500">
              24h Score Timeline
              {h && h.count > 0 && <span className="ml-2 text-gray-600 normal-case tracking-normal">{h.count} snapshots</span>}
            </div>
            {chartData.length > 1 ? (
              <ResponsiveContainer width="100%" height={160}>
                <AreaChart data={chartData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="compGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#6366f1" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#6366f1" stopOpacity={0}   />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="t" tick={{ fontSize: 9, fill: "#6b7280" }} axisLine={false} tickLine={false} interval="preserveStartEnd" />
                  <YAxis domain={[60, 100]} tick={{ fontSize: 9, fill: "#6b7280" }} axisLine={false} tickLine={false} />
                  <Tooltip content={<ChartTooltip />} />
                  <Area type="monotone" dataKey="score" stroke="#6366f1" strokeWidth={2} fill="url(#compGrad)" dot={false} />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex-1 flex flex-col items-center justify-center gap-2 text-center">
                <div className="text-xs text-gray-500">Snapshots accumulate as the dashboard polls.</div>
                <div className="text-[11px] text-gray-600">Current score: <span className="text-white font-semibold">{(p?.overall_score ?? 0).toFixed(1)}%</span></div>
              </div>
            )}
          </div>
        </div>

        {/* Row 2: Standard cards grid */}
        <div>
          <h2 className="text-xs font-semibold tracking-widest uppercase text-gray-500 mb-3">Standards Breakdown</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-3">
            {(p?.standards ?? PLACEHOLDER_STANDARDS).map(std => (
              <StandardCard key={std.short} std={std} />
            ))}
          </div>
        </div>

        {/* Row 3: Evidence actions */}
        <div className="rounded-xl border border-border bg-surface-2 p-5">
          <div className="text-xs font-semibold tracking-widest uppercase text-gray-500 mb-4">Evidence &amp; Reports</div>
          <div className="flex flex-wrap gap-3">
            <a
              href={`${API_URL}/compliance/soc2-bundle?days=${days}`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium text-white border border-accent-purple/40 bg-accent-purple/10 hover:bg-accent-purple/20 transition-colors"
            >
              <Download size={14} />
              Download SOC 2 Bundle
            </a>
            <a
              href={`${API_URL}/compliance/smb-report/html?days=${days}`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium text-emerald-400 border border-emerald-500/30 bg-emerald-500/10 hover:bg-emerald-500/20 transition-colors"
            >
              <ExternalLink size={14} />
              GDPR Art.30 Report
            </a>
            <a
              href={`${API_URL}/compliance/iso27001/html?days=${days}`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium text-amber-400 border border-amber-500/30 bg-amber-500/10 hover:bg-amber-500/20 transition-colors"
            >
              <ExternalLink size={14} />
              ISO 27001 Report
            </a>
            <a
              href={`${API_URL}/compliance/nis2/html?days=${days}`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium text-cyan-400 border border-cyan-500/30 bg-cyan-500/10 hover:bg-cyan-500/20 transition-colors"
            >
              <ExternalLink size={14} />
              NIS2 Report
            </a>
            <a
              href={`${API_URL}/compliance/hipaa/html?days=${days}`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium text-red-400 border border-red-500/30 bg-red-500/10 hover:bg-red-500/20 transition-colors"
            >
              <ExternalLink size={14} />
              HIPAA Safeguards
            </a>
            <a
              href={`${API_URL}/compliance/posture?days=${days}`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium text-gray-400 border border-white/10 bg-white/5 hover:bg-white/10 transition-colors ml-auto"
            >
              <Shield size={14} />
              Raw JSON
            </a>
          </div>

          {/* Audit integrity line */}
          <div className="mt-4 pt-4 border-t border-border flex items-center gap-2 text-xs text-gray-500">
            <CheckCircle size={12} className="text-emerald-400 shrink-0" />
            GDPR note: no prompt or response content is included in any report — only metadata (lengths, counts, timestamps).
          </div>
        </div>

      </div>
    </div>
  );
}

// ── Placeholder data (shown while first fetch loads) ─────────────────────────

const PLACEHOLDER_STANDARDS: PostureStandard[] = [
  { standard: "SOC 2 Type II",          short: "soc2",    passed: 0, partial: 0, failed: 0, total: 0, score: 0, attestation: "PARTIAL" },
  { standard: "GDPR (Art.5+30+35)",      short: "gdpr",    passed: 0, partial: 0, failed: 0, total: 0, score: 0, attestation: "PARTIAL" },
  { standard: "ISO/IEC 27001:2022",      short: "iso27001",passed: 0, partial: 0, failed: 0, total: 0, score: 0, attestation: "PARTIAL" },
  { standard: "HIPAA Security Rule",     short: "hipaa",   passed: 0, partial: 0, failed: 0, total: 0, score: 0, attestation: "PARTIAL" },
  { standard: "EU NIS2 Directive",       short: "nis2",    passed: 0, partial: 0, failed: 0, total: 0, score: 0, attestation: "PARTIAL" },
];
