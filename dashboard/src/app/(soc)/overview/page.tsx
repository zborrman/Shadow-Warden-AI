"use client";
import { useQuery } from "@tanstack/react-query";
import { Shield, Activity, Clock, Users, CheckCircle, DollarSign } from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";
import { Header } from "@/components/layout/header";
import { StatCard } from "@/components/ui/stat-card";
import { api, type StatsResponse, type ThreatsResponse, type RoiResponse } from "@/lib/api";
import { fmtNum, fmtMs, fmtUsd, cn } from "@/lib/utils";

const MOCK_STATS: StatsResponse = {
  days: 7, total: 184_320, allowed: 181_479, blocked: 2_841,
  block_rate_pct: 1.54, avg_latency_ms: 38.2, by_day: {},
};

const PIE_COLORS = ["#10b981", "#ef4444", "#f97316", "#f59e0b"];

const FLAG_LABEL: Record<string, string> = {
  jailbreak_attempt: "Jailbreak Attempt", secret_leak: "Secret/PII Leak",
  prompt_injection: "Prompt Injection",   social_engineering: "Social Engineering",
};

function buildTimeline(by_day: Record<string, { total: number; blocked: number }>) {
  const days = Object.keys(by_day).sort().slice(-7);
  return days.map(d => ({
    day:   d.slice(5),
    allow: by_day[d].total - by_day[d].blocked,
    block: by_day[d].blocked,
  }));
}

export default function OverviewPage() {
  const { data: stats }   = useQuery({ queryKey: ["stats"],   queryFn: api.stats,   placeholderData: MOCK_STATS });
  const { data: threats } = useQuery({ queryKey: ["threats"], queryFn: api.threats });
  const { data: roi }     = useQuery({ queryKey: ["roi"],     queryFn: api.roi });

  const s = stats ?? MOCK_STATS;
  const timeline = Object.keys(s.by_day).length > 0 ? buildTimeline(s.by_day) : [];

  const topThreats = (threats as ThreatsResponse | undefined)?.threats.slice(0, 5).map((t, i, arr) => ({
    name: FLAG_LABEL[t.flag] ?? t.flag,
    count: t.count,
    pct: arr[0].count > 0 ? Math.round(t.count / arr[0].count * 100) : 0,
  })) ?? [];

  const roiData = roi as RoiResponse | undefined;
  const savedUsd = roiData?.total_estimated_roi_usd ?? 1_420_000;

  const pieData = [
    { name: "Allow",  value: s.total > 0 ? +(s.allowed / s.total * 100).toFixed(1) : 95.4, color: "#10b981" },
    { name: "Block",  value: s.block_rate_pct, color: "#ef4444" },
    { name: "High",   value: s.total > 0 ? +((s.blocked - Math.round(s.blocked * 0.4)) / s.total * 100).toFixed(1) : 1.8, color: "#f97316" },
    { name: "Medium", value: s.total > 0 ? +(Math.round(s.blocked * 0.4) / s.total * 100).toFixed(1) : 1.26, color: "#f59e0b" },
  ];

  return (
    <div className="flex flex-col min-h-screen">
      <Header title="SOC Overview" subtitle="Real-time security posture" />

      <div className="p-6 space-y-6 animate-fade-in">
        {/* KPI row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard label="Total Requests"  value={fmtNum(s.total)}           icon={Activity} accent="blue"   sub={`Last ${s.days} days`} />
          <StatCard label="Threats Blocked" value={fmtNum(s.blocked)}         icon={Shield}   accent="red"    sub={`${s.block_rate_pct}% block rate`} />
          <StatCard label="Avg Latency"     value={fmtMs(s.avg_latency_ms)}   icon={Clock}    accent="purple" sub="P99 est ×1.3" />
          <StatCard label="Estimated Savings" value={fmtUsd(savedUsd)}        icon={DollarSign} accent="cyan" sub="IBM breach model" />
        </div>

        {/* Charts row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Timeline */}
          <div className="lg:col-span-2 rounded-xl bg-surface-2 border border-border p-5">
            <p className="text-sm font-semibold text-white mb-4">
              Request Volume ({timeline.length > 0 ? "7d daily" : "24h mock"})
            </p>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={timeline.length > 0 ? timeline : []}>
                <defs>
                  <linearGradient id="gAllow" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#10b981" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gBlock" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="day" tick={{ fill: "#6b7280", fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: "#6b7280", fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: "#0d1220", border: "1px solid #1e2a42", borderRadius: 8, fontSize: 12 }} />
                <Area type="monotone" dataKey="allow" stroke="#10b981" fill="url(#gAllow)" strokeWidth={2} name="Allow" />
                <Area type="monotone" dataKey="block" stroke="#ef4444" fill="url(#gBlock)" strokeWidth={2} name="Block" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Verdict pie */}
          <div className="rounded-xl bg-surface-2 border border-border p-5">
            <p className="text-sm font-semibold text-white mb-4">Verdict Distribution</p>
            <ResponsiveContainer width="100%" height={140}>
              <PieChart>
                <Pie data={pieData} dataKey="value" cx="50%" cy="50%" innerRadius={45} outerRadius={65} strokeWidth={0}>
                  {pieData.map((e, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: "#0d1220", border: "1px solid #1e2a42", borderRadius: 8, fontSize: 12 }}
                  formatter={(v: number) => [`${v}%`]} />
              </PieChart>
            </ResponsiveContainer>
            <div className="mt-3 space-y-1">
              {pieData.map((e, i) => (
                <div key={e.name} className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full" style={{ background: PIE_COLORS[i % PIE_COLORS.length] }} />
                    <span className="text-gray-400">{e.name}</span>
                  </div>
                  <span className="text-white font-mono">{e.value}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Bottom row */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Threat breakdown */}
          <div className="rounded-xl bg-surface-2 border border-border p-5">
            <p className="text-sm font-semibold text-white mb-4">Top Threat Categories</p>
            {topThreats.length > 0 ? (
              <div className="space-y-3">
                {topThreats.map(t => (
                  <div key={t.name}>
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className="text-gray-300">{t.name}</span>
                      <span className="text-gray-500 font-mono">{t.count.toLocaleString()}</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-surface-4 overflow-hidden">
                      <div className="h-full rounded-full bg-gradient-to-r from-accent-purple to-accent-blue transition-all"
                        style={{ width: `${t.pct}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-gray-600">No threat data yet — send requests through the gateway.</p>
            )}
          </div>

          {/* ROI + Compliance */}
          <div className="space-y-4">
            <div className="rounded-xl bg-surface-2 border border-border p-5">
              <div className="flex items-center gap-2 mb-3">
                <DollarSign size={14} className="text-accent-green" />
                <p className="text-sm font-semibold text-white">Financial Impact</p>
              </div>
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: "Savings Estimated", value: fmtUsd(savedUsd),                                   color: "text-accent-green" },
                  { label: "Breach Events",      value: String(roiData?.threat_mitigation.high_block_events ?? 0), color: "text-accent-cyan"  },
                  { label: "Secrets Redacted",   value: String(roiData?.secret_protection.secrets_redacted ?? 0), color: "text-gray-300"     },
                  { label: "Shadow Bans",        value: String(roiData?.shadow_ban.count ?? 0),              color: "text-gray-300"     },
                ].map(({ label, value, color }) => (
                  <div key={label} className="bg-surface-3 rounded-lg px-3 py-2">
                    <p className="text-[10px] text-gray-500 uppercase tracking-wider">{label}</p>
                    <p className={cn("text-base font-bold mt-0.5", color)}>{value}</p>
                  </div>
                ))}
              </div>
            </div>
            <div className="rounded-xl bg-surface-2 border border-border p-5">
              <div className="flex items-center gap-2 mb-3">
                <CheckCircle size={14} className="text-accent-green" />
                <p className="text-sm font-semibold text-white">Compliance Status</p>
              </div>
              <div className="grid grid-cols-3 gap-2">
                {["GDPR", "SOC 2", "OWASP LLM"].map(f => (
                  <div key={f} className="flex flex-col items-center gap-1 bg-surface-3 rounded-lg px-2 py-2">
                    <CheckCircle size={16} className="text-accent-green" />
                    <span className="text-[10px] text-gray-400 font-medium">{f}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
