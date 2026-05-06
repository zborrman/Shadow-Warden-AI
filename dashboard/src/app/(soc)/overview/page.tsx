"use client";
import { useQuery } from "@tanstack/react-query";
import { Shield, Activity, Clock, Users, TrendingUp, AlertTriangle, CheckCircle, DollarSign } from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";
import { Header } from "@/components/layout/header";
import { StatCard } from "@/components/ui/stat-card";
import { api } from "@/lib/api";
import { fmtNum, fmtMs, fmtUsd, cn } from "@/lib/utils";

const MOCK_STATS = {
  total_requests: 184_320, blocked_requests: 2_841, high_risk_requests: 1_204,
  allow_requests: 181_479, block_rate_pct: 1.54, avg_processing_ms: 38.2,
  p99_processing_ms: 47.1, uptime_hours: 2_190, active_tenants: 12,
};

const MOCK_TIMELINE = Array.from({ length: 24 }, (_, i) => ({
  hour: `${i}:00`,
  allow: Math.floor(6000 + Math.random() * 2000),
  block: Math.floor(80 + Math.random() * 60),
  high:  Math.floor(30 + Math.random() * 40),
}));

const MOCK_PIE = [
  { name: "Allow",  value: 95.4, color: "#10b981" },
  { name: "Block",  value: 1.54, color: "#ef4444" },
  { name: "High",   value: 1.8,  color: "#f97316" },
  { name: "Medium", value: 1.26, color: "#f59e0b" },
];

const THREAT_TYPES = [
  { name: "Jailbreak Attempt",  count: 1204, pct: 42 },
  { name: "Secret/PII Leak",    count: 786,  pct: 28 },
  { name: "Prompt Injection",   count: 512,  pct: 18 },
  { name: "Social Engineering", count: 201,  pct: 7 },
  { name: "Other",              count: 138,  pct: 5 },
];

export default function OverviewPage() {
  const { data: stats } = useQuery({ queryKey: ["stats"], queryFn: api.stats, placeholderData: MOCK_STATS });
  const { data: roi }   = useQuery({ queryKey: ["roi"],   queryFn: api.roi });
  const s = (stats as typeof MOCK_STATS) ?? MOCK_STATS;

  return (
    <div className="flex flex-col min-h-screen">
      <Header title="SOC Overview" subtitle="Real-time security posture" />

      <div className="p-6 space-y-6 animate-fade-in">
        {/* KPI row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard label="Total Requests"  value={fmtNum(s.total_requests)}   icon={Activity}       accent="blue"   sub="Last 90 days" />
          <StatCard label="Threats Blocked" value={fmtNum(s.blocked_requests)} icon={Shield}         accent="red"    sub={`${s.block_rate_pct}% block rate`} />
          <StatCard label="Avg Latency"     value={fmtMs(s.avg_processing_ms)} icon={Clock}          accent="purple" sub={`P99 ${fmtMs(s.p99_processing_ms)}`} />
          <StatCard label="Active Tenants"  value={s.active_tenants}            icon={Users}          accent="cyan"   sub={`${s.uptime_hours.toLocaleString()}h uptime`} />
        </div>

        {/* Charts row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Timeline */}
          <div className="lg:col-span-2 rounded-xl bg-surface-2 border border-border p-5">
            <p className="text-sm font-semibold text-white mb-4">Request Volume (24h)</p>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={MOCK_TIMELINE}>
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
                <XAxis dataKey="hour" tick={{ fill: "#6b7280", fontSize: 10 }} axisLine={false} tickLine={false} />
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
                <Pie data={MOCK_PIE} dataKey="value" cx="50%" cy="50%" innerRadius={45} outerRadius={65} strokeWidth={0}>
                  {MOCK_PIE.map((e, i) => <Cell key={i} fill={e.color} />)}
                </Pie>
                <Tooltip contentStyle={{ background: "#0d1220", border: "1px solid #1e2a42", borderRadius: 8, fontSize: 12 }}
                  formatter={(v: number) => [`${v}%`]} />
              </PieChart>
            </ResponsiveContainer>
            <div className="mt-3 space-y-1">
              {MOCK_PIE.map(e => (
                <div key={e.name} className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full" style={{ background: e.color }} />
                    <span className="text-gray-400">{e.name}</span>
                  </div>
                  <span className="text-white font-mono">{e.value}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Bottom row: Threats + ROI */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Threat breakdown */}
          <div className="rounded-xl bg-surface-2 border border-border p-5">
            <p className="text-sm font-semibold text-white mb-4">Top Threat Categories</p>
            <div className="space-y-3">
              {THREAT_TYPES.map(t => (
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
                  { label: "Savings Estimated", value: fmtUsd(1_420_000), color: "text-accent-green" },
                  { label: "ROI Multiplier",    value: "47×",             color: "text-accent-cyan"  },
                  { label: "Cost / Request",    value: "$0.0018",         color: "text-gray-300"     },
                  { label: "Industry",          value: "FinTech",         color: "text-gray-300"     },
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
