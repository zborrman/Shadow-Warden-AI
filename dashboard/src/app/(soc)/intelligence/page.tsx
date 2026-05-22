"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  LineChart, Line, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid,
} from "recharts";
import { TrendingUp, Shield, CheckCircle, AlertTriangle, Activity, Brain } from "lucide-react";
import { Header } from "@/components/layout/header";
import { api, type BIUsage, type BIThreats, type BICompliance, type BIPredictive } from "@/lib/api";
import { cn } from "@/lib/utils";

const MOCK_USAGE: BIUsage = {
  tenant_id: "default", period_days: 7, total_requests: 4_287,
  blocked_requests: 312, block_rate_pct: 7.3, avg_latency_ms: 18.4,
  daily_breakdown: {
    "Mon": { total: 580, blocked: 42 }, "Tue": { total: 624, blocked: 55 },
    "Wed": { total: 711, blocked: 61 }, "Thu": { total: 598, blocked: 38 },
    "Fri": { total: 703, blocked: 52 }, "Sat": { total: 490, blocked: 34 },
    "Sun": { total: 581, blocked: 30 },
  },
};

const MOCK_THREATS: BIThreats = {
  tenant_id: "default", period_days: 7, total_flags: 312,
  by_severity: { LOW: 88, MEDIUM: 124, HIGH: 78, CRITICAL: 22 },
  top_threats: [
    { flag: "jailbreak_attempt", count: 98 }, { flag: "prompt_injection", count: 74 },
    { flag: "pii_detected",      count: 67 }, { flag: "secret_leak",      count: 43 },
    { flag: "social_engineering", count: 30 },
  ],
};

const MOCK_COMPLIANCE: BICompliance = {
  tenant_id: "default", overall_score: 0.84,
  standards: [
    { standard: "GDPR",    score: 0.91, attestation: "PASS" },
    { standard: "SOC 2",   score: 0.82, attestation: "PARTIAL" },
    { standard: "ISO 27001", score: 0.79, attestation: "PARTIAL" },
  ],
  incidents_open: 2, training_compliance_pct: 87,
};

const MOCK_PREDICTIVE: BIPredictive = {
  tenant_id: "default", metric: "block_rate",
  current_value: 7.3, predicted_value: 8.1,
  trend_direction: "up", r_squared: 0.87,
};

function ScoreGauge({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const color = pct >= 85 ? "#10b981" : pct >= 70 ? "#f59e0b" : "#ef4444";
  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="80" height="80" viewBox="0 0 80 80">
        <circle cx="40" cy="40" r="32" fill="none" stroke="#1e2a42" strokeWidth="8" />
        <circle cx="40" cy="40" r="32" fill="none" stroke={color} strokeWidth="8"
          strokeDasharray={`${2 * Math.PI * 32 * score} ${2 * Math.PI * 32 * (1 - score)}`}
          strokeLinecap="round" transform="rotate(-90 40 40)" />
        <text x="40" y="45" textAnchor="middle" fill="white" fontSize="16" fontWeight="bold">{pct}%</text>
      </svg>
    </div>
  );
}

function SectionCard({ title, icon: Icon, color, children }: {
  title: string; icon: React.ElementType; color: string; children: React.ReactNode;
}) {
  return (
    <div className="rounded-xl bg-surface-2 border border-border p-5">
      <div className="flex items-center gap-2 mb-4">
        <Icon size={14} className={color} />
        <h2 className="text-sm font-semibold text-white">{title}</h2>
      </div>
      {children}
    </div>
  );
}

export default function IntelligencePage() {
  const [tenantId, setTenantId] = useState("default");
  const [days,     setDays]     = useState(7);

  const { data: usage }      = useQuery<BIUsage>({
    queryKey: ["bi-usage",  tenantId, days],
    queryFn:  () => api.biUsage(tenantId, days),
    placeholderData: MOCK_USAGE,
  });

  const { data: threats }    = useQuery<BIThreats>({
    queryKey: ["bi-threats", tenantId, days],
    queryFn:  () => api.biThreats(tenantId, days),
    placeholderData: MOCK_THREATS,
  });

  const { data: compliance } = useQuery<BICompliance>({
    queryKey: ["bi-compliance", tenantId],
    queryFn:  () => api.biCompliance(tenantId),
    placeholderData: MOCK_COMPLIANCE,
  });

  const { data: predictive } = useQuery<BIPredictive>({
    queryKey: ["bi-predictive", tenantId],
    queryFn:  () => api.biPredictive(tenantId),
    placeholderData: MOCK_PREDICTIVE,
  });

  const u = usage ?? MOCK_USAGE;
  const t = threats ?? MOCK_THREATS;
  const c = compliance ?? MOCK_COMPLIANCE;
  const p = predictive ?? MOCK_PREDICTIVE;

  const usageData = Object.entries(u.daily_breakdown ?? {}).map(([day, v]) => ({
    day, total: v.total, blocked: v.blocked,
  }));

  const threatData = (t.top_threats ?? []).map(x => ({ name: x.flag.replace(/_/g, " "), count: x.count }));

  const attestColor = (a: string) =>
    a === "PASS" ? "text-green-400" : a === "PARTIAL" ? "text-yellow-400" : "text-red-400";

  return (
    <div className="flex flex-col min-h-screen">
      <Header title="Business Intelligence" subtitle="Analytics, trends, compliance scores and predictions" />
      <div className="p-6 space-y-6 animate-fade-in">

        {/* Controls */}
        <div className="flex items-center gap-3 flex-wrap">
          <label className="text-xs text-gray-500">Tenant</label>
          <input
            value={tenantId}
            onChange={e => setTenantId(e.target.value)}
            className="px-3 py-1.5 text-xs rounded-lg bg-surface-3 border border-border text-gray-300 focus:outline-none focus:border-accent-blue w-40"
            placeholder="Tenant ID"
          />
          <label className="text-xs text-gray-500 ml-4">Period</label>
          {[7, 14, 30].map(d => (
            <button
              key={d}
              onClick={() => setDays(d)}
              className={cn("px-3 py-1.5 text-xs rounded-lg border transition-colors",
                days === d
                  ? "bg-accent-blue/20 border-accent-blue text-accent-blue"
                  : "bg-surface-3 border-border text-gray-400 hover:text-white"
              )}
            >{d}d</button>
          ))}
        </div>

        {/* KPI row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: "Total Requests",   value: u.total_requests.toLocaleString(), icon: Activity,      color: "bg-blue-500/15 text-blue-400" },
            { label: "Block Rate",       value: `${u.block_rate_pct.toFixed(1)}%`, icon: Shield,        color: "bg-red-500/15 text-red-400" },
            { label: "Avg Latency",      value: `${u.avg_latency_ms.toFixed(1)}ms`, icon: TrendingUp,   color: "bg-green-500/15 text-green-400" },
            { label: "Compliance Score", value: `${Math.round(c.overall_score * 100)}%`, icon: CheckCircle, color: "bg-purple-500/15 text-purple-400" },
          ].map(kpi => (
            <div key={kpi.label} className="rounded-xl bg-surface-2 border border-border p-4 flex items-start gap-3">
              <div className={cn("w-9 h-9 rounded-lg flex items-center justify-center shrink-0", kpi.color)}>
                <kpi.icon size={16} />
              </div>
              <div>
                <p className="text-[11px] text-gray-500 uppercase tracking-wider">{kpi.label}</p>
                <p className="text-xl font-bold text-white mt-0.5">{kpi.value}</p>
              </div>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Usage trends */}
          <SectionCard title="Usage Trends" icon={Activity} color="text-accent-blue">
            <ResponsiveContainer width="100%" height={180}>
              <LineChart data={usageData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2a42" />
                <XAxis dataKey="day" tick={{ fill: "#6b7280", fontSize: 10 }} axisLine={false} />
                <YAxis tick={{ fill: "#6b7280", fontSize: 10 }} axisLine={false} />
                <Tooltip contentStyle={{ background: "#0d1220", border: "1px solid #1e2a42", borderRadius: 8, fontSize: 11 }} />
                <Line type="monotone" dataKey="total"   stroke="#2563eb" strokeWidth={2} dot={false} name="Total" />
                <Line type="monotone" dataKey="blocked" stroke="#ef4444" strokeWidth={2} dot={false} name="Blocked" />
              </LineChart>
            </ResponsiveContainer>
            <div className="flex items-center gap-4 mt-2 text-[11px] text-gray-500">
              <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-accent-blue inline-block" />Total</span>
              <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-red-500 inline-block" />Blocked</span>
            </div>
          </SectionCard>

          {/* Top threats */}
          <SectionCard title="Top Threat Flags" icon={AlertTriangle} color="text-red-400">
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={threatData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2a42" horizontal={false} />
                <XAxis type="number" tick={{ fill: "#6b7280", fontSize: 10 }} axisLine={false} />
                <YAxis type="category" dataKey="name" tick={{ fill: "#9ca3af", fontSize: 10 }} width={110} axisLine={false} />
                <Tooltip contentStyle={{ background: "#0d1220", border: "1px solid #1e2a42", borderRadius: 8, fontSize: 11 }} />
                <Bar dataKey="count" fill="#ef4444" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </SectionCard>

          {/* Compliance */}
          <SectionCard title="Compliance Score" icon={CheckCircle} color="text-green-400">
            <div className="flex items-center gap-6">
              <ScoreGauge score={c.overall_score} />
              <div className="flex-1 space-y-2">
                {(c.standards ?? []).map(s => (
                  <div key={s.standard} className="flex items-center justify-between">
                    <span className="text-xs text-gray-300">{s.standard}</span>
                    <div className="flex items-center gap-3">
                      <div className="w-24 h-1.5 rounded-full bg-surface-4">
                        <div className="h-1.5 rounded-full bg-accent-blue transition-all"
                             style={{ width: `${Math.round(s.score * 100)}%` }} />
                      </div>
                      <span className={cn("text-[11px] font-medium w-14 text-right", attestColor(s.attestation))}>
                        {s.attestation}
                      </span>
                    </div>
                  </div>
                ))}
                <div className="pt-2 border-t border-border mt-2 flex gap-4 text-xs text-gray-500">
                  <span>Open incidents: <strong className="text-white">{c.incidents_open}</strong></span>
                  <span>Training: <strong className="text-white">{c.training_compliance_pct}%</strong></span>
                </div>
              </div>
            </div>
          </SectionCard>

          {/* Predictive */}
          <SectionCard title="Predictive Analytics" icon={Brain} color="text-accent-purple">
            <div className="space-y-4">
              <div className="flex items-center justify-between p-3 rounded-lg bg-surface-3">
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wider">{p.metric.replace(/_/g, " ")}</p>
                  <p className="text-2xl font-bold text-white mt-1">{p.current_value.toFixed(1)}%</p>
                  <p className="text-[11px] text-gray-500 mt-0.5">current value</p>
                </div>
                <div className="text-right">
                  <p className="text-xs text-gray-500 uppercase tracking-wider">7-day forecast</p>
                  <p className={cn("text-2xl font-bold mt-1",
                    p.trend_direction === "up" ? "text-red-400" : "text-green-400")}>
                    {p.predicted_value.toFixed(1)}%
                  </p>
                  <p className={cn("text-[11px] mt-0.5 flex items-center gap-1 justify-end",
                    p.trend_direction === "up" ? "text-red-400" : "text-green-400")}>
                    <TrendingUp size={10} />
                    {p.trend_direction === "up" ? "Increasing" : "Decreasing"}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2 text-xs text-gray-500">
                <span>Model fit: <strong className="text-white">R²={p.r_squared.toFixed(2)}</strong></span>
                <span className="text-gray-600">·</span>
                <span>OLS linear trend over last 30 samples</span>
              </div>
            </div>
          </SectionCard>
        </div>
      </div>
    </div>
  );
}
