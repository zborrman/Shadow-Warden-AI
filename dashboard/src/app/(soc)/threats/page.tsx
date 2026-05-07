"use client";
import { useQuery } from "@tanstack/react-query";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, RadarChart, PolarGrid, PolarAngleAxis, Radar, Cell } from "recharts";
import { Header } from "@/components/layout/header";
import { AlertTriangle, TrendingUp } from "lucide-react";
import { api, type ThreatsResponse } from "@/lib/api";

const FLAG_LABEL: Record<string, string> = {
  jailbreak_attempt:  "Jailbreak",
  secret_leak:        "Secret Leak",
  prompt_injection:   "Prompt Injection",
  social_engineering: "Social Engineering",
  data_poisoning:     "Data Poisoning",
  obfuscation:        "Obfuscation",
  shadow_ban:         "Shadow Ban",
};

const BAR_COLORS = ["#7c3aed", "#2563eb", "#06b6d4", "#10b981", "#f59e0b", "#ef4444"];

const RADAR_AXES = ["Jailbreak", "Obfuscation", "Secret Exfil", "SE / Phishing", "Data Poisoning", "Prompt Injection"];

export default function ThreatsPage() {
  const { data } = useQuery({ queryKey: ["threats"], queryFn: api.threats });
  const threats = (data as ThreatsResponse | undefined)?.threats ?? [];

  const barData = threats.map(t => ({
    name:  FLAG_LABEL[t.flag] ?? t.flag,
    count: t.count,
  }));

  const radarData = RADAR_AXES.map(axis => {
    const key = Object.entries(FLAG_LABEL).find(([, v]) => v.toLowerCase().includes(axis.toLowerCase().split(" ")[0]))?.[0];
    const val  = key ? (threats.find(t => t.flag === key)?.count ?? 0) : 0;
    const max  = threats[0]?.count || 1;
    return { axis, val: Math.round(val / max * 100) };
  });

  return (
    <div className="flex flex-col min-h-screen">
      <Header title="Threat Analysis" subtitle="AI threat landscape across all tenants" />
      <div className="p-6 space-y-5 animate-fade-in">

        {/* Top categories */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="rounded-xl bg-surface-2 border border-border p-5">
            <p className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
              <AlertTriangle size={14} className="text-accent-orange" /> Threat Volume
            </p>
            {barData.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={barData} layout="vertical">
                  <XAxis type="number" tick={{ fill: "#6b7280", fontSize: 10 }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="name" tick={{ fill: "#9ca3af", fontSize: 11 }} axisLine={false} tickLine={false} width={120} />
                  <Tooltip contentStyle={{ background: "#0d1220", border: "1px solid #1e2a42", borderRadius: 8, fontSize: 12 }} />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {barData.map((_, i) => <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[220px] flex items-center justify-center text-gray-600 text-sm">
                No threat data yet
              </div>
            )}
          </div>

          <div className="rounded-xl bg-surface-2 border border-border p-5">
            <p className="text-sm font-semibold text-white mb-4">Attack Surface Radar</p>
            <ResponsiveContainer width="100%" height={220}>
              <RadarChart data={radarData}>
                <PolarGrid stroke="#1e2a42" />
                <PolarAngleAxis dataKey="axis" tick={{ fill: "#9ca3af", fontSize: 10 }} />
                <Radar dataKey="val" stroke="#7c3aed" fill="#7c3aed" fillOpacity={0.2} strokeWidth={2} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Table */}
        {barData.length > 0 && (
          <div className="rounded-xl bg-surface-2 border border-border overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border">
                  {["Threat Type", "Total", "Share"].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-gray-500 font-medium uppercase tracking-wider text-[10px]">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {barData.map((t, i) => {
                  const total = barData.reduce((a, b) => a + b.count, 0);
                  const pct   = total > 0 ? Math.round(t.count / total * 100) : 0;
                  return (
                    <tr key={t.name} className="border-b border-border/50 hover:bg-surface-3 transition-colors">
                      <td className="px-4 py-3 flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full" style={{ background: BAR_COLORS[i % BAR_COLORS.length] }} />
                        <span className="text-gray-300">{t.name}</span>
                      </td>
                      <td className="px-4 py-3 font-mono text-white">{t.count.toLocaleString()}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 rounded-full bg-surface-4 overflow-hidden">
                            <div className="h-full rounded-full" style={{ width: `${pct}%`, background: BAR_COLORS[i % BAR_COLORS.length] }} />
                          </div>
                          <span className="text-gray-500">{pct}%</span>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {barData.length === 0 && (
          <div className="rounded-xl bg-surface-2 border border-border p-8 text-center">
            <TrendingUp size={24} className="text-gray-700 mx-auto mb-2" />
            <p className="text-sm text-gray-600">No threats detected in the current window.</p>
          </div>
        )}
      </div>
    </div>
  );
}
