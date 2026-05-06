"use client";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, RadarChart, PolarGrid, PolarAngleAxis, Radar } from "recharts";
import { Header } from "@/components/layout/header";
import { AlertTriangle, TrendingUp } from "lucide-react";

const THREAT_DATA = [
  { name: "Jailbreak",         count: 1204, week: 843,  pct: 42 },
  { name: "Secret Leak",       count: 786,  week: 612,  pct: 28 },
  { name: "Prompt Injection",  count: 512,  week: 390,  pct: 18 },
  { name: "Social Engineering",count: 201,  week: 157,  pct: 7  },
  { name: "Data Poisoning",    count: 88,   week: 71,   pct: 3  },
  { name: "Other",             count: 50,   week: 38,   pct: 2  },
];

const RADAR_DATA = [
  { axis: "Jailbreak",         val: 87 },
  { axis: "Obfuscation",       val: 62 },
  { axis: "Secret Exfil",      val: 74 },
  { axis: "SE / Phishing",     val: 55 },
  { axis: "Data Poisoning",    val: 38 },
  { axis: "Prompt Injection",  val: 79 },
];

const BAR_COLORS = ["#7c3aed", "#2563eb", "#06b6d4", "#10b981", "#f59e0b", "#ef4444"];

const TREND = Array.from({ length: 14 }, (_, i) => ({
  day: `D-${13 - i}`,
  jailbreak: 60 + Math.random() * 60 | 0,
  secrets:   30 + Math.random() * 40 | 0,
  injection: 20 + Math.random() * 30 | 0,
}));

export default function ThreatsPage() {
  return (
    <div className="flex flex-col min-h-screen">
      <Header title="Threat Analysis" subtitle="AI threat landscape across all tenants" />
      <div className="p-6 space-y-5 animate-fade-in">

        {/* Top categories */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="rounded-xl bg-surface-2 border border-border p-5">
            <p className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
              <AlertTriangle size={14} className="text-accent-orange" /> Threat Volume (90d)
            </p>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={THREAT_DATA} layout="vertical">
                <XAxis type="number" tick={{ fill: "#6b7280", fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" tick={{ fill: "#9ca3af", fontSize: 11 }} axisLine={false} tickLine={false} width={120} />
                <Tooltip contentStyle={{ background: "#0d1220", border: "1px solid #1e2a42", borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {THREAT_DATA.map((_, i) => (
                    <rect key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="rounded-xl bg-surface-2 border border-border p-5">
            <p className="text-sm font-semibold text-white mb-4">Attack Surface Radar</p>
            <ResponsiveContainer width="100%" height={220}>
              <RadarChart data={RADAR_DATA}>
                <PolarGrid stroke="#1e2a42" />
                <PolarAngleAxis dataKey="axis" tick={{ fill: "#9ca3af", fontSize: 10 }} />
                <Radar dataKey="val" stroke="#7c3aed" fill="#7c3aed" fillOpacity={0.2} strokeWidth={2} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* 14-day trend */}
        <div className="rounded-xl bg-surface-2 border border-border p-5">
          <p className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <TrendingUp size={14} className="text-accent-cyan" /> 14-Day Trend
          </p>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={TREND}>
              <XAxis dataKey="day" tick={{ fill: "#6b7280", fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: "#6b7280", fontSize: 10 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: "#0d1220", border: "1px solid #1e2a42", borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="jailbreak" stackId="a" fill="#7c3aed" name="Jailbreak"  radius={[0, 0, 0, 0]} />
              <Bar dataKey="secrets"   stackId="a" fill="#2563eb" name="Secrets"    />
              <Bar dataKey="injection" stackId="a" fill="#06b6d4" name="Injection"  radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Table */}
        <div className="rounded-xl bg-surface-2 border border-border overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border">
                {["Threat Type", "Total (90d)", "This Week", "Share", "Trend"].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-gray-500 font-medium uppercase tracking-wider text-[10px]">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {THREAT_DATA.map((t, i) => (
                <tr key={t.name} className="border-b border-border/50 hover:bg-surface-3 transition-colors">
                  <td className="px-4 py-3 flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full" style={{ background: BAR_COLORS[i % BAR_COLORS.length] }} />
                    <span className="text-gray-300">{t.name}</span>
                  </td>
                  <td className="px-4 py-3 font-mono text-white">{t.count.toLocaleString()}</td>
                  <td className="px-4 py-3 font-mono text-gray-300">{t.week.toLocaleString()}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-1.5 rounded-full bg-surface-4 overflow-hidden">
                        <div className="h-full rounded-full" style={{ width: `${t.pct}%`, background: BAR_COLORS[i % BAR_COLORS.length] }} />
                      </div>
                      <span className="text-gray-500">{t.pct}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-accent-green text-[10px]">▲ +{(Math.random() * 5 + 1).toFixed(1)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
