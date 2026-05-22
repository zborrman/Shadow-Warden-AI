"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Shield, AlertTriangle, CheckCircle, Building2,
  FileText, Users, TrendingUp, Clock, DollarSign,
} from "lucide-react";
import { Header } from "@/components/layout/header";
import { api, type IncidentEntry, type VendorStats } from "@/lib/api";
import { cn } from "@/lib/utils";

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: "text-red-400 bg-red-500/10 border-red-500/20",
  HIGH:     "text-orange-400 bg-orange-500/10 border-orange-500/20",
  MEDIUM:   "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  LOW:      "text-green-400 bg-green-500/10 border-green-500/20",
};

const STATUS_COLOR: Record<string, string> = {
  open:          "text-red-400",
  investigating: "text-yellow-400",
  resolved:      "text-green-400",
  closed:        "text-gray-500",
};

const MOCK_VENDOR_STATS: VendorStats = {
  total: 12, by_risk_tier: { LOW: 4, MEDIUM: 6, HIGH: 2 },
  by_status: { active: 10, review: 2 }, expiring_dpas: 3, active_dpas: 9,
};

const MOCK_INCIDENTS: IncidentEntry[] = [
  { incident_id: "inc_001", tenant_id: "t1", title: "Jailbreak attempt via role-play", severity: "HIGH",   category: "JAILBREAK",  status: "open",   created_at: new Date(Date.now() - 3_600_000).toISOString() },
  { incident_id: "inc_002", tenant_id: "t1", title: "PII found in marketing prompt",   severity: "MEDIUM", category: "PII_LEAK",   status: "resolved", created_at: new Date(Date.now() - 7_200_000).toISOString() },
  { incident_id: "inc_003", tenant_id: "t1", title: "Prompt injection in chatbot",     severity: "CRITICAL",category: "JAILBREAK", status: "investigating", created_at: new Date(Date.now() - 10_800_000).toISOString() },
  { incident_id: "inc_004", tenant_id: "t1", title: "Hallucinated legal advice",       severity: "LOW",    category: "HALLUCINATION", status: "closed", created_at: new Date(Date.now() - 86_400_000).toISOString() },
  { incident_id: "inc_005", tenant_id: "t1", title: "Vendor DPA expiring in 7 days",   severity: "MEDIUM", category: "COMPLIANCE", status: "open", created_at: new Date(Date.now() - 172_800_000).toISOString() },
];

function StatCard({ label, value, sub, icon: Icon, color }: {
  label: string; value: string | number; sub?: string;
  icon: React.ElementType; color: string;
}) {
  return (
    <div className="rounded-xl bg-surface-2 border border-border p-4 flex items-start gap-3">
      <div className={cn("w-9 h-9 rounded-lg flex items-center justify-center shrink-0", color)}>
        <Icon size={16} />
      </div>
      <div>
        <p className="text-[11px] text-gray-500 uppercase tracking-wider">{label}</p>
        <p className="text-2xl font-bold text-white mt-0.5">{value}</p>
        {sub && <p className="text-[11px] text-gray-500 mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

function fmtAge(iso: string) {
  const ms = Date.now() - new Date(iso).getTime();
  const h = Math.floor(ms / 3_600_000);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function SMBPage() {
  const [tenantId, setTenantId] = useState("default");

  const { data: vendorStats } = useQuery<VendorStats>({
    queryKey: ["vendor-stats", tenantId],
    queryFn:  () => api.vendorStats(tenantId),
    placeholderData: MOCK_VENDOR_STATS,
  });

  const { data: incidentData } = useQuery<{ incidents: IncidentEntry[] }>({
    queryKey: ["incidents", tenantId],
    queryFn:  () => api.incidents(tenantId, 5),
    placeholderData: { incidents: MOCK_INCIDENTS },
  });

  const { data: incidentStats } = useQuery({
    queryKey: ["incident-stats", tenantId],
    queryFn:  () => api.incidentStats(tenantId),
    placeholderData: { total: 5, open: 2, by_severity: { HIGH: 1, MEDIUM: 2, LOW: 1, CRITICAL: 1 }, by_category: {} },
  });

  const { data: budget } = useQuery({
    queryKey: ["budget", tenantId],
    queryFn:  () => api.budgetStatus(tenantId),
    placeholderData: { tenant_id: "default", period_month: "", total_caps: 4, departments: [] },
  });

  const vs = vendorStats ?? MOCK_VENDOR_STATS;
  const incidents = incidentData?.incidents ?? MOCK_INCIDENTS;
  const openCount = incidents.filter(i => i.status === "open" || i.status === "investigating").length;

  return (
    <div className="flex flex-col min-h-screen">
      <Header title="SMB Governance" subtitle="AI vendor governance, incidents, and compliance overview" />
      <div className="p-6 space-y-6 animate-fade-in">

        {/* Tenant selector */}
        <div className="flex items-center gap-3">
          <label className="text-xs text-gray-500">Tenant</label>
          <input
            value={tenantId}
            onChange={e => setTenantId(e.target.value)}
            className="px-3 py-1.5 text-xs rounded-lg bg-surface-3 border border-border text-gray-300 focus:outline-none focus:border-accent-blue w-40"
            placeholder="Tenant ID"
          />
        </div>

        {/* KPI row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard label="AI Vendors"      value={vs.total}              sub={`${vs.by_risk_tier?.HIGH ?? 0} high-risk`}       icon={Building2}     color="bg-blue-500/15 text-blue-400" />
          <StatCard label="Active DPAs"     value={vs.active_dpas}        sub={`${vs.expiring_dpas} expiring soon`}              icon={FileText}      color="bg-purple-500/15 text-purple-400" />
          <StatCard label="Open Incidents"  value={openCount}             sub={`${incidentStats?.total ?? 0} total`}             icon={AlertTriangle} color="bg-red-500/15 text-red-400" />
          <StatCard label="Budget Caps"     value={(budget as { total_caps?: number })?.total_caps ?? "—"} sub="departments tracked" icon={DollarSign}    color="bg-green-500/15 text-green-400" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Vendor risk breakdown */}
          <div className="rounded-xl bg-surface-2 border border-border p-5">
            <div className="flex items-center gap-2 mb-4">
              <Shield size={14} className="text-accent-blue" />
              <h2 className="text-sm font-semibold text-white">Vendor Risk Distribution</h2>
            </div>
            <div className="space-y-3">
              {(["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const).map(tier => {
                const count = vs.by_risk_tier?.[tier] ?? 0;
                const pct = vs.total ? (count / vs.total) * 100 : 0;
                const colors: Record<string, string> = {
                  LOW: "bg-green-500", MEDIUM: "bg-yellow-500",
                  HIGH: "bg-orange-500", CRITICAL: "bg-red-500",
                };
                return (
                  <div key={tier}>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-gray-400">{tier}</span>
                      <span className="text-gray-300 font-mono">{count}</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-surface-4">
                      <div className={cn("h-1.5 rounded-full transition-all", colors[tier])}
                           style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
            {vs.expiring_dpas > 0 && (
              <div className="mt-4 flex items-center gap-2 p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20 text-xs text-yellow-400">
                <Clock size={12} />
                {vs.expiring_dpas} DPA{vs.expiring_dpas > 1 ? "s" : ""} expiring within 30 days
              </div>
            )}
          </div>

          {/* Recent incidents */}
          <div className="rounded-xl bg-surface-2 border border-border p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <AlertTriangle size={14} className="text-red-400" />
                <h2 className="text-sm font-semibold text-white">Recent Incidents</h2>
              </div>
              <a href="/incidents" className="text-[11px] text-accent-blue hover:underline">View all</a>
            </div>
            <div className="space-y-2">
              {incidents.slice(0, 5).map(inc => (
                <div key={inc.incident_id}
                     className="flex items-start gap-3 p-2.5 rounded-lg hover:bg-surface-3 transition-colors">
                  <div className={cn("mt-0.5 text-[10px] font-bold px-1.5 py-0.5 rounded border shrink-0",
                                     SEVERITY_COLOR[inc.severity] ?? "text-gray-400 bg-gray-500/10 border-gray-500/20")}>
                    {inc.severity}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-white truncate">{inc.title}</p>
                    <p className="text-[11px] text-gray-500 mt-0.5">{inc.category} · {fmtAge(inc.created_at)}</p>
                  </div>
                  <span className={cn("text-[10px] shrink-0 font-medium capitalize", STATUS_COLOR[inc.status] ?? "text-gray-400")}>
                    {inc.status}
                  </span>
                </div>
              ))}
              {incidents.length === 0 && (
                <div className="flex items-center gap-2 py-6 justify-center text-green-400 text-sm">
                  <CheckCircle size={16} /> No active incidents
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Severity breakdown */}
        {incidentStats && (
          <div className="rounded-xl bg-surface-2 border border-border p-5">
            <div className="flex items-center gap-2 mb-4">
              <TrendingUp size={14} className="text-accent-purple" />
              <h2 className="text-sm font-semibold text-white">Incident Breakdown</h2>
            </div>
            <div className="grid grid-cols-4 gap-3">
              {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map(sev => {
                const n = (incidentStats as { by_severity: Record<string, number> }).by_severity?.[sev] ?? 0;
                return (
                  <div key={sev} className={cn("rounded-lg border p-3 text-center",
                    SEVERITY_COLOR[sev] ?? "text-gray-400 bg-gray-500/10 border-gray-500/20")}>
                    <p className="text-2xl font-bold">{n}</p>
                    <p className="text-[11px] font-medium mt-0.5 opacity-80">{sev}</p>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Quick links */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { href: "/budget",       icon: DollarSign,    label: "Budget Dashboard",       color: "text-green-400" },
            { href: "/intelligence", icon: TrendingUp,    label: "Business Intelligence",  color: "text-blue-400" },
            { href: "/smb/vendors",  icon: Building2,     label: "Vendor Register",        color: "text-purple-400" },
            { href: "/smb/training", icon: Users,         label: "Training Records",       color: "text-yellow-400" },
          ].map(link => (
            <a key={link.href} href={link.href}
               className="flex items-center gap-2.5 rounded-xl bg-surface-2 border border-border p-4 hover:border-border/70 hover:bg-surface-3 transition-all">
              <link.icon size={16} className={link.color} />
              <span className="text-xs text-gray-300 font-medium">{link.label}</span>
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}
