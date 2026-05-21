"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { DollarSign, AlertTriangle, CheckCircle, Clock } from "lucide-react";
import { Header } from "@/components/layout/header";
import { api } from "@/lib/api";

type BudgetDept = {
  status:        "ok" | "alert" | "over_budget" | "no_cap";
  department:    string;
  cap_usd:       number;
  current_spend: number;
  remaining:     number;
  pct_used:      number;
  alert_pct:     number;
};

type BudgetStatus = {
  tenant_id:    string;
  period_month: string;
  departments:  BudgetDept[];
  total_caps:   number;
};

function statusColor(s: BudgetDept["status"]) {
  if (s === "over_budget") return "text-red-400";
  if (s === "alert")       return "text-yellow-400";
  return "text-green-400";
}

function StatusIcon({ status }: { status: BudgetDept["status"] }) {
  if (status === "over_budget") return <AlertTriangle className="w-4 h-4 text-red-400" />;
  if (status === "alert")       return <Clock className="w-4 h-4 text-yellow-400" />;
  return <CheckCircle className="w-4 h-4 text-green-400" />;
}

export default function BudgetPage() {
  const [tenantId, setTenantId] = useState("default");

  const { data, isLoading, error } = useQuery<BudgetStatus>({
    queryKey:  ["budget", tenantId],
    queryFn:   () => api.budgetStatus(tenantId) as Promise<BudgetStatus>,
    refetchInterval: 30_000,
  });

  const depts     = data?.departments ?? [];
  const overCount = depts.filter(d => d.status === "over_budget").length;
  const alertCount = depts.filter(d => d.status === "alert").length;

  return (
    <div className="min-h-screen bg-[#0a0e1a] text-white">
      <Header title="AI Budget Dashboard" subtitle="Real-time spend vs cap by department" />
      <main className="p-6 max-w-6xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <DollarSign className="w-6 h-6 text-green-400" />
              AI Budget Dashboard
            </h1>
            <p className="text-slate-400 text-sm mt-1">
              {data?.period_month ?? "—"} · Real-time spend vs cap
            </p>
          </div>
          <input
            className="bg-slate-800 border border-slate-700 rounded px-3 py-1 text-sm text-white"
            value={tenantId}
            onChange={e => setTenantId(e.target.value)}
            placeholder="Tenant ID"
          />
        </div>

        {/* Summary cards */}
        <div className="grid grid-cols-3 gap-4 mb-6">
          <div className="bg-slate-800 rounded-xl p-4">
            <p className="text-slate-400 text-xs uppercase tracking-wide">Budget Caps</p>
            <p className="text-3xl font-bold mt-1">{data?.total_caps ?? "—"}</p>
          </div>
          <div className="bg-slate-800 rounded-xl p-4">
            <p className="text-slate-400 text-xs uppercase tracking-wide">Over Budget</p>
            <p className={`text-3xl font-bold mt-1 ${overCount > 0 ? "text-red-400" : "text-green-400"}`}>
              {overCount}
            </p>
          </div>
          <div className="bg-slate-800 rounded-xl p-4">
            <p className="text-slate-400 text-xs uppercase tracking-wide">Near Limit</p>
            <p className={`text-3xl font-bold mt-1 ${alertCount > 0 ? "text-yellow-400" : "text-green-400"}`}>
              {alertCount}
            </p>
          </div>
        </div>

        {isLoading && <p className="text-slate-400">Loading…</p>}
        {error    && <p className="text-red-400">Error: {String(error)}</p>}

        {/* Department spend bars */}
        {depts.length > 0 ? (
          <div className="space-y-4">
            {depts.map(dept => (
              <div key={dept.department} className="bg-slate-800 rounded-xl p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <StatusIcon status={dept.status} />
                    <span className="font-medium">{dept.department}</span>
                  </div>
                  <span className={`text-sm font-mono ${statusColor(dept.status)}`}>
                    ${dept.current_spend.toFixed(2)} / ${dept.cap_usd.toFixed(2)}
                  </span>
                </div>
                <div className="w-full bg-slate-700 rounded-full h-2">
                  <div
                    className={`h-2 rounded-full transition-all ${
                      dept.pct_used >= 1.0 ? "bg-red-500" :
                      dept.pct_used >= dept.alert_pct ? "bg-yellow-500" : "bg-green-500"
                    }`}
                    style={{ width: `${Math.min(dept.pct_used * 100, 100)}%` }}
                  />
                </div>
                <div className="flex justify-between text-xs text-slate-400 mt-1">
                  <span>{(dept.pct_used * 100).toFixed(1)}% used</span>
                  <span>${dept.remaining.toFixed(2)} remaining</span>
                </div>
              </div>
            ))}
          </div>
        ) : !isLoading && (
          <div className="bg-slate-800 rounded-xl p-8 text-center text-slate-400">
            No budget caps configured for this tenant.
          </div>
        )}
      </main>
    </div>
  );
}
