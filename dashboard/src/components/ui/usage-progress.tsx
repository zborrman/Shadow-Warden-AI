"use client";

import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { TrendingUp, Zap, AlertTriangle } from "lucide-react";

interface QuotaData {
  tenant_id: string;
  req_per_month: number | null;
  requests_used: number;
  requests_remaining: number | null;
  pct_used: number;
  overage_enabled: boolean;
  plan: string;
}

interface UsageProgressProps {
  tenantId?: string;
  className?: string;
  /** Show upgrade CTA at this percentage (default 80) */
  warnAt?: number;
}

const UPGRADE_NEXT: Record<string, { label: string; plan: string }> = {
  starter:            { label: "Individual",         plan: "individual" },
  individual:         { label: "Community Business", plan: "community_business" },
  community_business: { label: "Pro",                plan: "pro" },
  pro:                { label: "Enterprise",         plan: "enterprise" },
  enterprise:         { label: "custom",             plan: "enterprise" },
};

function BarColor(pct: number): string {
  if (pct >= 100) return "bg-accent-red";
  if (pct >= 80)  return "bg-accent-yellow";
  if (pct >= 50)  return "bg-accent-blue";
  return "bg-accent-green";
}

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000)     return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

async function fetchQuota(tenantId: string): Promise<QuotaData | null> {
  try {
    const res = await fetch("/api/billing/quota", {
      headers: { "X-Tenant-ID": tenantId },
    });
    if (!res.ok) return null;
    return await res.json() as QuotaData;
  } catch {
    return null;
  }
}

// ── Main component ────────────────────────────────────────────────────────────

export function UsageProgress({ tenantId = "default", className, warnAt = 80 }: UsageProgressProps) {
  const [quota, setQuota]     = useState<QuotaData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    fetchQuota(tenantId).then(data => {
      if (mounted) { setQuota(data); setLoading(false); }
    });
    const interval = setInterval(() => {
      fetchQuota(tenantId).then(data => { if (mounted && data) setQuota(data); });
    }, 60_000);  // refresh every 60s
    return () => { mounted = false; clearInterval(interval); };
  }, [tenantId]);

  if (loading) {
    return (
      <div className={cn("rounded-xl bg-surface-2 border border-border p-4 animate-pulse", className)}>
        <div className="h-3 w-1/3 bg-surface-3 rounded mb-3" />
        <div className="h-2 w-full bg-surface-3 rounded" />
      </div>
    );
  }

  if (!quota) return null;

  const pct          = Math.min(quota.pct_used ?? 0, 100);
  const unlimited    = quota.req_per_month === null;
  const showWarning  = !unlimited && pct >= warnAt;
  const nextPlan     = UPGRADE_NEXT[quota.plan ?? "starter"];
  const barColor     = BarColor(pct);

  return (
    <div className={cn(
      "rounded-xl border p-4 transition-all",
      showWarning
        ? "bg-accent-yellow/5 border-accent-yellow/30"
        : "bg-surface-2 border-border",
      className,
    )}>
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          {showWarning
            ? <AlertTriangle size={14} className="text-accent-yellow" />
            : <TrendingUp size={14} className="text-gray-400" />}
          <p className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
            Monthly Requests
          </p>
        </div>
        <span className={cn(
          "text-xs font-bold px-2 py-0.5 rounded-full",
          pct >= 100 ? "bg-accent-red/20 text-accent-red"
            : pct >= warnAt ? "bg-accent-yellow/20 text-accent-yellow"
            : "bg-surface-3 text-gray-400",
        )}>
          {unlimited ? "∞" : `${pct.toFixed(0)}%`}
        </span>
      </div>

      {/* Numbers */}
      {!unlimited && (
        <div className="flex items-baseline gap-1 mb-2">
          <span className="text-xl font-bold text-white">
            {formatNumber(quota.requests_used)}
          </span>
          <span className="text-sm text-gray-500">
            / {formatNumber(quota.req_per_month!)} req
          </span>
          {quota.requests_remaining !== null && (
            <span className="ml-auto text-xs text-gray-500">
              {formatNumber(quota.requests_remaining)} left
            </span>
          )}
        </div>
      )}

      {unlimited && (
        <p className="text-xl font-bold text-white mb-2">
          {formatNumber(quota.requests_used)} <span className="text-sm text-gray-500">used · unlimited</span>
        </p>
      )}

      {/* Progress bar */}
      {!unlimited && (
        <div className="w-full h-1.5 rounded-full bg-surface-3 overflow-hidden mb-3">
          <div
            className={cn("h-full rounded-full transition-all duration-700", barColor)}
            style={{ width: `${pct}%` }}
          />
        </div>
      )}

      {/* Upgrade CTA at 80%+ */}
      {showWarning && nextPlan.plan !== "enterprise" && (
        <div className="flex items-center justify-between pt-2 border-t border-accent-yellow/20">
          <p className="text-xs text-accent-yellow">
            {pct >= 100 ? "Limit reached — requests may be throttled" : `${100 - pct}% quota remaining`}
          </p>
          <a
            href={`/billing/upgrade?plan=${nextPlan.plan}`}
            className="flex items-center gap-1 text-xs font-semibold px-3 py-1.5 rounded-lg bg-accent-yellow/10 text-accent-yellow hover:bg-accent-yellow/20 transition-colors whitespace-nowrap"
          >
            <Zap size={10} />
            Upgrade to {nextPlan.label}
          </a>
        </div>
      )}

      {/* Overage notice */}
      {quota.overage_enabled && pct >= 100 && (
        <p className="text-xs text-gray-500 mt-2">
          Overage billing active — $0.50 per 1k additional requests
        </p>
      )}
    </div>
  );
}
