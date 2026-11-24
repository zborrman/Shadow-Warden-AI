"use client";
import { useQuery } from "@tanstack/react-query";
import { LivePage, Panel, LiveTable, Pill } from "@/components/ui/live";
import { DataUnavailable } from "@/components/ui/data-unavailable";
import { liveGet } from "@/lib/live";

type Status = { plan?: string; status?: string; renews_at?: string | null };
type Quota = { plan?: string; used?: number; limit?: number | null; effective_limit?: number | null; pct_used?: number };
type TenantAddons = { addons?: string[]; details?: { display_name?: string }[] };

export default function BillingPage() {
  const status = useQuery({ queryKey: ["/billing/status"], queryFn: () => liveGet<Status>("/billing/status"), retry: false });
  const quota = useQuery({ queryKey: ["/billing/quota"], queryFn: () => liveGet<Quota>("/billing/quota"), retry: false });
  const mine = useQuery({ queryKey: ["/billing/addons/tenant"], queryFn: () => liveGet<TenantAddons>("/billing/addons/tenant"), retry: false });
  const q = quota.data;
  const limit = q?.effective_limit ?? q?.limit;
  const pct = q?.pct_used ?? (limit ? ((q?.used ?? 0) / limit) * 100 : 0);
  // Catalogue entries carry no key, so a purchase is matched on display name.
  const active = new Set((mine.data?.details ?? []).map(d => d.display_name));

  return (
    <LivePage title="Billing" subtitle="Plan, usage and add-ons">
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Current plan">
          {status.isError ? (
            <DataUnavailable what="Billing status" />
          ) : (
            <div className="flex items-center gap-3">
              <span className="text-xl font-semibold text-white">{status.data?.plan ?? "…"}</span>
              {status.data?.status && <Pill value={status.data.status} />}
            </div>
          )}
        </Panel>
        <Panel title="Usage this period">
          {quota.isError ? (
            <DataUnavailable what="Request quota" />
          ) : (
            <div>
              <div className="flex justify-between text-xs text-gray-400">
                <span>Requests</span>
                <span className="font-mono text-gray-200">
                  {q ? `${(q.used ?? 0).toLocaleString("en-US")} / ${limit ? limit.toLocaleString("en-US") : "unlimited"}` : "…"}
                </span>
              </div>
              <div className="h-1.5 rounded bg-surface-3 mt-2 overflow-hidden">
                <div className="h-full bg-sky-500" style={{ width: `${Math.min(100, pct)}%` }} />
              </div>
            </div>
          )}
        </Panel>
      </div>
      <Panel title="Add-ons">
        <LiveTable
          what="Add-on catalogue"
          path="/billing/addons"
          listKeys={["addons"]}
          empty="No add-on is on sale."
          cols={[
            { key: "display_name", label: "Add-on" },
            { key: "usd_per_month", label: "Price", mono: true, render: r => `$${Number(r.usd_per_month).toFixed(2)}/mo` },
            { key: "min_tier", label: "Requires", mono: true },
            { key: "description", label: "What it adds" },
            { key: "active", label: "", render: r => (active.has(String(r.display_name)) ? <Pill value="active" /> : "") },
          ]}
        />
      </Panel>
      <p className="text-[11px] text-gray-500">
        Invoices are issued by the payment provider and are not shown here.
      </p>
    </LivePage>
  );
}
