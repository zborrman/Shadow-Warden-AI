"use client";
import { useQuery } from "@tanstack/react-query";
import { LivePage, Panel, LiveTable, Pill } from "@/components/ui/live";
import { liveGet, rowsOf, fmtDate } from "@/lib/live";

export default function VendorGovernancePage() {
  const expiring = useQuery({
    queryKey: ["/vendor-gov/dpa/expiring"],
    queryFn: () => liveGet<unknown>("/vendor-gov/dpa/expiring", { within_days: 30 }),
    retry: false,
  });
  const soon = rowsOf(expiring.data, "expiring");
  return (
    <LivePage title="Vendor Governance" subtitle="AI vendor register with DPA expiry tracking">
      {soon.length > 0 && (
        <div role="status" className="rounded-xl border border-yellow-500/30 bg-yellow-500/5 px-4 py-3 text-xs text-yellow-300">
          {soon.length} DPA{soon.length === 1 ? "" : "s"} expire within 30 days:{" "}
          {soon.map(d => `${d.vendor_id} (${fmtDate(d.expires_at)})`).join(", ")}
        </div>
      )}
      <Panel title="Vendors">
        <LiveTable
          what="Vendor register"
          path="/vendor-gov/vendors"
          listKeys={["vendors"]}
          empty="No vendors registered yet."
          cols={[
            { key: "display_name", label: "Vendor" },
            { key: "provider_type", label: "Type" },
            { key: "risk_tier", label: "Risk tier", render: r => <Pill value={r.risk_tier} /> },
            { key: "status", label: "Status", render: r => <Pill value={r.status} /> },
            { key: "contact_email", label: "Contact" },
            { key: "updated_at", label: "Updated", render: r => fmtDate(r.updated_at ?? r.created_at) },
          ]}
        />
      </Panel>
    </LivePage>
  );
}
