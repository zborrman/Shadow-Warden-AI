"use client";
import { useQuery } from "@tanstack/react-query";
import { LivePage, Panel, LiveTable, Pill, Kpi } from "@/components/ui/live";
import { liveGet, fmtDate } from "@/lib/live";

type Stats = { total?: number; open?: number; high_critical?: number; by_category?: Record<string, number> };

export default function IncidentRegisterPage() {
  const stats = useQuery({
    queryKey: ["/incidents/stats"],
    queryFn: () => liveGet<Stats>("/incidents/stats"),
    retry: false,
  });
  const s = stats.data;
  const v = (n: number | undefined) => (stats.isError ? "—" : s ? (n ?? 0) : "…");
  return (
    <LivePage title="Incident Register" subtitle="AI incidents, each linked to the community STIX 2.1 audit chain">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Kpi label="Incidents" value={v(s?.total)} />
        <Kpi label="Open" value={v(s?.open)} />
        <Kpi label="High or critical" value={v(s?.high_critical)} />
        <Kpi label="Categories" value={v(s ? Object.keys(s.by_category ?? {}).length : undefined)} />
      </div>
      <Panel title="Incidents">
        <LiveTable
          what="Incident register"
          path="/incidents"
          listKeys={["incidents"]}
          empty="No incidents logged."
          cols={[
            { key: "incident_id", label: "ID", mono: true },
            { key: "title", label: "Incident" },
            { key: "severity", label: "Severity", render: r => <Pill value={r.severity} /> },
            { key: "status", label: "Status", render: r => <Pill value={r.status} /> },
            { key: "created_at", label: "Logged", render: r => fmtDate(r.created_at) },
            { key: "stix_chain_id", label: "STIX entry", mono: true, render: r => (r.stix_chain_id ? String(r.stix_chain_id).slice(0, 18) + "…" : "—") },
          ]}
        />
      </Panel>
    </LivePage>
  );
}
