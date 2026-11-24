"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { LivePage, Panel, LiveTable, Kpi, CommunityPicker } from "@/components/ui/live";
import { DataUnavailable } from "@/components/ui/data-unavailable";
import { liveGet, fmtDate } from "@/lib/live";

type Report = {
  total_programs: number;
  total_completions: number;
  passed: number;
  pass_rate: number;
  expired: number;
  unique_employees: number;
};

export default function TrainingRecordsPage() {
  const [community, setCommunity] = useState("");
  const report = useQuery({
    queryKey: ["/training/compliance-report", community],
    queryFn: () => liveGet<Report>("/training/compliance-report", { community_id: community }),
    enabled: !!community,
    retry: false,
  });
  const r = report.data;
  const v = (n: number | undefined) => (!community ? "—" : r ? n ?? 0 : "…");
  return (
    <LivePage title="Training Records" subtitle="Employee AI training completions with HMAC-signed attestations">
      <CommunityPicker value={community} onChange={setCommunity} />
      {report.isError ? (
        <DataUnavailable what="Training compliance report" />
      ) : (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <Kpi label="Programs" value={v(r?.total_programs)} />
          <Kpi label="Pass rate" value={!community ? "—" : r ? `${Math.round(Number(r.pass_rate) * 100)}%` : "…"} sub={r ? `${r.passed} of ${r.total_completions} completions` : undefined} />
          <Kpi label="Employees" value={v(r?.unique_employees)} />
          <Kpi label="Expired" value={v(r?.expired)} sub="certifications past validity" />
        </div>
      )}
      <Panel title="Programs">
        <LiveTable
          what="Training programs"
          enabled={!!community}
          path="/training/programs"
          params={{ community_id: community }}
          listKeys={["programs"]}
          empty="No training programs in this community."
          cols={[
            { key: "title", label: "Program" },
            { key: "passing_score", label: "Passing score", mono: true },
            { key: "valid_days", label: "Valid (days)", mono: true },
            { key: "required_for", label: "Required for", render: row => (Array.isArray(row.required_for) ? row.required_for.join(", ") : String(row.required_for ?? "—")) },
            { key: "created_at", label: "Created", render: row => fmtDate(row.created_at) },
          ]}
        />
      </Panel>
    </LivePage>
  );
}
