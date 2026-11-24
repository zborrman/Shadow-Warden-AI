"use client";
import { useQuery } from "@tanstack/react-query";
import { LivePage, Panel, LiveTable, Pill } from "@/components/ui/live";
import { DataUnavailable } from "@/components/ui/data-unavailable";
import { liveGet, fmtDate } from "@/lib/live";

type Policy = {
  mode?: string;
  allowlist?: string[];
  denylist?: string[];
  risk_threshold?: string;
  notify_slack?: boolean;
};

const MODES = ["MONITOR", "BLOCK_DENYLIST", "ALLOWLIST_ONLY"];

function Chips({ items, tone }: { items?: string[]; tone: "good" | "bad" }) {
  if (!items?.length) return <p className="text-[11px] text-gray-500">None</p>;
  return (
    <div className="flex flex-wrap gap-1">
      {items.map(i => <Pill key={i} value={i} tone={tone} />)}
    </div>
  );
}

export default function ShadowAiPage() {
  const policy = useQuery({
    queryKey: ["/shadow-ai/policy"],
    queryFn: () => liveGet<Policy>("/shadow-ai/policy"),
    retry: false,
  });
  const p = policy.data;
  return (
    <LivePage title="Shadow AI" subtitle="Unsanctioned AI providers seen on the network, and the policy applied to them">
      <div className="grid gap-4 lg:grid-cols-[300px_1fr]">
        <Panel title="Policy">
          {policy.isError ? (
            <DataUnavailable what="Shadow AI policy" />
          ) : (
            <div className="space-y-3">
              <div>
                <p className="text-[11px] text-gray-500 mb-1">Mode</p>
                <div className="flex rounded-md border border-border overflow-hidden text-[10px] font-mono">
                  {MODES.map(m => (
                    <span
                      key={m}
                      className={m === p?.mode ? "flex-1 px-2 py-1.5 text-center bg-white/10 text-white" : "flex-1 px-2 py-1.5 text-center text-gray-500"}
                    >
                      {m}
                    </span>
                  ))}
                </div>
              </div>
              <p className="text-[11px] text-gray-500">
                Risk threshold: <span className="text-gray-200 font-mono">{p?.risk_threshold ?? "—"}</span>
                {" · "}Slack: <span className="text-gray-200">{p?.notify_slack ? "on" : "off"}</span>
              </p>
              <div>
                <p className="text-[11px] text-gray-500 mb-1">Allowlist</p>
                <Chips items={p?.allowlist} tone="good" />
              </div>
              <div>
                <p className="text-[11px] text-gray-500 mb-1">Denylist</p>
                <Chips items={p?.denylist} tone="bad" />
              </div>
            </div>
          )}
        </Panel>
        <Panel title="Discovered providers">
          <LiveTable
            what="Shadow AI findings"
            path="/shadow-ai/findings"
            listKeys={["findings"]}
            empty="No findings yet. Findings arrive from subnet scans and DNS telemetry."
            cols={[
              { key: "display_name", label: "Provider" },
              { key: "source", label: "Source" },
              { key: "ip", label: "Host", mono: true },
              { key: "risk_level", label: "Risk", render: r => <Pill value={r.risk_level} /> },
              { key: "verdict", label: "Verdict", render: r => <Pill value={r.verdict} /> },
              { key: "detected_at", label: "Seen", render: r => fmtDate(r.detected_at) },
            ]}
          />
        </Panel>
      </div>
      <Panel title="Known provider signatures">
        <LiveTable
          what="Provider signatures"
          path="/shadow-ai/providers"
          empty="No signatures loaded."
          cols={[
            { key: "display_name", label: "Provider" },
            { key: "category", label: "Category" },
            { key: "risk_level", label: "Risk", render: r => <Pill value={r.risk_level} /> },
            { key: "domains", label: "Domains", render: r => (Array.isArray(r.domains) ? r.domains.slice(0, 3).join(", ") : "—") },
          ]}
        />
      </Panel>
    </LivePage>
  );
}
