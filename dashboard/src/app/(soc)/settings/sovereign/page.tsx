"use client";
import { useQuery } from "@tanstack/react-query";
import { LivePage, Panel, LiveTable, Pill } from "@/components/ui/live";
import { DataUnavailable } from "@/components/ui/data-unavailable";
import { liveGet, rowsOf, fmtDate } from "@/lib/live";

type Policy = {
  home_jurisdiction?: string;
  allowed_jurisdictions?: string[];
  blocked_jurisdictions?: string[];
  require_attestation?: boolean;
  fallback_mode?: string;
};

export default function SovereignRoutingPage() {
  const policy = useQuery({ queryKey: ["/sovereign/policy"], queryFn: () => liveGet<Policy>("/sovereign/policy"), retry: false });
  const juris = useQuery({ queryKey: ["/sovereign/jurisdictions"], queryFn: () => liveGet<unknown>("/sovereign/jurisdictions"), retry: false });
  const p = policy.data;
  const home = p?.home_jurisdiction;
  return (
    <LivePage title="Sovereign Routing" subtitle="Jurisdiction policy and MASQUE tunnels for AI traffic">
      <div className="grid gap-4 lg:grid-cols-[300px_1fr]">
        <Panel title="Tenant policy">
          {policy.isError ? (
            <DataUnavailable what="Routing policy" />
          ) : (
            <dl className="space-y-2 text-xs">
              {[
                ["Home jurisdiction", home],
                ["Allowed", p?.allowed_jurisdictions?.join(", ")],
                ["Blocked", p?.blocked_jurisdictions?.join(", ") || "none"],
                ["Fallback", p?.fallback_mode],
                ["Attestation", p ? (p.require_attestation ? "required" : "optional") : undefined],
              ].map(([k, val]) => (
                <div key={k} className="flex justify-between gap-3">
                  <dt className="text-gray-500">{k}</dt>
                  <dd className="text-gray-200 font-mono">{val ?? "…"}</dd>
                </div>
              ))}
            </dl>
          )}
        </Panel>
        <Panel title="Jurisdictions">
          {juris.isError ? (
            <DataUnavailable what="Jurisdictions" />
          ) : (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              {rowsOf(juris.data, "jurisdictions").map(j => (
                <div
                  key={String(j.code)}
                  className={j.code === home ? "rounded-lg border border-sky-500/60 p-2" : "rounded-lg border border-border p-2"}
                >
                  <p className="font-mono text-sm text-white">{String(j.code)}</p>
                  <p className="text-[10px] text-gray-500 mt-1">
                    Adequacy: {Array.isArray(j.adequacy_partners) && j.adequacy_partners.length ? j.adequacy_partners.join(", ") : "—"}
                  </p>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>
      <Panel title="Tunnels">
        <LiveTable
          what="MASQUE tunnels"
          path="/sovereign/tunnels"
          listKeys={["tunnels"]}
          empty="No tunnels registered."
          cols={[
            { key: "tunnel_id", label: "Tunnel", mono: true },
            { key: "jurisdiction", label: "Jurisdiction", mono: true },
            { key: "region", label: "Region" },
            { key: "protocol", label: "Protocol", mono: true },
            { key: "latency_ms", label: "Latency (ms)", mono: true },
            { key: "last_seen_at", label: "Last probe", render: r => fmtDate(r.last_seen_at) },
            { key: "status", label: "Status", render: r => <Pill value={r.status} /> },
          ]}
        />
      </Panel>
    </LivePage>
  );
}
