"use client";
import { useQuery } from "@tanstack/react-query";
import { LivePage, Panel, LiveTable, Kpi, Pill } from "@/components/ui/live";
import { liveGet, fmtDate } from "@/lib/live";

type Stats = { total?: number; by_status?: Record<string, number>; by_vault_type?: Record<string, number> };

export default function SecretsVaultPage() {
  const stats = useQuery({ queryKey: ["/secrets/stats"], queryFn: () => liveGet<Stats>("/secrets/stats"), retry: false });
  const s = stats.data;
  const v = (n: number | undefined) => (stats.isError ? "—" : s ? n ?? 0 : "…");
  return (
    <LivePage title="Secrets Vault" subtitle="Secrets governance — vault connectors, inventory and lifecycle. Metadata only, never a secret value">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Kpi label="Secrets tracked" value={v(s?.total)} />
        <Kpi label="Active" value={v(s?.by_status?.active)} />
        <Kpi label="Expired" value={v(s?.by_status?.expired)} />
        <Kpi label="Vault types" value={v(s ? Object.keys(s.by_vault_type ?? {}).length : undefined)} />
      </div>
      <Panel title="Connected vaults">
        <LiveTable
          what="Vault connectors"
          path="/secrets/vaults"
          listKeys={["vaults"]}
          empty="No vault connected."
          cols={[
            { key: "vault_type", label: "Type", render: r => <Pill value={r.vault_type} tone="info" /> },
            { key: "display_name", label: "Name" },
            { key: "last_synced", label: "Last synced", render: r => fmtDate(r.last_synced) },
            { key: "created_at", label: "Connected", render: r => fmtDate(r.created_at) },
          ]}
        />
      </Panel>
      <Panel title="Inventory">
        <LiveTable
          what="Secrets inventory"
          path="/secrets/inventory"
          listKeys={["secrets"]}
          empty="No secrets in the inventory yet. Sync a vault to populate it."
          cols={[
            { key: "name", label: "Secret", mono: true },
            { key: "vault_type", label: "Vault", mono: true },
            { key: "risk_score", label: "Risk", mono: true },
            { key: "last_rotated", label: "Last rotated", render: r => fmtDate(r.last_rotated) },
            { key: "expires_at", label: "Expires", render: r => fmtDate(r.expires_at) },
            { key: "status", label: "Status", render: r => <Pill value={r.status} /> },
          ]}
        />
      </Panel>
    </LivePage>
  );
}
