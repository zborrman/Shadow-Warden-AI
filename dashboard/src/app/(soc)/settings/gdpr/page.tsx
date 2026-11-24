"use client";
import { useQuery } from "@tanstack/react-query";
import { LivePage, Panel } from "@/components/ui/live";
import { DataUnavailable } from "@/components/ui/data-unavailable";
import { liveGet } from "@/lib/live";

type Retention = {
  log_retention_days?: number;
  auto_purge_enabled?: boolean;
  auto_purge_cron?: string;
};

export default function GdprControlsPage() {
  const q = useQuery({ queryKey: ["/gdpr/retention-policy"], queryFn: () => liveGet<Retention>("/gdpr/retention-policy"), retry: false });
  const r = q.data;
  return (
    <LivePage title="GDPR Controls" subtitle="Data protection controls and records of processing">
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Controls">
          {q.isError ? (
            <DataUnavailable what="Retention policy" />
          ) : (
            <dl className="divide-y divide-border text-xs">
              <Row k="Prompt content stored" v="Never — only metadata (type, length, timing)" />
              <Row k="Log retention" v={r ? `${r.log_retention_days} days` : "…"} />
              <Row k="Automatic purge" v={r ? (r.auto_purge_enabled ? `on · ${r.auto_purge_cron}` : "off") : "…"} />
              <Row k="Secrets in logs" v="Redacted before logging" />
            </dl>
          )}
        </Panel>
        <Panel title="Records">
          <p className="text-[11px] text-gray-500 mb-3">
            Generated from the live configuration on each request.
          </p>
          <a
            href="/api/warden/api/compliance/gdpr/ropa"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-block px-3 py-1.5 rounded-md border border-border text-xs text-gray-200 hover:text-white"
          >
            Art. 30 record of processing
          </a>
        </Panel>
      </div>
    </LivePage>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between gap-3 py-2">
      <dt className="text-gray-500">{k}</dt>
      <dd className="text-gray-200 text-right">{v}</dd>
    </div>
  );
}
