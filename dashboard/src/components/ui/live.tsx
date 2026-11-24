"use client";
// Building blocks for the pages behind the sidebar's former "SOON" items.
// Layout follows the approved mock-ups (page header, KPI strip, panels,
// tables); every value on screen comes from a gateway response.
import { useQuery } from "@tanstack/react-query";
import { Inbox } from "lucide-react";
import { Header } from "@/components/layout/header";
import { DataUnavailable } from "@/components/ui/data-unavailable";
import { liveGet, rowsOf, TENANT_ID } from "@/lib/live";
import { cn } from "@/lib/utils";

export function LivePage({
  title, subtitle, children,
}: { title: string; subtitle: string; children: React.ReactNode }) {
  return (
    <div>
      <Header title={title} subtitle={subtitle} />
      <div className="p-6 space-y-4">{children}</div>
    </div>
  );
}

export function Panel({
  title, aside, children, className,
}: { title: string; aside?: React.ReactNode; children: React.ReactNode; className?: string }) {
  return (
    <section className={cn("rounded-xl bg-surface-2 border border-border", className)}>
      <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
        <h2 className="text-sm font-semibold text-white flex-1">{title}</h2>
        {aside}
      </div>
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Kpi({ label, value, sub }: { label: string; value: React.ReactNode; sub?: string }) {
  return (
    <div className="rounded-xl bg-surface-2 border border-border p-4">
      <p className="text-[10px] font-mono uppercase tracking-widest text-gray-500">{label}</p>
      <p className="text-2xl font-bold font-mono text-white mt-1">{value}</p>
      {sub && <p className="text-[11px] text-gray-500 mt-0.5">{sub}</p>}
    </div>
  );
}

const PILL_TONE: Record<string, string> = {
  good: "text-green-400 bg-green-500/10 border-green-500/20",
  warn: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  bad: "text-red-400 bg-red-500/10 border-red-500/20",
  info: "text-sky-400 bg-sky-500/10 border-sky-500/20",
  mute: "text-gray-400 bg-surface-3 border-border",
};

const GOOD = /^(active|healthy|ok|up|pass|allow|allowed|verified|accepted|connected|implemented|low|done|compliant|true)$/i;
const BAD = /^(revoked|offline|down|fail|failed|block|blocked|rejected|expired|overdue|critical|high|retired|error|offboarded|false)$/i;
const WARN = /^(pending|pending_review|degraded|review|medium|flag|stale|partial|investigating|open|issued|due)$/i;

export function Pill({ value, tone }: { value: unknown; tone?: keyof typeof PILL_TONE }) {
  const s = value === null || value === undefined || value === "" ? "—" : String(value);
  const t = tone ?? (GOOD.test(s) ? "good" : BAD.test(s) ? "bad" : WARN.test(s) ? "warn" : "mute");
  return (
    <span className={cn("inline-block px-1.5 py-0.5 rounded border text-[10px] font-mono uppercase tracking-wide", PILL_TONE[t])}>
      {s}
    </span>
  );
}

export type Col = {
  key: string;
  label: string;
  render?: (row: Record<string, unknown>) => React.ReactNode;
  mono?: boolean;
};

export function RecordsTable({ cols, rows, empty }: { cols: Col[]; rows: Record<string, unknown>[]; empty: string }) {
  if (rows.length === 0) return <Empty text={empty} />;
  return (
    <div className="overflow-x-auto -mx-4">
      <table className="w-full text-xs">
        <thead>
          <tr className="bg-surface-3/60 text-gray-500 text-left">
            {cols.map(c => <th key={c.key} className="px-4 py-2 font-medium">{c.label}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="border-t border-border">
              {cols.map(c => {
                const raw = r[c.key];
                const cell = c.render ? c.render(r) : raw === null || raw === undefined || raw === "" ? "—" : String(raw);
                return (
                  <td key={c.key} className={cn("px-4 py-2 text-gray-300", c.mono && "font-mono")}>{cell}</td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Empty({ text }: { text: string }) {
  return (
    <div className="flex items-center gap-2 py-6 justify-center text-xs text-gray-500">
      <Inbox size={14} /> {text}
    </div>
  );
}

/**
 * One gateway read rendered as a table. Loading shows a skeleton, an error
 * shows DataUnavailable, an empty list says so — there is no sample data.
 */
export function LiveTable({
  what, path, params, listKeys = [], cols, empty, enabled = true,
}: {
  what: string;
  path: string;
  params?: Record<string, string | number | undefined>;
  listKeys?: string[];
  cols: Col[];
  empty: string;
  enabled?: boolean;
}) {
  const q = useQuery({
    queryKey: [path, params],
    queryFn: () => liveGet<unknown>(path, params),
    enabled,
    retry: false,
  });
  if (!enabled) return <Empty text="Choose a community above." />;
  if (q.isLoading) return <div className="h-20 rounded-lg bg-surface-3 animate-pulse" />;
  if (q.isError) return <DataUnavailable what={what} />;
  return <RecordsTable cols={cols} rows={rowsOf(q.data, ...listKeys)} empty={empty} />;
}

/** Community selector for the SEP pages, which are all scoped to one community. */
export function CommunityPicker({ value, onChange }: { value: string; onChange: (id: string) => void }) {
  const q = useQuery({
    queryKey: ["/communities", TENANT_ID],
    queryFn: () => liveGet<unknown>("/communities", { tenant_id: TENANT_ID }),
    retry: false,
  });
  const rows = rowsOf(q.data, "communities");
  if (q.isError) return <DataUnavailable what="Community list" />;
  return (
    <label className="flex items-center gap-2 text-xs text-gray-400">
      Community
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        className="bg-surface-3 border border-border rounded-md px-2 py-1.5 text-xs text-white min-w-56"
      >
        <option value="">{q.isLoading ? "Loading…" : rows.length ? "Select…" : "No communities yet"}</option>
        {rows.map(r => (
          <option key={String(r.community_id)} value={String(r.community_id)}>
            {String(r.name ?? r.community_id)}
          </option>
        ))}
      </select>
    </label>
  );
}
