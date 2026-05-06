"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { Search, Filter, ChevronRight } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { Header } from "@/components/layout/header";
import { VerdictBadge } from "@/components/ui/verdict-badge";
import { api } from "@/lib/api";
import { fmtMs, cn } from "@/lib/utils";
import type { Verdict } from "@/lib/types";

const MOCK_EVENTS = Array.from({ length: 50 }, (_, i) => ({
  request_id: `req_${(Math.random() * 1e9 | 0).toString(36)}`,
  ts: new Date(Date.now() - i * 73_000).toISOString(),
  tenant_id: ["tenant_a", "tenant_b", "tenant_c"][i % 3],
  verdict: (["ALLOW", "ALLOW", "ALLOW", "MEDIUM", "HIGH", "BLOCK"] as Verdict[])[i % 6],
  processing_ms: 22 + Math.random() * 40,
  threat_type: i % 6 < 3 ? null : ["Jailbreak", "Secret Leak", "Prompt Injection"][i % 3],
  content_length: 80 + Math.random() * 400 | 0,
}));

const VERDICTS: (Verdict | "ALL")[] = ["ALL", "ALLOW", "MEDIUM", "HIGH", "BLOCK"];

export default function EventsPage() {
  const router = useRouter();
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<Verdict | "ALL">("ALL");

  const { data: raw } = useQuery({ queryKey: ["events"], queryFn: () => api.events(200), placeholderData: MOCK_EVENTS });
  const events = (raw as typeof MOCK_EVENTS) ?? MOCK_EVENTS;

  const filtered = events.filter(e => {
    if (filter !== "ALL" && e.verdict !== filter) return false;
    if (search && !e.request_id.includes(search) && !e.tenant_id.includes(search) && !(e.threat_type ?? "").toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="flex flex-col min-h-screen">
      <Header title="Security Events" subtitle={`${events.length.toLocaleString()} events`} />
      <div className="p-6 space-y-4 animate-fade-in">
        {/* Toolbar */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative flex-1 min-w-48">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search request ID, tenant, threat..."
              className="w-full pl-8 pr-3 py-2 text-xs rounded-lg bg-surface-3 border border-border text-gray-300 placeholder-gray-600 focus:outline-none focus:border-accent-blue"
            />
          </div>
          <div className="flex items-center gap-1 bg-surface-3 rounded-lg p-0.5 border border-border">
            {VERDICTS.map(v => (
              <button
                key={v}
                onClick={() => setFilter(v)}
                className={cn(
                  "px-3 py-1.5 rounded-md text-xs font-medium transition-colors",
                  filter === v ? "bg-accent-blue text-white" : "text-gray-400 hover:text-white"
                )}
              >
                {v}
              </button>
            ))}
          </div>
        </div>

        {/* Table */}
        <div className="rounded-xl bg-surface-2 border border-border overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border">
                {["Request ID", "Time", "Tenant", "Verdict", "Latency", "Threat Type", ""].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-gray-500 font-medium uppercase tracking-wider text-[10px]">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map(e => (
                <tr
                  key={e.request_id}
                  className="border-b border-border/50 hover:bg-surface-3 cursor-pointer transition-colors"
                  onClick={() => router.push(`/events/${e.request_id}`)}
                >
                  <td className="px-4 py-3 font-mono text-accent-blue">{e.request_id}</td>
                  <td className="px-4 py-3 text-gray-400">{formatDistanceToNow(new Date(e.ts), { addSuffix: true })}</td>
                  <td className="px-4 py-3 text-gray-300">{e.tenant_id}</td>
                  <td className="px-4 py-3"><VerdictBadge verdict={e.verdict} /></td>
                  <td className="px-4 py-3 font-mono text-gray-300">{fmtMs(e.processing_ms)}</td>
                  <td className="px-4 py-3 text-gray-400">{e.threat_type ?? <span className="text-gray-600">—</span>}</td>
                  <td className="px-4 py-3"><ChevronRight size={12} className="text-gray-600" /></td>
                </tr>
              ))}
            </tbody>
          </table>
          {filtered.length === 0 && (
            <div className="text-center py-12 text-gray-600 text-sm">No events match your filter</div>
          )}
        </div>
      </div>
    </div>
  );
}
