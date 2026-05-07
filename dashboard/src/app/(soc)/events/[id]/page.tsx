"use client";
import { useParams, useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Clock, CheckCircle, AlertTriangle } from "lucide-react";
import { Header } from "@/components/layout/header";
import { VerdictBadge } from "@/components/ui/verdict-badge";
import { CommunityRecommendations } from "@/components/ui/community-recommendations";
import { fmtMs, cn } from "@/lib/utils";
import { api, type EventEntry } from "@/lib/api";
import type { Verdict } from "@/lib/types";

const STAGE_ORDER = ["topology", "obfuscation", "secret_redactor", "semantic_guard", "brain", "causal_arbiter", "phish_guard", "ers", "decision"];

type StageData = { ms: number; verdict?: string; score?: number };
type XaiStages = Record<string, { latency_ms?: number; verdict?: string; score?: number }>;

function toVerdict(e: EventEntry): Verdict {
  if (e.allowed) return "ALLOW";
  const rl = (e.risk_level ?? "").toUpperCase();
  return (["BLOCK", "HIGH", "MEDIUM"].includes(rl) ? rl : "BLOCK") as Verdict;
}

function buildStages(xai: Record<string, unknown> | undefined): Record<string, StageData> {
  const raw = (xai?.stages ?? {}) as XaiStages;
  const out: Record<string, StageData> = {};
  for (const s of STAGE_ORDER) {
    const d = raw[s];
    out[s] = { ms: d?.latency_ms ?? 0, verdict: d?.verdict, score: d?.score };
  }
  return out;
}

function StageRow({ name, data }: { name: string; data: StageData }) {
  const isBad = ["HIGH", "BLOCK", "MEDIUM", "FLAG"].includes((data.verdict ?? "").toUpperCase());
  return (
    <div className="flex items-center gap-4 py-2.5 border-b border-border/50 text-xs">
      <div className="w-36 flex items-center gap-2 shrink-0">
        {isBad
          ? <AlertTriangle size={12} className="text-accent-yellow shrink-0" />
          : <CheckCircle   size={12} className="text-accent-green  shrink-0" />}
        <span className="font-mono text-gray-300">{name}</span>
      </div>
      <VerdictBadge verdict={(data.verdict ?? "ALLOW") as Verdict} />
      <span className="text-gray-500 font-mono">{fmtMs(data.ms)}</span>
      {data.score !== undefined && data.score > 0 && (
        <div className="flex items-center gap-2 ml-auto">
          <div className="w-24 h-1.5 rounded-full bg-surface-4 overflow-hidden">
            <div
              className={cn("h-full rounded-full", data.score > 0.7 ? "bg-accent-red" : data.score > 0.4 ? "bg-accent-yellow" : "bg-accent-green")}
              style={{ width: `${data.score * 100}%` }}
            />
          </div>
          <span className="text-gray-500 w-8 text-right">{(data.score * 100).toFixed(0)}%</span>
        </div>
      )}
    </div>
  );
}

export default function EventDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router  = useRouter();

  const { data: event } = useQuery<EventEntry>({
    queryKey: ["event", id],
    queryFn:  () => api.event(id),
    retry: false,
  });

  const { data: xai } = useQuery<Record<string, unknown>>({
    queryKey: ["xai", id],
    queryFn:  () => api.xaiExplain(id),
    enabled:  !!event,
    retry: false,
  });

  if (!event) {
    return (
      <div className="flex flex-col min-h-screen">
        <Header title="Event Detail" subtitle={id} />
        <div className="p-6 flex items-center justify-center flex-1">
          <p className="text-gray-600 text-sm">Loading event…</p>
        </div>
      </div>
    );
  }

  const verdict = toVerdict(event);
  const stages  = buildStages(xai);
  const threadType = event.flags[0] ?? null;

  return (
    <div className="flex flex-col min-h-screen">
      <Header title="Event Detail" subtitle={event.request_id} />
      <div className="p-6 space-y-5 animate-fade-in">
        <button onClick={() => router.back()} className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-white transition-colors">
          <ArrowLeft size={13} /> Back to events
        </button>

        {/* Summary */}
        <div className="rounded-xl bg-surface-2 border border-border p-5">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { label: "Verdict",      value: <VerdictBadge verdict={verdict} /> },
              { label: "Tenant",       value: <span className="text-sm font-mono text-white">{event.tenant_id}</span> },
              { label: "Latency",      value: <span className="text-sm font-mono text-white">{fmtMs(event.elapsed_ms)}</span> },
              { label: "Threat Flags", value: <span className="text-sm text-accent-orange">{threadType ?? "—"}</span> },
              { label: "Secrets",      value: <span className="text-sm font-mono text-white">{event.secrets_found.length}</span> },
              { label: "Risk Level",   value: <span className="text-sm font-mono text-white">{event.risk_level}</span> },
              { label: "Allowed",      value: <span className={cn("text-sm font-semibold", event.allowed ? "text-accent-green" : "text-accent-red")}>{event.allowed ? "YES" : "NO"}</span> },
              { label: "Content Len",  value: <span className="text-sm font-mono text-white">{event.content_length ?? "—"} chars</span> },
            ].map(({ label, value }) => (
              <div key={label}>
                <p className="text-[10px] uppercase tracking-wider text-gray-500 mb-1">{label}</p>
                {value}
              </div>
            ))}
          </div>
        </div>

        {/* Pipeline stages */}
        <div className="rounded-xl bg-surface-2 border border-border p-5">
          <p className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <Clock size={14} className="text-accent-purple" /> Pipeline Execution
          </p>
          {xai ? (
            STAGE_ORDER.map(s => <StageRow key={s} name={s} data={stages[s]} />)
          ) : (
            <p className="text-xs text-gray-600">XAI data unavailable — enable OTEL_ENABLED and XAI add-on for per-stage breakdown.</p>
          )}
        </div>

        {/* Flags */}
        {event.flags.length > 0 && (
          <div className="rounded-xl bg-surface-2 border border-border p-5">
            <p className="text-sm font-semibold text-white mb-3">Detected Flags</p>
            <div className="flex flex-wrap gap-2">
              {event.flags.map(f => (
                <span key={f} className="px-2 py-1 rounded-md bg-accent-red/10 border border-accent-red/20 text-accent-red text-xs font-mono">{f}</span>
              ))}
            </div>
          </div>
        )}

        {/* Community recommendations — only for blocked/high-risk events */}
        {!event.allowed && event.flags.length > 0 && (
          <CommunityRecommendations flags={event.flags} riskLevel={event.risk_level} />
        )}
      </div>
    </div>
  );
}
