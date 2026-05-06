"use client";
import { useParams, useRouter } from "next/navigation";
import { ArrowLeft, Clock, CheckCircle, XCircle, AlertTriangle } from "lucide-react";
import { Header } from "@/components/layout/header";
import { VerdictBadge } from "@/components/ui/verdict-badge";
import { fmtMs, cn } from "@/lib/utils";
import type { Verdict } from "@/lib/types";

const STAGE_ORDER = ["topology", "obfuscation", "secret_redactor", "semantic_guard", "brain", "causal_arbiter", "phish_guard", "ers", "decision"];

const MOCK_DETAIL = {
  request_id: "req_example",
  ts: new Date().toISOString(),
  tenant_id: "tenant_a",
  verdict: "HIGH" as Verdict,
  processing_ms: 42.3,
  threat_type: "Jailbreak Attempt",
  content_length: 312,
  stages: {
    topology:       { ms: 1.2,  verdict: "PASS",   score: 0.12 },
    obfuscation:    { ms: 0.8,  verdict: "CLEAN",  score: 0 },
    secret_redactor:{ ms: 2.1,  verdict: "CLEAN",  score: 0 },
    semantic_guard: { ms: 3.4,  verdict: "MEDIUM", score: 0.61 },
    brain:          { ms: 18.7, verdict: "HIGH",   score: 0.87 },
    causal_arbiter: { ms: 4.2,  verdict: "HIGH",   score: 0.82 },
    phish_guard:    { ms: 2.9,  verdict: "CLEAN",  score: 0.04 },
    ers:            { ms: 1.1,  verdict: "PASS",   score: 0.31 },
    decision:       { ms: 0.3,  verdict: "HIGH",   score: 0 },
  },
  redacted_secrets: 0,
  ers_score: 0.31,
  shadow_banned: false,
  causal_risk: 0.82,
};

function StageRow({ name, data }: { name: string; data: { ms: number; verdict?: string; score?: number } }) {
  const isBad = ["HIGH", "BLOCK", "MEDIUM"].includes(data.verdict ?? "");
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
  const router = useRouter();
  const { id } = useParams<{ id: string }>();
  const e = { ...MOCK_DETAIL, request_id: id };

  return (
    <div className="flex flex-col min-h-screen">
      <Header title="Event Detail" subtitle={e.request_id} />
      <div className="p-6 space-y-5 animate-fade-in">
        <button onClick={() => router.back()} className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-white transition-colors">
          <ArrowLeft size={13} /> Back to events
        </button>

        {/* Summary */}
        <div className="rounded-xl bg-surface-2 border border-border p-5">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { label: "Verdict",    value: <VerdictBadge verdict={e.verdict} /> },
              { label: "Tenant",     value: <span className="text-sm font-mono text-white">{e.tenant_id}</span> },
              { label: "Latency",    value: <span className="text-sm font-mono text-white">{fmtMs(e.processing_ms)}</span> },
              { label: "Threat",     value: <span className="text-sm text-accent-orange">{e.threat_type ?? "—"}</span> },
              { label: "ERS Score",  value: <span className="text-sm font-mono text-white">{(e.ers_score * 100).toFixed(0)}%</span> },
              { label: "Causal Risk",value: <span className="text-sm font-mono text-accent-red">{(e.causal_risk * 100).toFixed(0)}%</span> },
              { label: "Shadow Ban", value: <span className={cn("text-sm font-semibold", e.shadow_banned ? "text-accent-red" : "text-gray-500")}>{e.shadow_banned ? "YES" : "NO"}</span> },
              { label: "Content Len",value: <span className="text-sm font-mono text-white">{e.content_length} chars</span> },
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
          {STAGE_ORDER.map(s => (
            <StageRow key={s} name={s} data={e.stages[s as keyof typeof e.stages] ?? { ms: 0, verdict: "PASS" }} />
          ))}
        </div>
      </div>
    </div>
  );
}
