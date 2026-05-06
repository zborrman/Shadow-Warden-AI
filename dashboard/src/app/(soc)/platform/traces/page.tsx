"use client";
import { Header } from "@/components/layout/header";
import { ExternalLink } from "lucide-react";

const JAEGER = process.env.NEXT_PUBLIC_JAEGER_URL ?? "http://91.98.234.160:16686";

export default function TracesPage() {
  return (
    <div className="flex flex-col min-h-screen">
      <Header title="Distributed Traces" subtitle="OpenTelemetry → OTel Collector → Jaeger" />
      <div className="p-6 space-y-4 animate-fade-in">

        <div className="flex items-center justify-between">
          <p className="text-xs text-gray-500">
            Per-layer spans: topology → obfuscation → secret_redactor → semantic_guard → brain → causal_arbiter → phish_guard → ers
          </p>
          <a href={JAEGER} target="_blank" rel="noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-3 border border-border text-xs text-accent-blue hover:border-accent-blue/40 transition-colors">
            <ExternalLink size={12} /> Open Jaeger UI
          </a>
        </div>

        <div className="rounded-xl bg-surface-2 border border-border overflow-hidden">
          <iframe
            src={`${JAEGER}/search?service=shadow-warden&limit=100`}
            width="100%"
            height="700"
            frameBorder="0"
            className="block"
            title="Jaeger Trace Search"
          />
        </div>
      </div>
    </div>
  );
}
