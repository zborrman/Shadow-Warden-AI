"use client";
import { Header } from "@/components/layout/header";
import { ExternalLink, Terminal } from "lucide-react";
import { JAEGER_URL, internalLink } from "@/lib/internal-links";

// OB-F21: was `?? "http://91.98.234.160:16686"`. Jaeger is bound to 127.0.0.1
// on the host, so that literal was a dead link and the iframe below it was a
// blank box. `internalLink` renders the tunnel command instead when the
// service has no published URL.
const jaeger = internalLink("Jaeger", JAEGER_URL);
const JAEGER = jaeger.kind === "link" ? jaeger.href : "";

export default function TracesPage() {
  return (
    <div className="flex flex-col min-h-screen">
      <Header title="Distributed Traces" subtitle="OpenTelemetry → OTel Collector → Jaeger" />
      <div className="p-6 space-y-4 animate-fade-in">

        <div className="flex items-center justify-between">
          <p className="text-xs text-gray-500">
            Per-layer spans: topology → obfuscation → secret_redactor → semantic_guard → brain → causal_arbiter → phish_guard → ers
          </p>
          {jaeger.kind === "link" ? (
            <a href={jaeger.href} target="_blank" rel="noreferrer"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-3 border border-border text-xs text-accent-blue hover:border-accent-blue/40 transition-colors">
              <ExternalLink size={12} /> Open Jaeger UI
            </a>
          ) : (
            <span title={jaeger.command}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-black/20 border border-border/60 text-[11px] text-gray-500 font-mono">
              <Terminal size={12} /> {jaeger.command}
            </span>
          )}
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
