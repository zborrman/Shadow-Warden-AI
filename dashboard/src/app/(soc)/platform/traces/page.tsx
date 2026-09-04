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

        {/* Only embed when Jaeger is actually published. With JAEGER empty the
            src collapsed to `/search?service=…`, a RELATIVE path — so the frame
            requested the dashboard's own origin and rendered whatever that
            returned. An empty base does not make an iframe inert; it re-points
            it at yourself. */}
        {jaeger.kind === "link" ? (
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
        ) : (
          <div className="rounded-xl bg-surface-2 border border-border p-5 space-y-2">
            <p className="text-[13px] font-semibold text-white">Jaeger is not published</p>
            <p className="text-xs text-gray-400 leading-relaxed max-w-2xl">
              It is bound to loopback on the host. Open a tunnel with the
              command above — replacing{" "}
              <code className="text-gray-300">&lt;host&gt;</code> with the
              server — or set{" "}
              <code className="text-gray-300">NEXT_PUBLIC_JAEGER_URL</code> at
              build time once a vhost exists.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
