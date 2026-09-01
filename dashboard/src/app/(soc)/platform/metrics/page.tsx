"use client";
import { Header } from "@/components/layout/header";
import { ExternalLink, Terminal } from "lucide-react";
import {
  GRAFANA_URL,
  grafanaDashboardHref,
  grafanaPanelHref,
  internalLink,
} from "@/lib/internal-links";

/**
 * Panels on the provisioned `shadow-warden-overview` dashboard.
 *
 * Every field here is checked against grafana/dashboards/warden_overview.json
 * by warden/tests/test_dashboard_links_resolve.py — id AND title. The previous
 * list was wrong in every row: it labelled panel 1 "P99 Latency" (it is
 * "Requests / min"), panel 2 "Request Rate" (it is "Block Rate"), panel 3
 * "Block Rate" (it is "p95 Latency"), and panel 4 "Shadow Ban Rate", which is
 * not a panel that exists on any dashboard in this repo. Nothing caught it
 * because nothing compared the two files.
 */
const PANELS: ReadonlyArray<{ id: number; title: string }> = [
  { id: 60, title: "SLO — /filter pipeline latency (P50 / P99 / P99.9)" },
  { id: 4, title: "Request Rate — /filter" },
  { id: 2, title: "Block Rate" },
  { id: 21, title: "Fail-open Bypasses (24h)" },
];

export default function MetricsPage() {
  const link = internalLink("Grafana", GRAFANA_URL);

  return (
    <div className="flex flex-col min-h-screen">
      <Header title="Platform Metrics" subtitle="Live Prometheus / Grafana telemetry" />
      <div className="p-6 space-y-5 animate-fade-in">

        {link.kind === "tunnel" ? (
          <div className="rounded-xl bg-surface-2 border border-border p-5 space-y-3">
            <div className="flex items-center gap-2">
              <Terminal size={14} className="text-gray-400 shrink-0" />
              <p className="text-[13px] font-semibold text-white">
                Grafana is not published
              </p>
            </div>
            <p className="text-xs text-gray-400 leading-relaxed max-w-2xl">
              It is bound to loopback on the host, so it holds every datasource
              credential and the whole alerting configuration behind the origin
              firewall rather than in front of it. Reach it over a tunnel, or
              set <code className="text-gray-300">NEXT_PUBLIC_GRAFANA_URL</code>{" "}
              at build time once the vhost behind Cloudflare Access exists.
            </p>
            <pre className="text-[11px] text-gray-300 bg-black/30 rounded-lg px-3 py-2 overflow-x-auto">
              {link.command}
            </pre>
            <p className="text-[11px] text-gray-600">
              A template — substitute <code>&lt;host&gt;</code> with the server
              before running it.
            </p>
          </div>
        ) : (
          <>
            {/* Panels are linked, not embedded. Grafana ships
                `allow_embedding = false` and this deployment does not override
                it, so an <iframe> renders nothing at all — which is what the
                four iframes on this page did for their whole life. Turning
                embedding on would mean anonymous access or a shared session
                cookie for a service holding every datasource credential; that
                is a security decision, not a layout fix. */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {PANELS.map(panel => (
                <a
                  key={panel.id}
                  href={grafanaPanelHref(panel.id)}
                  target="_blank"
                  rel="noreferrer"
                  className="rounded-xl bg-surface-2 border border-border px-4 py-3 flex items-center justify-between transition-all hover:-translate-y-0.5 hover:border-blue-500/30 hover:bg-blue-500/5"
                >
                  <div>
                    <p className="text-[13px] font-semibold text-white">{panel.title}</p>
                    <p className="text-[11px] text-gray-500">Panel {panel.id}</p>
                  </div>
                  <ExternalLink size={12} className="text-gray-600 shrink-0 ml-2" />
                </a>
              ))}
            </div>

            <div className="rounded-xl bg-surface-2 border border-border px-4 py-3">
              <a
                href={grafanaDashboardHref()}
                target="_blank"
                rel="noreferrer"
                className="flex items-center justify-between"
              >
                <div>
                  <p className="text-[13px] font-semibold text-white">
                    Shadow Warden — Overview
                  </p>
                  <p className="text-[11px] text-gray-500">
                    All 41 panels, in Grafana
                  </p>
                </div>
                <ExternalLink size={12} className="text-gray-600 shrink-0 ml-2" />
              </a>
            </div>
          </>
        )}

      </div>
    </div>
  );
}
