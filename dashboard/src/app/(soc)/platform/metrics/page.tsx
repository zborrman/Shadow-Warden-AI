"use client";
import { Header } from "@/components/layout/header";
import { ExternalLink } from "lucide-react";

const GRAFANA = process.env.NEXT_PUBLIC_GRAFANA_URL ?? "http://91.98.234.160:3000";

const PANELS = [
  { title: "P99 Latency",        panelId: 1 },
  { title: "Request Rate",       panelId: 2 },
  { title: "Block Rate",         panelId: 3 },
  { title: "Shadow Ban Rate",    panelId: 4 },
];

export default function MetricsPage() {
  const theme = "dark";
  const base  = `${GRAFANA}/d/shadow-warden/shadow-warden`;

  return (
    <div className="flex flex-col min-h-screen">
      <Header title="Platform Metrics" subtitle="Live Prometheus / Grafana telemetry" />
      <div className="p-6 space-y-5 animate-fade-in">

        {/* Quick-access panels */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {PANELS.map(p => (
            <div key={p.panelId} className="rounded-xl bg-surface-2 border border-border overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-border">
                <p className="text-xs font-medium text-gray-300">{p.title}</p>
                <a
                  href={`${base}?panelId=${p.panelId}&fullscreen`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-gray-600 hover:text-accent-blue transition-colors"
                >
                  <ExternalLink size={12} />
                </a>
              </div>
              <iframe
                src={`${base}?panelId=${p.panelId}&theme=${theme}&orgId=1&refresh=15s`}
                width="100%"
                height="200"
                frameBorder="0"
                className="block"
              />
            </div>
          ))}
        </div>

        {/* Full dashboard embed */}
        <div className="rounded-xl bg-surface-2 border border-border overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-border">
            <p className="text-xs font-medium text-gray-300">Full Grafana Dashboard</p>
            <a href={base} target="_blank" rel="noreferrer"
              className="flex items-center gap-1 text-xs text-accent-blue hover:underline">
              Open in Grafana <ExternalLink size=11 />
            </a>
          </div>
          <iframe
            src={`${base}?theme=${theme}&orgId=1&kiosk&refresh=15s`}
            width="100%"
            height="600"
            frameBorder="0"
            className="block"
          />
        </div>
      </div>
    </div>
  );
}
