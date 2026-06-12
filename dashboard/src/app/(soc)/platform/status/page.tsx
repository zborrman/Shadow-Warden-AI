"use client";
import { useQuery } from "@tanstack/react-query";
import { api, ServiceHealth } from "@/lib/api";
import { RefreshCw, ExternalLink, CheckCircle2, XCircle, AlertTriangle, HelpCircle } from "lucide-react";

const GRAFANA_URL  = process.env.NEXT_PUBLIC_GRAFANA_URL  ?? "http://localhost:3000";
const JAEGER_URL   = process.env.NEXT_PUBLIC_JAEGER_URL   ?? "http://localhost:16686";
const API_URL      = process.env.NEXT_PUBLIC_API_URL      ?? "https://api.shadow-warden-ai.com";

const STATUS_CONFIG = {
  ok:       { color: "#30D158", bg: "rgba(48,209,88,0.12)",   label: "Healthy",  Icon: CheckCircle2 },
  degraded: { color: "#FF9F0A", bg: "rgba(255,159,10,0.12)",  label: "Degraded", Icon: AlertTriangle },
  down:     { color: "#FF2D55", bg: "rgba(255,45,85,0.12)",   label: "Down",     Icon: XCircle },
  unknown:  { color: "#8E8E9E", bg: "rgba(142,142,158,0.10)", label: "Unknown",  Icon: HelpCircle },
  partial:  { color: "#BF5AF2", bg: "rgba(191,90,242,0.12)",  label: "Partial",  Icon: AlertTriangle },
} as const;

const OVERALL_LABELS = {
  ok:       { text: "All Systems Operational", color: "#30D158" },
  degraded: { text: "Partial Degradation",     color: "#FF9F0A" },
  down:     { text: "Service Outage",           color: "#FF2D55" },
  partial:  { text: "Some Services Unknown",    color: "#BF5AF2" },
} as const;

const QUICK_LINKS = [
  { label: "Grafana",     href: GRAFANA_URL,                         desc: "Metrics & dashboards" },
  { label: "Jaeger",      href: JAEGER_URL,                          desc: "Distributed traces"    },
  { label: "API Docs",    href: `${API_URL}/docs`,                   desc: "Swagger / OpenAPI"     },
  { label: "Redoc",       href: "https://docs.shadow-warden-ai.com", desc: "Public API reference"  },
  { label: "MinIO",       href: "http://91.98.234.160:9001",         desc: "Object store console"  },
  { label: "Prometheus",  href: "http://91.98.234.160:9090",         desc: "Raw metrics"           },
];

function ServiceCard({ svc }: { svc: ServiceHealth }) {
  const cfg = STATUS_CONFIG[svc.status as keyof typeof STATUS_CONFIG] ?? STATUS_CONFIG.unknown;
  const { Icon } = cfg;

  return (
    <div
      className="rounded-xl p-4 flex items-start gap-3 border transition-all"
      style={{ borderColor: cfg.color + "30", background: cfg.bg }}
    >
      <Icon size={18} className="shrink-0 mt-0.5" style={{ color: cfg.color }} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between gap-2">
          <span className="text-sm font-semibold text-white truncate">{svc.display}</span>
          <span
            className="text-[10px] font-bold px-1.5 py-0.5 rounded-full shrink-0"
            style={{ background: cfg.color + "20", color: cfg.color }}
          >
            {cfg.label}
          </span>
        </div>
        <p className="text-[11px] text-gray-500 mt-0.5 truncate">{svc.detail}</p>
        {svc.latency_ms !== null && (
          <span className="text-[10px] text-gray-600 font-mono">{svc.latency_ms.toFixed(1)} ms</span>
        )}
      </div>
    </div>
  );
}

export default function StatusPage() {
  const { data, isLoading, error, refetch, isFetching, dataUpdatedAt } = useQuery({
    queryKey: ["deploy_status"],
    queryFn: api.deployStatus,
    refetchInterval: 30_000,
    retry: false,
  });

  const overall = data?.overall ?? "unknown";
  const overallCfg = OVERALL_LABELS[overall as keyof typeof OVERALL_LABELS]
    ?? { text: "Checking…", color: "#8E8E9E" };

  const lastChecked = dataUpdatedAt
    ? new Date(dataUpdatedAt).toLocaleTimeString()
    : "—";

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white">Service Status</h1>
          <p className="text-sm text-gray-400 mt-0.5">
            All 11 Docker services — auto-refreshes every 30 s
          </p>
        </div>
        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold border border-border text-gray-300 hover:text-white hover:bg-white/5 transition-colors disabled:opacity-50"
        >
          <RefreshCw size={12} className={isFetching ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      {/* Overall banner */}
      {!isLoading && data && (
        <div
          className="rounded-2xl px-5 py-4 flex items-center justify-between"
          style={{ background: overallCfg.color + "14", border: `1px solid ${overallCfg.color}30` }}
        >
          <div>
            <span className="text-base font-bold" style={{ color: overallCfg.color }}>
              {overallCfg.text}
            </span>
            <p className="text-xs text-gray-500 mt-0.5">
              {data.ok_count} / {data.total} services healthy · checked {lastChecked}
            </p>
          </div>
          <div
            className="text-2xl font-black tabular-nums"
            style={{ color: overallCfg.color }}
          >
            {data.ok_count}/{data.total}
          </div>
        </div>
      )}

      {/* Error state */}
      {error && !isLoading && (
        <div className="rounded-xl px-5 py-4 border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
          Could not reach <code className="font-mono">/deploy/status</code> — gateway may be down.
        </div>
      )}

      {/* Service grid */}
      {isLoading ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {Array.from({ length: 11 }).map((_, i) => (
            <div key={i} className="h-20 rounded-xl animate-pulse bg-white/5" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {data?.services.map(svc => (
            <ServiceCard key={svc.name} svc={svc} />
          ))}
        </div>
      )}

      {/* Quick links */}
      <div>
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
          External Consoles
        </h2>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
          {QUICK_LINKS.map(link => (
            <a
              key={link.href}
              href={link.href}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center justify-between rounded-xl px-4 py-3 text-sm transition-all hover:-translate-y-0.5 border border-border hover:border-blue-500/30 hover:bg-blue-500/5"
            >
              <div>
                <p className="text-[13px] font-semibold text-white">{link.label}</p>
                <p className="text-[11px] text-gray-500">{link.desc}</p>
              </div>
              <ExternalLink size={12} className="text-gray-600 shrink-0 ml-2" />
            </a>
          ))}
        </div>
      </div>

    </div>
  );
}
