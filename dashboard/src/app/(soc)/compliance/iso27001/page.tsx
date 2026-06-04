"use client";
import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { BarChart, Bar, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { Shield, ExternalLink, CheckCircle, AlertTriangle, GitMerge, RefreshCw, Search } from "lucide-react";
import { Header } from "@/components/layout/header";
import { api, type Iso27001Control, type Iso27001Response } from "@/lib/api";
import { cn, fmtNum } from "@/lib/utils";

// ── Constants ─────────────────────────────────────────────────────────────────

const THEMES = ["Organizational", "People", "Physical", "Technological"] as const;
type Theme = typeof THEMES[number];

const THEME_COLOR: Record<Theme, string> = {
  Organizational: "#6366f1",
  People:         "#10b981",
  Physical:       "#f59e0b",
  Technological:  "#ef4444",
};

const STATUS_COLOR: Record<string, string> = {
  Implemented: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
  Partial:     "text-amber-400  bg-amber-500/10  border-amber-500/20",
  Delegated:   "text-blue-400   bg-blue-500/10   border-blue-500/20",
};

const STATUS_ICON: Record<string, React.ElementType> = {
  Implemented: CheckCircle,
  Partial:     AlertTriangle,
  Delegated:   GitMerge,
};

const PERIOD_OPTIONS = [
  { label: "7d",   value: 7   },
  { label: "30d",  value: 30  },
  { label: "90d",  value: 90  },
  { label: "180d", value: 180 },
  { label: "365d", value: 365 },
];

// ── Sub-components ────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const Icon = STATUS_ICON[status] ?? Shield;
  return (
    <span className={cn("flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full border shrink-0", STATUS_COLOR[status])}>
      <Icon size={10} />
      {status}
    </span>
  );
}

function ThemeBar({ theme, data }: { theme: Theme; data: Iso27001Response }) {
  const t      = data.themes[theme];
  const pct    = t.total > 0 ? Math.round(t.implemented / t.total * 100) : 0;
  const color  = THEME_COLOR[theme];
  return (
    <div className="rounded-xl border border-border bg-surface-2 p-4 flex flex-col gap-2">
      <div className="text-xs font-semibold" style={{ color }}>{theme}</div>
      <div className="text-3xl font-black tabular-nums" style={{ color }}>{pct}<span className="text-sm font-normal text-gray-500">%</span></div>
      <div className="h-1.5 rounded-full overflow-hidden bg-white/5">
        <div className="h-full rounded-full transition-all duration-700" style={{ width: `${pct}%`, background: color }} />
      </div>
      <div className="flex gap-3 text-[11px] text-gray-500">
        <span className="text-emerald-400 font-semibold">{t.implemented}✓</span>
        {t.partial  > 0 && <span className="text-amber-400 font-semibold">{t.partial}~</span>}
        {t.delegated > 0 && <span className="text-blue-400 font-semibold">{t.delegated}⇢</span>}
        <span className="ml-auto">{t.total} ctrl</span>
      </div>
    </div>
  );
}

function ControlRow({ ctrl }: { ctrl: Iso27001Control }) {
  const color = THEME_COLOR[ctrl.theme as Theme] ?? "#6b7280";
  return (
    <div className="rounded-lg border border-border bg-surface-2 p-3 hover:border-white/10 transition-colors"
         style={{ borderLeft: `2px solid ${color}` }}>
      <div className="flex items-start gap-2">
        <code className="text-[11px] text-indigo-400 bg-indigo-500/10 px-1.5 py-0.5 rounded font-mono shrink-0">{ctrl.control}</code>
        <span className="text-[13px] font-medium text-white flex-1">{ctrl.domain}</span>
        <StatusBadge status={ctrl.status} />
      </div>
      <p className="text-[11px] text-gray-500 mt-1.5 ml-0 leading-relaxed">{ctrl.evidence}</p>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function Iso27001Page() {
  const [days,        setDays]        = useState(30);
  const [search,      setSearch]      = useState("");
  const [statusFlt,   setStatusFlt]   = useState<string[]>(["Implemented", "Partial", "Delegated"]);
  const [themeFlt,    setThemeFlt]    = useState<string[]>([...THEMES]);
  const [activeTheme, setActiveTheme] = useState<Theme | null>(null);

  const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "https://api.shadow-warden-ai.com";

  const { data, isFetching, dataUpdatedAt, refetch } = useQuery({
    queryKey:        ["iso27001", days],
    queryFn:         () => api.iso27001(days),
    refetchInterval: 0,
    retry:           false,
  });

  const d = data as Iso27001Response | undefined;

  const updatedAt = dataUpdatedAt
    ? new Date(dataUpdatedAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : null;

  const filtered = useMemo(() => {
    if (!d) return [];
    return d.controls.filter(c =>
      statusFlt.includes(c.status) &&
      themeFlt.includes(c.theme) &&
      (!activeTheme || c.theme === activeTheme) &&
      (!search || c.control.toLowerCase().includes(search.toLowerCase()) ||
                  c.domain.toLowerCase().includes(search.toLowerCase()) ||
                  c.evidence.toLowerCase().includes(search.toLowerCase()))
    );
  }, [d, search, statusFlt, themeFlt, activeTheme]);

  const barData = THEMES.map(t => ({
    name:  t.slice(0, 3).toUpperCase(),
    score: d ? Math.round((d.themes[t]?.implemented ?? 0) / Math.max(d.themes[t]?.total ?? 1, 1) * 100) : 0,
    color: THEME_COLOR[t],
  }));

  return (
    <div className="flex flex-col min-h-screen">
      <Header
        title="ISO 27001:2022 Control Mapping"
        subtitle="Annex A — 93 controls mapped to platform capabilities"
      />

      <div className="flex-1 p-6 space-y-6">

        {/* Controls + period + refresh */}
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-1 rounded-lg border border-border bg-surface-2 p-1">
            {PERIOD_OPTIONS.map(opt => (
              <button key={opt.value} onClick={() => setDays(opt.value)}
                className={cn("px-3 py-1.5 text-xs font-medium rounded-md transition-colors",
                  days === opt.value ? "bg-indigo-500 text-white" : "text-gray-400 hover:text-white")}>
                {opt.label}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-2 text-xs text-gray-500">
            {isFetching
              ? <RefreshCw size={12} className="animate-spin text-indigo-400" />
              : <button onClick={() => refetch()} className="flex items-center gap-1 hover:text-white transition-colors">
                  <RefreshCw size={12} /> Refresh
                </button>
            }
            {updatedAt && <span className="text-gray-600">{updatedAt}</span>}
          </div>
        </div>

        {/* Row 1: KPI tiles */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {[
            { label: "Total Controls",  value: fmtNum(d?.controls_total ?? 0), color: "#818cf8" },
            { label: "Implemented",     value: fmtNum(d?.implemented    ?? 0), color: "#4ade80" },
            { label: "Partial",         value: fmtNum(d?.partial        ?? 0), color: "#fb923c" },
            { label: "Delegated",       value: fmtNum(d?.delegated      ?? 0), color: "#60a5fa" },
            { label: "Coverage Score",  value: `${d?.coverage_pct ?? 0}%`,     color: "#818cf8" },
          ].map(k => (
            <div key={k.label} className="rounded-xl border border-border bg-surface-2 p-4 text-center">
              <div className="text-2xl font-black tabular-nums" style={{ color: k.color }}>{k.value}</div>
              <div className="text-[10px] text-gray-500 uppercase tracking-wide mt-1">{k.label}</div>
            </div>
          ))}
        </div>

        {/* Row 2: Theme bars + bar chart */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="grid grid-cols-2 gap-3 lg:col-span-2">
            {THEMES.map(t => d && <ThemeBar key={t} theme={t} data={d} />)}
          </div>
          <div className="rounded-xl border border-border bg-surface-2 p-5 flex flex-col gap-3">
            <div className="text-xs font-semibold tracking-widest uppercase text-gray-500">Implementation rate by theme</div>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={barData} margin={{ top: 4, right: 4, left: -24, bottom: 0 }}>
                <XAxis dataKey="name" tick={{ fontSize: 10, fill: "#6b7280" }} axisLine={false} tickLine={false} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: "#6b7280" }} axisLine={false} tickLine={false} />
                <Tooltip
                  content={({ active, payload }) =>
                    active && payload?.length ? (
                      <div className="rounded-lg px-3 py-2 text-xs border border-border bg-surface-3 shadow-xl">
                        <span className="text-white font-semibold">{payload[0].value}% implemented</span>
                      </div>
                    ) : null
                  }
                />
                <Bar dataKey="score" radius={[4, 4, 0, 0]}>
                  {barData.map((e, i) => <Cell key={i} fill={e.color} fillOpacity={0.85} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Row 3: Controls matrix */}
        <div>
          <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
            <h2 className="text-xs font-semibold tracking-widest uppercase text-gray-500">Controls Matrix</h2>
            <div className="flex items-center gap-2 flex-wrap">
              {/* Theme filter chips */}
              {THEMES.map(t => (
                <button key={t}
                  onClick={() => setActiveTheme(activeTheme === t ? null : t)}
                  className="text-[10px] font-semibold px-2.5 py-1 rounded-full border transition-all"
                  style={{
                    borderColor: THEME_COLOR[t] + (activeTheme === t ? "80" : "30"),
                    color:       activeTheme === t || !activeTheme ? THEME_COLOR[t] : "#4b5563",
                    background:  activeTheme === t ? THEME_COLOR[t] + "18" : "transparent",
                  }}>
                  {t}
                </button>
              ))}
            </div>
          </div>

          {/* Search + status filters */}
          <div className="flex items-center gap-3 mb-3 flex-wrap">
            <div className="relative">
              <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
              <input
                type="text"
                placeholder="Search control or keyword…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="pl-8 pr-3 py-1.5 text-xs rounded-lg border border-border bg-surface-2 text-gray-300 placeholder-gray-600 outline-none focus:border-indigo-500/50 w-56"
              />
            </div>
            {["Implemented", "Partial", "Delegated"].map(s => (
              <button key={s}
                onClick={() => setStatusFlt(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s])}
                className={cn("text-[10px] font-semibold px-2.5 py-1 rounded-full border transition-all",
                  statusFlt.includes(s) ? STATUS_COLOR[s] : "border-border text-gray-600")}>
                {s}
              </button>
            ))}
            <span className="text-[11px] text-gray-600 ml-auto">{filtered.length} / {d?.controls_total ?? 0}</span>
          </div>

          <div className="space-y-1.5">
            {filtered.map(c => <ControlRow key={c.control} ctrl={c} />)}
            {filtered.length === 0 && (
              <div className="text-center py-8 text-gray-500 text-sm">No controls match the current filters.</div>
            )}
          </div>
        </div>

        {/* Row 4: Evidence actions */}
        <div className="rounded-xl border border-border bg-surface-2 p-5">
          <div className="text-xs font-semibold tracking-widest uppercase text-gray-500 mb-4">Evidence &amp; Reports</div>
          <div className="flex flex-wrap gap-3">
            <a href={`${API_URL}/compliance/iso27001/html?days=${days}`} target="_blank" rel="noopener noreferrer"
               className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium text-indigo-400 border border-indigo-500/30 bg-indigo-500/10 hover:bg-indigo-500/20 transition-colors">
              <ExternalLink size={14} /> Print-ready HTML Report
            </a>
            <a href={`${API_URL}/compliance/iso27001?days=${days}`} target="_blank" rel="noopener noreferrer"
               className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium text-gray-400 border border-white/10 bg-white/5 hover:bg-white/10 transition-colors ml-auto">
              <Shield size={14} /> Raw JSON
            </a>
          </div>
          <div className="mt-4 pt-4 border-t border-border text-xs text-gray-500">
            <CheckCircle size={12} className="inline text-emerald-400 mr-1" />
            ISO/IEC 27001:2022 · 93 Annex A controls · Enterprise tier · CP-22
          </div>
        </div>
      </div>
    </div>
  );
}
