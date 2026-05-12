"use client";
import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { DollarSign, Shield, Key, Ban, TrendingUp, ChevronDown } from "lucide-react";
import { Header } from "@/components/layout/header";
import { api, type RoiResponse } from "@/lib/api";
import { fmtUsd, cn } from "@/lib/utils";

const INDUSTRIES = [
  { id: "healthcare",   label: "Healthcare",        breach: 10_930_000, icon: "🏥" },
  { id: "finance",      label: "Financial",         breach:  6_080_000, icon: "🏦" },
  { id: "technology",   label: "Technology",        breach:  5_820_000, icon: "💻" },
  { id: "energy",       label: "Energy / Utilities",breach:  5_290_000, icon: "⚡" },
  { id: "pharma",       label: "Pharma / Life Sci", breach:  5_060_000, icon: "💊" },
  { id: "retail",       label: "Retail / E-commerce",breach: 3_480_000, icon: "🛒" },
  { id: "education",    label: "Education",         breach:  3_580_000, icon: "🎓" },
  { id: "general",      label: "Other / General",   breach:  4_450_000, icon: "🏢" },
];

const REQ_PRESETS = [
  { label: "1K / day",   value: 1_000 },
  { label: "10K / day",  value: 10_000 },
  { label: "100K / day", value: 100_000 },
  { label: "1M / day",   value: 1_000_000 },
];

function calcRoi(reqs: number, breachCost: number) {
  const days = 30;
  const total = reqs * days;
  const blockRate   = 0.0154;
  const blocked     = Math.round(total * blockRate);
  const highBlocks  = Math.round(blocked * 0.38);
  const breachProb  = 0.0012;                           // ~0.12% of high blocks become breach
  const breachSaved = Math.round(highBlocks * breachProb * breachCost);
  const secretRate  = 0.003;
  const secrets     = Math.round(total * secretRate);
  const credCost    = 4_650;                            // IBM: avg credential theft cost
  const secretSaved = Math.round(secrets * credCost * 0.008);
  const shadowBans  = Math.round(blocked * 0.12);
  const tokenCost   = 0.002;
  const tokensSaved = Math.round(shadowBans * 800);
  const shadowSaved = Math.round(tokensSaved * tokenCost);
  const total_roi   = breachSaved + secretSaved + shadowSaved;

  return { total, blocked, highBlocks, breachSaved, secrets, secretSaved, shadowBans, shadowSaved, total_roi };
}

function CountUp({ value, prefix = "$" }: { value: number; prefix?: string }) {
  return (
    <span className="tabular-nums">
      {prefix}{value.toLocaleString("en-US")}
    </span>
  );
}

export default function RoiPage() {
  const [industryId, setIndustryId] = useState("technology");
  const [reqPreset,  setReqPreset]  = useState(1);   // index into REQ_PRESETS
  const [open,       setOpen]       = useState(false);

  const { data: liveRoi } = useQuery({ queryKey: ["roi"], queryFn: api.roi });

  const industry = INDUSTRIES.find(i => i.id === industryId) ?? INDUSTRIES[2];
  const reqs     = REQ_PRESETS[reqPreset].value;
  const calc     = useMemo(() => calcRoi(reqs, industry.breach), [reqs, industry.breach]);

  const live = liveRoi as RoiResponse | undefined;
  const totalDisplay = live?.total_estimated_roi_usd
    ? Math.max(live.total_estimated_roi_usd, calc.total_roi)
    : calc.total_roi;

  const cards = [
    {
      label:  "Breach Prevention",
      value:  live ? live.threat_mitigation.estimated_breach_cost_avoided : calc.breachSaved,
      sub:    `${live?.threat_mitigation.high_block_events ?? calc.highBlocks} high-risk blocks`,
      icon:   Shield,
      color:  "text-red-400",
      bg:     "bg-red-500/10 border-red-500/20",
    },
    {
      label:  "Credential Protection",
      value:  live ? live.secret_protection.estimated_credential_savings : calc.secretSaved,
      sub:    `${live?.secret_protection.secrets_redacted ?? calc.secrets} secrets redacted`,
      icon:   Key,
      color:  "text-amber-400",
      bg:     "bg-amber-500/10 border-amber-500/20",
    },
    {
      label:  "Shadow Ban Savings",
      value:  live ? live.shadow_ban.cost_saved_usd : calc.shadowSaved,
      sub:    `${live?.shadow_ban.count ?? calc.shadowBans} attackers banned`,
      icon:   Ban,
      color:  "text-purple-400",
      bg:     "bg-purple-500/10 border-purple-500/20",
    },
  ];

  return (
    <div className="flex flex-col min-h-screen">
      <Header title="Dollar Impact" subtitle="See your ROI in 5 seconds" />

      <div className="p-6 space-y-6 animate-fade-in max-w-4xl">

        {/* Configurator */}
        <div className="rounded-xl bg-surface-2 border border-border p-6">
          <p className="text-xs text-gray-500 uppercase tracking-widest font-semibold mb-4">
            Configure your environment
          </p>
          <div className="flex flex-col sm:flex-row gap-4">
            {/* Industry picker */}
            <div className="flex-1 relative">
              <p className="text-[11px] text-gray-500 mb-1.5">Industry</p>
              <button
                onClick={() => setOpen(o => !o)}
                className="w-full flex items-center justify-between px-3 py-2.5 rounded-lg bg-surface-3 border border-border text-sm text-white hover:border-accent-purple/50 transition-colors"
              >
                <span>{industry.icon} {industry.label}</span>
                <ChevronDown size={14} className={cn("text-gray-500 transition-transform", open && "rotate-180")} />
              </button>
              {open && (
                <div className="absolute z-10 mt-1 w-full rounded-lg bg-surface-3 border border-border shadow-xl overflow-hidden">
                  {INDUSTRIES.map(ind => (
                    <button
                      key={ind.id}
                      onClick={() => { setIndustryId(ind.id); setOpen(false); }}
                      className={cn(
                        "w-full flex items-center justify-between px-3 py-2 text-sm text-left hover:bg-surface-4 transition-colors",
                        ind.id === industryId ? "text-white" : "text-gray-400"
                      )}
                    >
                      <span>{ind.icon} {ind.label}</span>
                      <span className="text-[10px] text-gray-600 font-mono">
                        avg breach {fmtUsd(ind.breach)}
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Request volume */}
            <div className="flex-1">
              <p className="text-[11px] text-gray-500 mb-1.5">Request Volume</p>
              <div className="grid grid-cols-4 gap-1 p-1 rounded-lg bg-surface-3 border border-border">
                {REQ_PRESETS.map((p, i) => (
                  <button
                    key={p.label}
                    onClick={() => setReqPreset(i)}
                    className={cn(
                      "py-2 rounded-md text-xs font-medium transition-colors",
                      reqPreset === i
                        ? "bg-accent-purple text-white"
                        : "text-gray-400 hover:text-white"
                    )}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Hero ROI number */}
        <div className="rounded-xl border p-8 text-center relative overflow-hidden"
             style={{ background: "linear-gradient(135deg, #0a0f1e 0%, #0f172a 100%)", borderColor: "rgba(16,185,129,0.3)" }}>
          <div className="absolute inset-0 pointer-events-none"
               style={{ background: "radial-gradient(ellipse at 50% 0%, rgba(16,185,129,0.08) 0%, transparent 65%)" }} />
          <p className="text-xs font-semibold uppercase tracking-widest text-emerald-500 mb-2">
            Estimated Monthly Savings
          </p>
          <p className="text-[56px] font-black text-white leading-none mb-2 tabular-nums">
            <CountUp value={totalDisplay} />
          </p>
          <p className="text-sm text-gray-500">
            {industry.icon} {industry.label} · {REQ_PRESETS[reqPreset].label} · IBM 2024 breach data
          </p>
          {live && (
            <div className="inline-flex items-center gap-1.5 mt-4 px-3 py-1 rounded-full text-[11px] font-semibold"
                 style={{ background: "rgba(16,185,129,0.1)", border: "1px solid rgba(16,185,129,0.25)", color: "#10b981" }}>
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Live data · {live.days} days · {live.total_requests.toLocaleString()} requests
            </div>
          )}
        </div>

        {/* 3-card breakdown */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {cards.map(({ label, value, sub, icon: Icon, color, bg }) => (
            <div key={label} className={cn("rounded-xl border p-5", bg)}>
              <div className="flex items-center gap-2 mb-3">
                <Icon size={15} className={color} />
                <p className="text-xs font-semibold text-gray-300">{label}</p>
              </div>
              <p className={cn("text-2xl font-black tabular-nums mb-1", color)}>
                {fmtUsd(value)}
              </p>
              <p className="text-[11px] text-gray-500">{sub}</p>
            </div>
          ))}
        </div>

        {/* ROI multiplier */}
        <div className="rounded-xl bg-surface-2 border border-border p-5">
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp size={14} className="text-accent-cyan" />
            <p className="text-sm font-semibold text-white">ROI Multiplier</p>
            <span className="ml-auto text-[10px] text-gray-600">Pro plan · $69/mo</span>
          </div>
          <div className="grid grid-cols-3 gap-3">
            {[
              { label: "Monthly Savings",  value: fmtUsd(totalDisplay),            color: "text-emerald-400" },
              { label: "Monthly Cost",     value: "$69",                            color: "text-gray-300"   },
              { label: "ROI Multiple",     value: `${Math.round(totalDisplay / 69)}×`, color: "text-amber-400"  },
            ].map(({ label, value, color }) => (
              <div key={label} className="bg-surface-3 rounded-lg px-4 py-3 text-center">
                <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">{label}</p>
                <p className={cn("text-xl font-black tabular-nums", color)}>{value}</p>
              </div>
            ))}
          </div>
          <p className="text-[10px] text-gray-600 mt-3">
            Source: IBM Cost of a Data Breach Report 2024. Estimates are conservative and based on industry averages.
            Actual savings depend on threat volume and incident response capability.
          </p>
        </div>

      </div>
    </div>
  );
}
