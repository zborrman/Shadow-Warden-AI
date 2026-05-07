"use client";

import { useState, useMemo } from "react";
import { cn } from "@/lib/utils";
import { Check, Zap, Building2, Shield, Lock } from "lucide-react";

// ── Types ─────────────────────────────────────────────────────────────────────

type Tier = "starter" | "individual" | "community_business" | "pro" | "enterprise";
type Billing = "monthly" | "annual";

interface TierConfig {
  id: Tier;
  label: string;
  monthlyPrice: number;
  annualPrice: number | null;
  requests: string;
  description: string;
  icon: React.ElementType;
  highlight?: boolean;
  trialEligible?: boolean;
  features: string[];
}

interface Addon {
  key: string;
  label: string;
  price: number;
  minTier: Tier;
  description: string;
}

interface Bundle {
  key: string;
  label: string;
  price: number;
  fullPrice: number;
  savings: number;
  minTier: Tier;
  includes: string[];
}

// ── Data ──────────────────────────────────────────────────────────────────────

const TIERS: TierConfig[] = [
  {
    id: "starter",
    label: "Starter",
    monthlyPrice: 0,
    annualPrice: null,
    requests: "1,000 req/mo",
    description: "Try the full filter pipeline",
    icon: Zap,
    features: ["9-layer filter", "Analytics dashboard", "Community access", "Docker self-host"],
  },
  {
    id: "individual",
    label: "Individual",
    monthlyPrice: 5,
    annualPrice: 51,
    requests: "5,000 req/mo",
    description: "Solo devs & consultants",
    icon: Shield,
    trialEligible: true,
    features: ["Everything in Starter", "Audit trail", "XAI add-on eligible", "Secrets Vault add-on", "14-day Pro trial"],
  },
  {
    id: "community_business",
    label: "Community Business",
    monthlyPrice: 19,
    annualPrice: 194,
    requests: "10,000 req/mo",
    description: "SMB teams & security communities",
    icon: Building2,
    trialEligible: true,
    features: [
      "Everything in Individual",
      "File Scanner (DOCX/XLSX)",
      "Shadow AI Monitor",
      "3 communities × 10 members",
      "180-day retention",
      "Secrets Governance",
    ],
  },
  {
    id: "pro",
    label: "Pro",
    monthlyPrice: 69,
    annualPrice: 703,
    requests: "50,000 req/mo",
    description: "Mid-market & growing teams",
    icon: Shield,
    highlight: true,
    features: [
      "Everything in Community Business",
      "MasterAgent SOC (included)",
      "Causal XAI reports",
      "Multi-tenant (up to 50)",
      "SIEM (Splunk + Elastic)",
      "Slack / PagerDuty alerts",
      "Overage billing ($0.50/1k)",
    ],
  },
  {
    id: "enterprise",
    label: "Enterprise",
    monthlyPrice: 249,
    annualPrice: 2541,
    requests: "Unlimited",
    description: "MSPs & regulated enterprises",
    icon: Lock,
    features: [
      "Everything in Pro",
      "Post-Quantum Crypto (ML-DSA-65)",
      "Sovereign AI Cloud (8 jurisdictions)",
      "BYOK + White-label",
      "On-prem deployment",
      "Dedicated support & SLA",
      "All add-ons included",
    ],
  },
];

const ADDONS: Addon[] = [
  { key: "xai_audit",          label: "XAI Audit Reports",      price: 9,  minTier: "individual",         description: "HTML + PDF causal chain reports" },
  { key: "secrets_vault",      label: "Secrets Vault",          price: 12, minTier: "individual",         description: "AWS SM / Azure KV / HashiCorp governance" },
  { key: "shadow_ai_discovery",label: "Shadow AI Discovery",    price: 15, minTier: "pro",                description: "Subnet probe + DNS telemetry, 18 providers" },
  { key: "on_prem_pack",       label: "On-Prem Deployment",     price: 29, minTier: "pro",                description: "Self-hosted license + Helm chart" },
  { key: "community_seats",    label: "Community Seats (+5)",   price: 9,  minTier: "community_business", description: "Add 5 member slots (stackable)" },
];

const BUNDLES: Bundle[] = [
  {
    key: "power_user_bundle",
    label: "Power User Bundle",
    price: 29,
    fullPrice: 36,
    savings: 7,
    minTier: "pro",
    includes: ["secrets_vault", "xai_audit", "shadow_ai_discovery"],
  },
];

const TIER_ORDER: Record<Tier, number> = {
  starter: 0, individual: 1, community_business: 2, pro: 3, enterprise: 4,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function tierMeets(current: Tier, required: Tier): boolean {
  return TIER_ORDER[current] >= TIER_ORDER[required];
}

function formatPrice(usd: number | null, billing: Billing): string {
  if (usd === null) return "Custom";
  if (usd === 0) return "Free";
  if (billing === "annual" && usd > 12) {
    const mo = Math.round((usd / 12) * 100) / 100;
    return `$${mo.toFixed(2)}/mo`;
  }
  return `$${usd}/mo`;
}

// ── Subcomponents ─────────────────────────────────────────────────────────────

function TierCard({
  tier, selected, billing, onClick,
}: { tier: TierConfig; selected: boolean; billing: Billing; onClick: () => void }) {
  const price = billing === "annual" && tier.annualPrice ? tier.annualPrice : tier.monthlyPrice * 12 || tier.monthlyPrice;
  const displayPrice = billing === "annual" && tier.annualPrice
    ? `$${(tier.annualPrice / 12).toFixed(2)}/mo`
    : tier.monthlyPrice === 0 ? "Free" : `$${tier.monthlyPrice}/mo`;
  const Icon = tier.icon;

  return (
    <button
      onClick={onClick}
      className={cn(
        "relative text-left rounded-xl border p-4 transition-all",
        selected
          ? "border-accent-purple bg-accent-purple/10 ring-1 ring-accent-purple"
          : "border-border bg-surface-2 hover:border-accent-purple/40",
        tier.highlight && !selected && "border-accent-blue/30",
      )}
    >
      {tier.highlight && (
        <span className="absolute -top-2.5 left-4 text-[10px] font-bold px-2 py-0.5 rounded-full bg-accent-blue text-white uppercase tracking-wide">
          Most popular
        </span>
      )}
      <div className="flex items-center gap-2 mb-2">
        <Icon size={14} className={selected ? "text-accent-purple" : "text-gray-400"} />
        <span className={cn("text-sm font-semibold", selected ? "text-white" : "text-gray-300")}>{tier.label}</span>
      </div>
      <p className="text-xl font-bold text-white">{displayPrice}</p>
      {billing === "annual" && tier.annualPrice && (
        <p className="text-[10px] text-accent-green mt-0.5">${tier.annualPrice}/yr · save 15%</p>
      )}
      <p className="text-[10px] text-gray-500 mt-1">{tier.requests}</p>
    </button>
  );
}

function AddonRow({
  addon, active, eligible, onToggle,
}: { addon: Addon; active: boolean; eligible: boolean; onToggle: () => void }) {
  return (
    <label className={cn(
      "flex items-center justify-between p-3 rounded-lg border cursor-pointer transition-all",
      !eligible && "opacity-40 cursor-not-allowed",
      active ? "border-accent-purple/50 bg-accent-purple/5" : "border-border bg-surface-2 hover:border-border/80",
    )}>
      <div className="flex items-center gap-3">
        <input
          type="checkbox"
          checked={active}
          disabled={!eligible}
          onChange={onToggle}
          className="accent-purple-500 w-4 h-4"
        />
        <div>
          <p className="text-sm font-medium text-gray-200">{addon.label}</p>
          <p className="text-xs text-gray-500">{addon.description}</p>
          {!eligible && (
            <p className="text-[10px] text-accent-yellow mt-0.5">
              Requires {addon.minTier.replace("_", " ")} plan
            </p>
          )}
        </div>
      </div>
      <span className="text-sm font-semibold text-accent-green whitespace-nowrap ml-4">
        +${addon.price}/mo
      </span>
    </label>
  );
}

function BundleCard({
  bundle, active, eligible, onToggle, selectedAddons,
}: { bundle: Bundle; active: boolean; eligible: boolean; onToggle: () => void; selectedAddons: Set<string> }) {
  const alreadyHasAll = bundle.includes.every(k => selectedAddons.has(k));
  return (
    <label className={cn(
      "flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-all",
      !eligible && "opacity-40 cursor-not-allowed",
      active ? "border-accent-green/50 bg-accent-green/5" : "border-border bg-surface-2 hover:border-border/80",
    )}>
      <input
        type="checkbox"
        checked={active}
        disabled={!eligible}
        onChange={onToggle}
        className="accent-green-500 w-4 h-4 mt-0.5"
      />
      <div className="flex-1">
        <div className="flex items-center justify-between">
          <p className="text-sm font-semibold text-gray-200">{bundle.label}</p>
          <div className="text-right">
            <span className="text-sm font-bold text-accent-green">${bundle.price}/mo</span>
            <span className="text-xs text-gray-500 line-through ml-2">${bundle.fullPrice}</span>
          </div>
        </div>
        <p className="text-xs text-accent-green font-medium mt-0.5">Save ${bundle.savings}/mo vs buying separately</p>
        <p className="text-xs text-gray-500 mt-1">
          Includes: {bundle.includes.map(k => ADDONS.find(a => a.key === k)?.label).filter(Boolean).join(" + ")}
        </p>
        {alreadyHasAll && !active && (
          <p className="text-[10px] text-accent-yellow mt-1">You already selected all components — use bundle to save</p>
        )}
      </div>
    </label>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export function PricingCalculator() {
  const [selectedTier, setSelectedTier] = useState<Tier>("pro");
  const [billing, setBilling] = useState<Billing>("monthly");
  const [selectedAddons, setSelectedAddons] = useState<Set<string>>(new Set());
  const [selectedBundles, setSelectedBundles] = useState<Set<string>>(new Set());

  const tier = TIERS.find(t => t.id === selectedTier)!;

  function toggleAddon(key: string) {
    setSelectedAddons(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }

  function toggleBundle(key: string) {
    const bundle = BUNDLES.find(b => b.key === key)!;
    setSelectedBundles(prev => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
        // remove individual addons covered by bundle
        setSelectedAddons(prev2 => {
          const next2 = new Set(prev2);
          bundle.includes.forEach(k => next2.delete(k));
          return next2;
        });
      }
      return next;
    });
  }

  const total = useMemo(() => {
    const baseMonthly = tier.monthlyPrice;
    const addonMonthly = Array.from(selectedAddons).reduce((sum, k) => {
      const addon = ADDONS.find(a => a.key === k);
      return sum + (addon ? addon.price : 0);
    }, 0);
    const bundleMonthly = Array.from(selectedBundles).reduce((sum, k) => {
      const bundle = BUNDLES.find(b => b.key === k);
      return sum + (bundle ? bundle.price : 0);
    }, 0);
    const monthly = baseMonthly + addonMonthly + bundleMonthly;
    const annual  = billing === "annual"
      ? (tier.annualPrice ?? baseMonthly * 12) + (addonMonthly + bundleMonthly) * 12 * (1 - 0.15)
      : monthly;
    return { monthly, annual };
  }, [selectedTier, selectedAddons, selectedBundles, billing, tier]);

  const eligible = (minTier: Tier) => tierMeets(selectedTier, minTier);

  // Bundles available only when NOT all components already selected individually
  const bundleDisplayAddons = new Set([
    ...Array.from(selectedAddons),
    ...Array.from(selectedBundles).flatMap(k => BUNDLES.find(b => b.key === k)?.includes ?? []),
  ]);

  return (
    <div className="rounded-2xl bg-surface-1 border border-border p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-bold text-white">Pricing Calculator</h3>
          <p className="text-sm text-gray-500 mt-0.5">Build your exact plan — tier + add-ons</p>
        </div>

        {/* Billing toggle */}
        <div className="flex items-center gap-1 bg-surface-2 rounded-lg p-1 border border-border">
          {(["monthly", "annual"] as Billing[]).map(b => (
            <button
              key={b}
              onClick={() => setBilling(b)}
              className={cn(
                "px-3 py-1.5 rounded-md text-xs font-semibold transition-all capitalize",
                billing === b ? "bg-accent-purple text-white" : "text-gray-400 hover:text-gray-200",
              )}
            >
              {b}
              {b === "annual" && <span className="ml-1 text-accent-green">−15%</span>}
            </button>
          ))}
        </div>
      </div>

      {/* Tier selector */}
      <div>
        <p className="text-xs text-gray-500 uppercase tracking-wider mb-3 font-semibold">Select Plan</p>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
          {TIERS.map(t => (
            <TierCard key={t.id} tier={t} selected={selectedTier === t.id} billing={billing} onClick={() => setSelectedTier(t.id)} />
          ))}
        </div>
      </div>

      {/* Features */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-1">
        {tier.features.map(f => (
          <div key={f} className="flex items-center gap-2 text-xs text-gray-400">
            <Check size={11} className="text-accent-green shrink-0" />
            {f}
          </div>
        ))}
        {tier.trialEligible && (
          <div className="flex items-center gap-2 text-xs text-accent-yellow">
            <Zap size={11} className="shrink-0" />
            14-day Pro trial available
          </div>
        )}
      </div>

      {/* Bundles */}
      <div>
        <p className="text-xs text-gray-500 uppercase tracking-wider mb-3 font-semibold">Bundles</p>
        <div className="space-y-2">
          {BUNDLES.map(b => (
            <BundleCard
              key={b.key}
              bundle={b}
              active={selectedBundles.has(b.key)}
              eligible={eligible(b.minTier)}
              onToggle={() => toggleBundle(b.key)}
              selectedAddons={selectedAddons}
            />
          ))}
        </div>
      </div>

      {/* Add-ons */}
      <div>
        <p className="text-xs text-gray-500 uppercase tracking-wider mb-3 font-semibold">Add-ons</p>
        <div className="space-y-2">
          {ADDONS.filter(a => !Array.from(selectedBundles).some(bk =>
            BUNDLES.find(b => b.key === bk)?.includes.includes(a.key)
          )).map(a => (
            <AddonRow
              key={a.key}
              addon={a}
              active={selectedAddons.has(a.key)}
              eligible={eligible(a.minTier)}
              onToggle={() => toggleAddon(a.key)}
            />
          ))}
        </div>
      </div>

      {/* Total */}
      <div className="rounded-xl bg-surface-2 border border-border p-4 flex items-center justify-between">
        <div>
          <p className="text-xs text-gray-500 uppercase tracking-wider font-semibold">Total</p>
          {billing === "annual" ? (
            <>
              <p className="text-2xl font-bold text-white">${(total.annual / 12).toFixed(2)}<span className="text-sm text-gray-500">/mo</span></p>
              <p className="text-xs text-accent-green">${total.annual.toFixed(0)}/year · billed annually</p>
            </>
          ) : (
            <p className="text-2xl font-bold text-white">${total.monthly}<span className="text-sm text-gray-500">/mo</span></p>
          )}
        </div>
        <a
          href={selectedTier === "enterprise"
            ? "mailto:sales@shadow-warden-ai.com?subject=Enterprise inquiry"
            : `/billing/upgrade?plan=${selectedTier}`}
          className="px-5 py-2.5 rounded-lg bg-accent-purple text-white text-sm font-semibold hover:bg-accent-purple/80 transition-colors"
        >
          {selectedTier === "enterprise" ? "Contact Sales" : selectedTier === "starter" ? "Start Free" : "Get Started"}
        </a>
      </div>
    </div>
  );
}
