"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { ChevronRight, ChevronLeft, Check, Upload, Tag, Globe, Layers } from "lucide-react";

const STEPS = [
  { id: 1, label: "Asset Type" },
  { id: 2, label: "Content" },
  { id: 3, label: "Pricing" },
  { id: 4, label: "Chain" },
  { id: 5, label: "Review" },
];

const ASSET_TYPES = [
  { value: "detection_rule",  label: "Detection Rule",   desc: "YARA / Sigma / custom regex jailbreak rule",  icon: "🛡" },
  { value: "semantic_model",  label: "Semantic Model",   desc: "MiniLM fine-tuned threat corpus bundle",       icon: "🧠" },
  { value: "signal_bundle",   label: "Signal Bundle",    desc: "OSINT threat intel feed or IoC list",          icon: "📡" },
  { value: "threat_intel",    label: "Threat Intel",     desc: "Structured threat intelligence report (STIX)", icon: "🔍" },
];

const CHAINS = [
  { value: "sepolia",         label: "Sepolia Testnet",  desc: "Ethereum L1 testnet (free gas)",  icon: "⟠" },
  { value: "polygon_amoy",    label: "Polygon Amoy",     desc: "Low-cost L2 testnet",              icon: "Ⓟ" },
  { value: "arbitrum_sepolia",label: "Arbitrum Sepolia", desc: "Optimistic rollup testnet",        icon: "🔵" },
];

const PRICING_STRATEGIES = [
  { value: "fixed",          label: "Fixed Price",       desc: "Set a single price; buyer pays it immediately" },
  { value: "demand_based",   label: "Demand-Based",      desc: "Price adjusts dynamically with demand" },
  { value: "auction",        label: "Sealed Auction",    desc: "Highest bid wins after 24h" },
];

type FormState = {
  asset_type:        string;
  name:              string;
  description:       string;
  content:           string;
  pricing_strategy:  string;
  price_usd:         string;
  chain:             string;
};

const EMPTY: FormState = {
  asset_type: "", name: "", description: "", content: "",
  pricing_strategy: "fixed", price_usd: "", chain: "sepolia",
};

export default function NewListingPage() {
  const router = useRouter();
  const [step, setStep]       = useState(1);
  const [form, setForm]       = useState<FormState>(EMPTY);
  const [submitting, setSub]  = useState(false);
  const [error, setError]     = useState<string | null>(null);

  function set(k: keyof FormState, v: string) {
    setForm((f) => ({ ...f, [k]: v }));
    setError(null);
  }

  function validate(): string | null {
    if (step === 1 && !form.asset_type)         return "Select an asset type.";
    if (step === 2 && !form.name.trim())         return "Name is required.";
    if (step === 2 && !form.content.trim())      return "Content / payload is required.";
    if (step === 3 && !form.price_usd)           return "Price is required.";
    if (step === 3 && Number(form.price_usd) <= 0) return "Price must be greater than 0.";
    return null;
  }

  function next() {
    const err = validate();
    if (err) { setError(err); return; }
    setStep((s) => Math.min(s + 1, 5));
  }

  async function submit() {
    setSub(true);
    setError(null);
    try {
      const API = process.env.NEXT_PUBLIC_API_URL ?? "https://api.shadow-warden-ai.com";
      const resp = await fetch(`${API}/marketplace/listings`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          asset_type:       form.asset_type,
          name:             form.name,
          description:      form.description,
          content:          form.content,
          pricing_strategy: form.pricing_strategy,
          price_usd:        Number(form.price_usd),
          chain:            form.chain,
        }),
      });
      if (!resp.ok) {
        const j = await resp.json().catch(() => ({}));
        throw new Error(j.detail ?? `HTTP ${resp.status}`);
      }
      router.push("/marketplace");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Submission failed.");
    } finally {
      setSub(false);
    }
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">New Listing</h1>
        <p className="text-white/50 text-sm mt-1">Tokenize and publish a security asset to the marketplace</p>
      </div>

      {/* Step indicators */}
      <div className="flex items-center gap-0">
        {STEPS.map((s, i) => (
          <div key={s.id} className="flex items-center flex-1 last:flex-none">
            <div className={`flex items-center gap-2 ${step >= s.id ? "text-white" : "text-white/30"}`}>
              <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0 transition-colors ${
                step > s.id  ? "bg-emerald-500 text-white" :
                step === s.id ? "bg-blue-500 text-white" :
                                "bg-white/10 text-white/30"
              }`}>
                {step > s.id ? <Check className="w-3.5 h-3.5" /> : s.id}
              </div>
              <span className="text-xs hidden sm:block">{s.label}</span>
            </div>
            {i < STEPS.length - 1 && <div className={`h-px flex-1 mx-2 transition-colors ${step > s.id ? "bg-emerald-500/50" : "bg-white/10"}`} />}
          </div>
        ))}
      </div>

      <div className="bg-white/5 rounded-xl border border-white/10 p-6 space-y-5">
        {/* Step 1 — Asset Type */}
        {step === 1 && (
          <div className="space-y-4">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2"><Layers className="w-4 h-4" /> Select Asset Type</h2>
            <div className="grid grid-cols-2 gap-3">
              {ASSET_TYPES.map((t) => (
                <button
                  key={t.value}
                  onClick={() => set("asset_type", t.value)}
                  className={`text-left p-4 rounded-lg border transition-all ${
                    form.asset_type === t.value
                      ? "border-blue-500 bg-blue-500/10"
                      : "border-white/10 bg-white/3 hover:border-white/20"
                  }`}
                >
                  <div className="text-2xl mb-2">{t.icon}</div>
                  <div className="text-sm font-semibold text-white">{t.label}</div>
                  <div className="text-xs text-white/50 mt-1">{t.desc}</div>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Step 2 — Content */}
        {step === 2 && (
          <div className="space-y-4">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2"><Upload className="w-4 h-4" /> Asset Content</h2>
            <div>
              <label className="text-xs text-white/50 block mb-1">Name *</label>
              <input
                className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder:text-white/30 focus:outline-none focus:border-blue-500"
                placeholder="e.g. GPT-4 Jailbreak Detector v3"
                value={form.name}
                onChange={(e) => set("name", e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs text-white/50 block mb-1">Description</label>
              <textarea
                className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder:text-white/30 focus:outline-none focus:border-blue-500 resize-none"
                rows={2}
                placeholder="What does this asset detect or protect against?"
                value={form.description}
                onChange={(e) => set("description", e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs text-white/50 block mb-1">Payload / Content *</label>
              <textarea
                className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder:text-white/30 focus:outline-none focus:border-blue-500 resize-none font-mono"
                rows={6}
                placeholder="Paste YARA rule, regex pattern, STIX JSON, or model bundle ID..."
                value={form.content}
                onChange={(e) => set("content", e.target.value)}
              />
            </div>
          </div>
        )}

        {/* Step 3 — Pricing */}
        {step === 3 && (
          <div className="space-y-4">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2"><Tag className="w-4 h-4" /> Pricing Strategy</h2>
            <div className="space-y-2">
              {PRICING_STRATEGIES.map((p) => (
                <label key={p.value} className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-all ${
                  form.pricing_strategy === p.value ? "border-blue-500 bg-blue-500/10" : "border-white/10 hover:border-white/20"
                }`}>
                  <input type="radio" name="pricing" value={p.value} checked={form.pricing_strategy === p.value}
                    onChange={() => set("pricing_strategy", p.value)} className="mt-0.5 accent-blue-500" />
                  <div>
                    <div className="text-sm font-semibold text-white">{p.label}</div>
                    <div className="text-xs text-white/50">{p.desc}</div>
                  </div>
                </label>
              ))}
            </div>
            <div>
              <label className="text-xs text-white/50 block mb-1">
                {form.pricing_strategy === "auction" ? "Reserve Price (USD) *" : "Price (USD) *"}
              </label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-white/40 text-sm">$</span>
                <input
                  type="number"
                  min="0.01"
                  step="0.01"
                  className="w-full bg-white/5 border border-white/10 rounded-lg pl-7 pr-3 py-2 text-sm text-white placeholder:text-white/30 focus:outline-none focus:border-blue-500"
                  placeholder="0.00"
                  value={form.price_usd}
                  onChange={(e) => set("price_usd", e.target.value)}
                />
              </div>
            </div>
          </div>
        )}

        {/* Step 4 — Chain */}
        {step === 4 && (
          <div className="space-y-4">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2"><Globe className="w-4 h-4" /> Select Chain</h2>
            <div className="space-y-2">
              {CHAINS.map((c) => (
                <button
                  key={c.value}
                  onClick={() => set("chain", c.value)}
                  className={`w-full text-left flex items-center gap-4 p-4 rounded-lg border transition-all ${
                    form.chain === c.value ? "border-blue-500 bg-blue-500/10" : "border-white/10 hover:border-white/20"
                  }`}
                >
                  <span className="text-2xl">{c.icon}</span>
                  <div>
                    <div className="text-sm font-semibold text-white">{c.label}</div>
                    <div className="text-xs text-white/50">{c.desc}</div>
                  </div>
                  {form.chain === c.value && <Check className="w-4 h-4 text-blue-400 ml-auto" />}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Step 5 — Review */}
        {step === 5 && (
          <div className="space-y-4">
            <h2 className="text-sm font-semibold text-white">Review & Tokenize</h2>
            <div className="bg-white/5 rounded-lg p-4 space-y-2 text-sm">
              {[
                ["Asset Type",      ASSET_TYPES.find((t) => t.value === form.asset_type)?.label ?? "—"],
                ["Name",            form.name || "—"],
                ["Pricing",         PRICING_STRATEGIES.find((p) => p.value === form.pricing_strategy)?.label ?? "—"],
                ["Price",           form.price_usd ? `$${Number(form.price_usd).toFixed(2)}` : "—"],
                ["Chain",           CHAINS.find((c) => c.value === form.chain)?.label ?? "—"],
                ["Content Length",  `${form.content.length} chars`],
              ].map(([k, v]) => (
                <div key={k} className="flex justify-between">
                  <span className="text-white/40">{k}</span>
                  <span className="text-white font-medium">{v}</span>
                </div>
              ))}
            </div>
            <p className="text-xs text-white/40">
              Submitting will run the content through the 9-layer Warden security pipeline,
              pin it to IPFS, and create an on-chain escrow contract on {CHAINS.find((c) => c.value === form.chain)?.label}.
            </p>
          </div>
        )}

        {error && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2 text-sm text-red-400">
            {error}
          </div>
        )}

        <div className="flex justify-between pt-2">
          <button
            onClick={() => setStep((s) => Math.max(s - 1, 1))}
            disabled={step === 1}
            className="flex items-center gap-1 text-sm text-white/50 hover:text-white disabled:opacity-30 transition-colors"
          >
            <ChevronLeft className="w-4 h-4" /> Back
          </button>
          {step < 5 ? (
            <button
              onClick={next}
              className="flex items-center gap-1 px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold rounded-lg transition-colors"
            >
              Next <ChevronRight className="w-4 h-4" />
            </button>
          ) : (
            <button
              onClick={submit}
              disabled={submitting}
              className="flex items-center gap-2 px-5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-semibold rounded-lg transition-colors disabled:opacity-50"
            >
              {submitting ? "Publishing…" : "Tokenize & Publish"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
