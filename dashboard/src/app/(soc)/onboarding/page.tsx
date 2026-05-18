"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

// ── Types ─────────────────────────────────────────────────────────────────────

interface StepProps {
  onNext: () => void;
  onBack?: () => void;
}

// ── Step components ───────────────────────────────────────────────────────────

function StepWelcome({ onNext }: StepProps) {
  return (
    <div className="flex flex-col gap-6 items-center text-center">
      <div className="w-16 h-16 rounded-2xl bg-[#FF2D55]/20 flex items-center justify-center text-3xl">
        🛡️
      </div>
      <div>
        <h2 className="text-2xl font-bold text-white mb-2">Welcome to Shadow Warden AI</h2>
        <p className="text-slate-400 max-w-md">
          Your AI security gateway is almost ready. This 5-step wizard sets up your API connection,
          filters, and alerting — takes under 2 minutes.
        </p>
      </div>
      <button
        onClick={onNext}
        className="px-8 py-3 rounded-xl bg-[#FF2D55] hover:bg-[#e0253f] text-white font-semibold transition-colors"
      >
        Get Started →
      </button>
    </div>
  );
}

function StepApiKey({ onNext, onBack }: StepProps) {
  const [apiUrl, setApiUrl] = useState(
    typeof window !== "undefined"
      ? localStorage.getItem("sw_api_url") ?? "https://api.shadow-warden-ai.com"
      : "https://api.shadow-warden-ai.com"
  );
  const [apiKey, setApiKey] = useState(
    typeof window !== "undefined" ? localStorage.getItem("sw_api_key") ?? "" : ""
  );
  const [testing, setTesting] = useState(false);
  const [status, setStatus] = useState<"idle" | "ok" | "error">("idle");

  async function testConnection() {
    setTesting(true);
    setStatus("idle");
    try {
      const res = await fetch(`${apiUrl}/health`, {
        headers: apiKey ? { "X-API-Key": apiKey } : {},
        signal: AbortSignal.timeout(5000),
      });
      setStatus(res.ok ? "ok" : "error");
    } catch {
      setStatus("error");
    } finally {
      setTesting(false);
    }
  }

  function save() {
    localStorage.setItem("sw_api_url", apiUrl);
    localStorage.setItem("sw_api_key", apiKey);
    onNext();
  }

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Connect to the API</h2>
        <p className="text-slate-400 text-sm">Enter your Shadow Warden API details.</p>
      </div>
      <div className="flex flex-col gap-3">
        <div>
          <label className="text-xs text-slate-400 mb-1 block">API Base URL</label>
          <input
            className="w-full bg-[#16161F] border border-slate-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#FF2D55]"
            value={apiUrl}
            onChange={(e) => setApiUrl(e.target.value)}
            placeholder="https://api.shadow-warden-ai.com"
          />
        </div>
        <div>
          <label className="text-xs text-slate-400 mb-1 block">API Key</label>
          <input
            type="password"
            className="w-full bg-[#16161F] border border-slate-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#FF2D55]"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="sk-warden-…"
          />
        </div>
      </div>
      <div className="flex gap-3 items-center">
        <button
          onClick={testConnection}
          disabled={testing}
          className="px-4 py-2 rounded-lg border border-slate-600 text-slate-300 text-sm hover:border-slate-400 disabled:opacity-50 transition-colors"
        >
          {testing ? "Testing…" : "Test Connection"}
        </button>
        {status === "ok" && <span className="text-[#30D158] text-sm">✓ Connected</span>}
        {status === "error" && <span className="text-[#FF2D55] text-sm">✗ Failed — check URL/key</span>}
      </div>
      <div className="flex gap-3 mt-2">
        <button onClick={onBack} className="px-5 py-2 rounded-lg border border-slate-700 text-slate-400 hover:text-white transition-colors">
          ← Back
        </button>
        <button
          onClick={save}
          className="flex-1 px-5 py-2 rounded-xl bg-[#FF2D55] hover:bg-[#e0253f] text-white font-semibold transition-colors"
        >
          Save & Continue
        </button>
      </div>
    </div>
  );
}

const RISK_LEVELS = ["LOW", "MEDIUM", "HIGH", "BLOCK"] as const;
type RiskLevel = (typeof RISK_LEVELS)[number];

function StepFilters({ onNext, onBack }: StepProps) {
  const [minRisk, setMinRisk] = useState<RiskLevel>("MEDIUM");
  const [autoBlock, setAutoBlock] = useState(true);
  const [redactPii, setRedactPii] = useState(true);

  function save() {
    localStorage.setItem("sw_min_risk", minRisk);
    localStorage.setItem("sw_auto_block", String(autoBlock));
    localStorage.setItem("sw_redact_pii", String(redactPii));
    onNext();
  }

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Configure Filters</h2>
        <p className="text-slate-400 text-sm">Set your risk tolerance and PII handling.</p>
      </div>
      <div className="flex flex-col gap-4">
        <div>
          <label className="text-xs text-slate-400 mb-2 block">Minimum risk level to annotate</label>
          <div className="flex gap-2">
            {RISK_LEVELS.map((r) => (
              <button
                key={r}
                onClick={() => setMinRisk(r)}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                  minRisk === r
                    ? r === "HIGH" || r === "BLOCK"
                      ? "bg-[#FF2D55] text-white"
                      : r === "MEDIUM"
                      ? "bg-[#FFD60A] text-black"
                      : "bg-[#30D158] text-black"
                    : "border border-slate-700 text-slate-400 hover:border-slate-500"
                }`}
              >
                {r}
              </button>
            ))}
          </div>
        </div>
        <label className="flex items-center gap-3 cursor-pointer">
          <div
            onClick={() => setAutoBlock(!autoBlock)}
            className={`w-10 h-6 rounded-full transition-colors relative ${autoBlock ? "bg-[#FF2D55]" : "bg-slate-700"}`}
          >
            <div className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-all ${autoBlock ? "left-5" : "left-1"}`} />
          </div>
          <div>
            <span className="text-white text-sm font-medium">Auto-block HIGH/BLOCK verdicts</span>
            <p className="text-slate-500 text-xs">Automatically reject requests at pipeline level</p>
          </div>
        </label>
        <label className="flex items-center gap-3 cursor-pointer">
          <div
            onClick={() => setRedactPii(!redactPii)}
            className={`w-10 h-6 rounded-full transition-colors relative ${redactPii ? "bg-[#0A84FF]" : "bg-slate-700"}`}
          >
            <div className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-all ${redactPii ? "left-5" : "left-1"}`} />
          </div>
          <div>
            <span className="text-white text-sm font-medium">Redact PII &amp; secrets</span>
            <p className="text-slate-500 text-xs">Strip 15 PII patterns + entropy-detected secrets</p>
          </div>
        </label>
      </div>
      <div className="flex gap-3 mt-2">
        <button onClick={onBack} className="px-5 py-2 rounded-lg border border-slate-700 text-slate-400 hover:text-white transition-colors">
          ← Back
        </button>
        <button
          onClick={save}
          className="flex-1 px-5 py-2 rounded-xl bg-[#FF2D55] hover:bg-[#e0253f] text-white font-semibold transition-colors"
        >
          Save & Continue
        </button>
      </div>
    </div>
  );
}

function StepAlerting({ onNext, onBack }: StepProps) {
  const [slackUrl, setSlackUrl] = useState("");
  const [alertLevel, setAlertLevel] = useState<"HIGH" | "BLOCK">("BLOCK");

  function save() {
    localStorage.setItem("sw_slack_url", slackUrl);
    localStorage.setItem("sw_alert_level", alertLevel);
    onNext();
  }

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Set Up Alerting</h2>
        <p className="text-slate-400 text-sm">Get notified when threats are detected.</p>
      </div>
      <div className="flex flex-col gap-4">
        <div>
          <label className="text-xs text-slate-400 mb-1 block">Slack Webhook URL (optional)</label>
          <input
            className="w-full bg-[#16161F] border border-slate-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#FF2D55]"
            value={slackUrl}
            onChange={(e) => setSlackUrl(e.target.value)}
            placeholder="https://hooks.slack.com/services/…"
          />
          <p className="text-slate-500 text-xs mt-1">
            Warden posts a message to this channel on HIGH/BLOCK verdicts.
          </p>
        </div>
        <div>
          <label className="text-xs text-slate-400 mb-2 block">Alert on verdicts at or above</label>
          <div className="flex gap-2">
            {(["HIGH", "BLOCK"] as const).map((r) => (
              <button
                key={r}
                onClick={() => setAlertLevel(r)}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                  alertLevel === r
                    ? "bg-[#FF2D55] text-white"
                    : "border border-slate-700 text-slate-400 hover:border-slate-500"
                }`}
              >
                {r}+
              </button>
            ))}
          </div>
        </div>
      </div>
      <div className="flex gap-3 mt-2">
        <button onClick={onBack} className="px-5 py-2 rounded-lg border border-slate-700 text-slate-400 hover:text-white transition-colors">
          ← Back
        </button>
        <button
          onClick={save}
          className="flex-1 px-5 py-2 rounded-xl bg-[#FF2D55] hover:bg-[#e0253f] text-white font-semibold transition-colors"
        >
          Save & Continue
        </button>
      </div>
    </div>
  );
}

function StepDone({ onBack }: StepProps) {
  const router = useRouter();
  return (
    <div className="flex flex-col gap-6 items-center text-center">
      <div className="w-16 h-16 rounded-2xl bg-[#30D158]/20 flex items-center justify-center text-3xl">
        ✅
      </div>
      <div>
        <h2 className="text-2xl font-bold text-white mb-2">You&apos;re all set!</h2>
        <p className="text-slate-400 max-w-md">
          Shadow Warden is configured and ready. Head to the Overview to see your security posture
          in real time.
        </p>
      </div>
      <div className="grid grid-cols-2 gap-3 w-full max-w-xs">
        <button
          onClick={() => router.push("/overview")}
          className="px-5 py-3 rounded-xl bg-[#FF2D55] hover:bg-[#e0253f] text-white font-semibold transition-colors"
        >
          Go to Overview
        </button>
        <button
          onClick={() => router.push("/events")}
          className="px-5 py-3 rounded-xl border border-slate-600 text-slate-300 hover:border-slate-400 transition-colors"
        >
          View Events
        </button>
      </div>
      <button onClick={onBack} className="text-slate-500 text-sm hover:text-slate-400">
        ← Back
      </button>
    </div>
  );
}

// ── Step definitions ──────────────────────────────────────────────────────────

const STEPS = [
  { label: "Welcome", color: "#FF2D55" },
  { label: "API", color: "#0A84FF" },
  { label: "Filters", color: "#FFD60A" },
  { label: "Alerting", color: "#BF5AF2" },
  { label: "Done", color: "#30D158" },
];

// ── Main page ─────────────────────────────────────────────────────────────────

export default function OnboardingPage() {
  const [step, setStep] = useState(0);
  const next = () => setStep((s) => Math.min(s + 1, STEPS.length - 1));
  const back = () => setStep((s) => Math.max(s - 1, 0));

  return (
    <div className="min-h-screen bg-[#03050F] flex items-center justify-center p-4">
      <div className="w-full max-w-lg">
        {/* Progress bar */}
        <div className="mb-8">
          <div className="flex items-center justify-between mb-3">
            {STEPS.map((s, i) => (
              <div key={s.label} className="flex items-center gap-2">
                <div
                  className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition-all"
                  style={{
                    background: i <= step ? s.color : "transparent",
                    border: `2px solid ${i <= step ? s.color : "#374151"}`,
                    color: i <= step ? (s.color === "#FFD60A" ? "#000" : "#fff") : "#6b7280",
                  }}
                >
                  {i < step ? "✓" : i + 1}
                </div>
                {i < STEPS.length - 1 && (
                  <div
                    className="h-0.5 w-8 sm:w-16 transition-all"
                    style={{ background: i < step ? STEPS[i].color : "#374151" }}
                  />
                )}
              </div>
            ))}
          </div>
          <p className="text-slate-500 text-xs text-center">
            Step {step + 1} of {STEPS.length} — {STEPS[step].label}
          </p>
        </div>

        {/* Card */}
        <div className="bg-[#0D0D14] border border-slate-800 rounded-2xl p-8">
          {step === 0 && <StepWelcome onNext={next} />}
          {step === 1 && <StepApiKey onNext={next} onBack={back} />}
          {step === 2 && <StepFilters onNext={next} onBack={back} />}
          {step === 3 && <StepAlerting onNext={next} onBack={back} />}
          {step === 4 && <StepDone onNext={next} onBack={back} />}
        </div>
      </div>
    </div>
  );
}
