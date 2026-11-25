"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { AuthShell, ErrorNote, Spinner, field, labelCls, primary, secondary } from "@/components/auth/AuthShell";

// Two steps, both checked on the server (src/lib/twoStep.ts): the access key
// earns a 5-minute pending cookie, the authenticator code turns it into a
// session. There is no way past step two from this page.

async function post(path: string, body: unknown): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const data = (await res.json().catch(() => ({}))) as { error?: string };
    return { ok: res.ok, error: data.error };
  } catch {
    return { ok: false, error: "Could not reach the dashboard server." };
  }
}

export default function LoginPage() {
  const router = useRouter();
  const [step, setStep] = useState<"key" | "code">("key");
  const [key, setKey] = useState("");
  const [show, setShow] = useState(false);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function onKey(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (!key.trim()) return setError("Enter the access key.");
    setBusy(true);
    const r = await post("/api/auth", { key: key.trim() });
    setBusy(false);
    if (!r.ok) return setError(r.error ?? "Sign-in failed.");
    setKey("");
    setStep("code");
  }

  async function onCode(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (!/^\d{6}$/.test(code)) return setError("Enter all 6 digits.");
    setBusy(true);
    const r = await post("/api/auth/verify", { code });
    setBusy(false);
    if (!r.ok) {
      setCode("");
      setError(r.error ?? "That code did not work.");
      if (r.error?.includes("expired") || r.error?.includes("Locked")) setStep("key");
      return;
    }
    router.push("/");
    router.refresh();
  }

  if (step === "code") {
    return (
      <AuthShell step="Step 2 of 2" title="Two-step verification"
                 lead="Open your authenticator app and enter the current code for the Shadow Warden dashboard.">
        {error && <ErrorNote>{error}</ErrorNote>}
        <form onSubmit={onCode} className="flex flex-col gap-4" noValidate>
          <label className={labelCls}>6-digit code
            <input value={code} onChange={e => setCode(e.target.value.replace(/[^0-9]/g, "").slice(0, 6))}
                   inputMode="numeric" autoComplete="one-time-code" autoFocus placeholder="000000"
                   className={`${field} min-h-[56px] font-mono text-[24px] tracking-[0.4em] text-center`} />
          </label>
          <button type="submit" disabled={busy || code.length !== 6} className={primary}>
            {busy ? <Spinner /> : "Verify and sign in"}
          </button>
          <button type="button" onClick={() => { setStep("key"); setCode(""); setError(""); }} className={secondary}>
            Start over
          </button>
        </form>
      </AuthShell>
    );
  }

  return (
    <AuthShell step="Step 1 of 2" title="Sign in to the SOC dashboard"
               lead="Enter the access key. A code from your authenticator app comes next."
               footer={<p className="m-0 text-[13px] leading-[18px] text-[#8b98a8]">Lost the key or the authenticator? The operator sets both on the server (DASHBOARD_API_KEY, DASHBOARD_TOTP_SECRET) and can rotate them.</p>}>
      {error && <ErrorNote>{error}</ErrorNote>}
      <form onSubmit={onKey} className="flex flex-col gap-4" noValidate>
        <div className="flex flex-col gap-1.5">
          <label htmlFor="access-key" className="text-[14px] font-medium">Access key</label>
          <div className="flex rounded-lg border border-[#5c6b7e] bg-[#07090c] overflow-hidden focus-within:border-[#00c2ff] focus-within:ring-2 focus-within:ring-[#00c2ff]/30">
            <input id="access-key" type={show ? "text" : "password"} autoComplete="current-password" value={key}
                   onChange={e => setKey(e.target.value)} autoFocus
                   className="flex-1 min-w-0 min-h-[44px] px-3.5 border-0 bg-transparent text-[15px] text-[#e6edf3] focus:outline-none" />
            <button type="button" onClick={() => setShow(!show)} aria-label={show ? "Hide key" : "Show key"}
                    className="min-w-[64px] px-3.5 border-0 border-l border-[#232c38] bg-transparent text-[13px] font-semibold text-[#8b98a8] cursor-pointer">
              {show ? "Hide" : "Show"}
            </button>
          </div>
        </div>
        <button type="submit" disabled={busy} className={primary}>{busy ? <Spinner /> : "Continue"}</button>
      </form>
    </AuthShell>
  );
}
