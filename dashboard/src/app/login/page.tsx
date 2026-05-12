"use client";
import { useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Key, Fingerprint, CheckCircle2, ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";

/* ── design tokens ── */
const T = {
  bg:      "#030712",
  surf1:   "#0a0f1e",
  surf2:   "#0f172a",
  border:  "rgba(255,255,255,0.07)",
  indigo:  "#6366f1",
  purple:  "#8b5cf6",
  text:    "#f1f5f9",
  muted:   "#94a3b8",
  subtle:  "#475569",
};

type Step = "credentials" | "totp" | "passkey_prompt";
type Tab  = "signin" | "register";

/* ── passkey helpers (WebAuthn, localStorage-backed) ── */
function b64url(buf: ArrayBuffer) {
  const bytes = new Uint8Array(buf);
  let str = "";
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
function fromB64url(s: string): Uint8Array {
  const b = s.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(b), c => c.charCodeAt(0));
}

async function passkeyRegister(email: string) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { name: "Shadow Warden", id: location.hostname },
      user: {
        id: new TextEncoder().encode(email),
        name: email,
        displayName: email,
      },
      pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -257, type: "public-key" }],
      authenticatorSelection: { userVerification: "preferred", residentKey: "preferred" },
      timeout: 60000,
    },
  }) as PublicKeyCredential;
  const stored = JSON.parse(localStorage.getItem("sw_passkeys") ?? "[]") as string[];
  stored.push(b64url(cred.rawId));
  localStorage.setItem("sw_passkeys", JSON.stringify(stored));
  return true;
}

async function passkeyAuth() {
  const stored = JSON.parse(localStorage.getItem("sw_passkeys") ?? "[]") as string[];
  if (!stored.length) throw new Error("No passkey registered");
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: stored.map(id => ({ type: "public-key" as const, id: fromB64url(id).buffer as ArrayBuffer })),
      userVerification: "preferred",
      timeout: 60000,
    },
  }) as PublicKeyCredential;
  return b64url(cred.rawId);
}

function hasPasskey() {
  if (typeof window === "undefined") return false;
  return JSON.parse(localStorage.getItem("sw_passkeys") ?? "[]").length > 0;
}

/* ── sub-components ── */
function FieldInput({
  type = "text", placeholder, value, onChange, autoFocus, autoComplete,
}: {
  type?: string; placeholder: string; value: string;
  onChange: (v: string) => void; autoFocus?: boolean; autoComplete?: string;
}) {
  return (
    <input
      type={type}
      placeholder={placeholder}
      value={value}
      onChange={e => onChange(e.target.value)}
      autoFocus={autoFocus}
      autoComplete={autoComplete}
      className="w-full px-3.5 py-2.5 text-sm rounded-lg border text-gray-200 placeholder-gray-600 focus:outline-none transition-colors bg-transparent"
      style={{
        borderColor: T.border,
        background: "rgba(255,255,255,0.03)",
        caretColor: T.indigo,
      }}
      onFocus={e => (e.target.style.borderColor = T.indigo)}
      onBlur={e => (e.target.style.borderColor = T.border)}
    />
  );
}

function PrimaryBtn({ children, onClick, disabled, type = "button" }: {
  children: React.ReactNode; onClick?: () => void; disabled?: boolean; type?: "button" | "submit";
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className="w-full py-2.5 rounded-lg text-sm font-semibold transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
      style={{ background: `linear-gradient(135deg,${T.indigo},${T.purple})`, color: "#fff" }}
    >
      {children}
    </button>
  );
}

function GhostBtn({ children, onClick }: { children: React.ReactNode; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="w-full py-2.5 rounded-lg text-sm font-medium transition-colors text-gray-400 hover:text-white"
      style={{ border: `1px solid ${T.border}` }}
    >
      {children}
    </button>
  );
}

/* ── TOTP digit inputs ── */
function TotpInputs({ onComplete }: { onComplete: (code: string) => void }) {
  const [digits, setDigits] = useState(Array(6).fill(""));
  const r0 = useRef<HTMLInputElement>(null);
  const r1 = useRef<HTMLInputElement>(null);
  const r2 = useRef<HTMLInputElement>(null);
  const r3 = useRef<HTMLInputElement>(null);
  const r4 = useRef<HTMLInputElement>(null);
  const r5 = useRef<HTMLInputElement>(null);
  const refs = [r0, r1, r2, r3, r4, r5];

  function handleChange(i: number, val: string) {
    const d = val.replace(/\D/g, "").slice(-1);
    const next = [...digits];
    next[i] = d;
    setDigits(next);
    if (d && i < 5) refs[i + 1].current?.focus();
    if (next.every(x => x)) onComplete(next.join(""));
  }

  function handleKey(i: number, e: React.KeyboardEvent) {
    if (e.key === "Backspace" && !digits[i] && i > 0) refs[i - 1].current?.focus();
    if (e.key === "ArrowLeft" && i > 0) refs[i - 1].current?.focus();
    if (e.key === "ArrowRight" && i < 5) refs[i + 1].current?.focus();
  }

  function handlePaste(e: React.ClipboardEvent) {
    const text = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, 6);
    if (text.length === 6) {
      setDigits(text.split(""));
      refs[5].current?.focus();
      onComplete(text);
    }
    e.preventDefault();
  }

  return (
    <div className="flex items-center gap-2">
      {digits.map((d, i) => (
        <input
          key={i}
          ref={refs[i]}
          type="text"
          inputMode="numeric"
          maxLength={1}
          value={d}
          autoFocus={i === 0}
          onChange={e => handleChange(i, e.target.value)}
          onKeyDown={e => handleKey(i, e)}
          onPaste={i === 0 ? handlePaste : undefined}
          className="w-10 h-12 text-center text-lg font-bold rounded-lg border focus:outline-none transition-colors"
          style={{
            background: "rgba(255,255,255,0.04)",
            borderColor: d ? T.indigo : T.border,
            color: T.text,
            caretColor: T.indigo,
          }}
        />
      ))}
    </div>
  );
}

/* ── left brand panel ── */
function BrandPanel() {
  const features = [
    { icon: "⬡", label: "9-stage causal defense pipeline" },
    { icon: "🧠", label: "Self-improving ML — Claude Opus Evolution" },
    { icon: "🔐", label: "Post-quantum cryptography (ML-DSA-65)" },
    { icon: "🌍", label: "Sovereign AI Cloud · 8 jurisdictions" },
  ];
  return (
    <div
      className="hidden lg:flex flex-col justify-between p-10 relative overflow-hidden"
      style={{ background: T.surf1 }}
    >
      {/* radial glow */}
      <div
        className="absolute pointer-events-none"
        style={{
          top: "10%", left: "50%", transform: "translateX(-50%)",
          width: 500, height: 400,
          background: `radial-gradient(ellipse,rgba(99,102,241,0.12) 0%,transparent 70%)`,
        }}
      />
      {/* grid */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          backgroundImage: `linear-gradient(rgba(99,102,241,0.04) 1px,transparent 1px),linear-gradient(90deg,rgba(99,102,241,0.04) 1px,transparent 1px)`,
          backgroundSize: "48px 48px",
        }}
      />

      <div className="relative z-10">
        <div className="flex items-center gap-2.5 mb-12">
          <div
            className="w-9 h-9 rounded-xl flex items-center justify-center text-sm font-black"
            style={{ background: `linear-gradient(135deg,${T.indigo},${T.purple})` }}
          >
            SW
          </div>
          <span className="text-white font-bold text-lg tracking-tight">Shadow Warden</span>
        </div>

        <h2 className="text-[28px] font-black leading-tight mb-3" style={{ color: T.text }}>
          Your AI. Your Rules.<br />
          <span style={{ background: `linear-gradient(90deg,${T.indigo},${T.purple})`, WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
            Your Fortress.
          </span>
        </h2>
        <p className="text-[14px] mb-10" style={{ color: T.muted }}>
          Real-time AI security gateway — deployed in 60 seconds.
        </p>

        <div className="space-y-4">
          {features.map(f => (
            <div key={f.label} className="flex items-start gap-3">
              <span className="text-[18px] mt-0.5 shrink-0">{f.icon}</span>
              <p className="text-[13px] font-medium" style={{ color: T.muted }}>{f.label}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="relative z-10">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full text-[11px] font-semibold w-fit"
             style={{ color: "#10b981", background: "rgba(16,185,129,0.1)", border: "1px solid rgba(16,185,129,0.2)" }}>
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          v4.19 · Production
        </div>
      </div>
    </div>
  );
}

/* ── main page ── */
export default function LoginPage() {
  const router = useRouter();
  const [tab,   setTab]   = useState<Tab>("signin");
  const [step,  setStep]  = useState<Step>("credentials");
  const [email, setEmail] = useState("");
  const [pw,    setPw]    = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [passkeySupported] = useState(() =>
    typeof window !== "undefined" && !!window.PublicKeyCredential
  );

  async function handlePasskeyLogin() {
    setError(""); setLoading(true);
    try {
      await passkeyAuth();
      // Passkey verified client-side — create session via API
      const res = await fetch("/api/auth/passkey", { method: "POST" });
      if (res.ok) { router.push("/"); router.refresh(); }
      else setError("Passkey session failed");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Passkey auth failed");
    } finally { setLoading(false); }
  }

  async function handleCredentials(e: React.FormEvent) {
    e.preventDefault();
    setError(""); setLoading(true);
    try {
      const res = await fetch("/api/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key: pw }),
      });
      if (res.ok) {
        // Advance to TOTP step (cookie already set; TOTP is additional verification gate)
        setStep("totp");
      } else {
        setError("Invalid credentials");
      }
    } catch {
      setError("Connection error");
    } finally { setLoading(false); }
  }

  async function handleTotp(code: string) {
    setError(""); setLoading(true);
    try {
      const res = await fetch("/api/auth/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      if (res.ok) {
        if (tab === "register" || !hasPasskey()) {
          setStep("passkey_prompt");
        } else {
          router.push("/"); router.refresh();
        }
      } else {
        setError("Invalid verification code");
      }
    } catch {
      setError("Verification failed");
    } finally { setLoading(false); }
  }

  async function handlePasskeyRegister() {
    setError(""); setLoading(true);
    try {
      await passkeyRegister(email || "admin");
      router.push("/"); router.refresh();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Passkey setup failed");
    } finally { setLoading(false); }
  }

  const canPasskeyLogin = passkeySupported && hasPasskey() && tab === "signin";

  return (
    <div className="min-h-screen flex" style={{ background: T.bg }}>
      {/* left brand */}
      <div className="flex-1">
        <BrandPanel />
      </div>

      {/* right form */}
      <div
        className="w-full lg:w-[420px] shrink-0 flex flex-col items-center justify-center p-8"
        style={{ borderLeft: `1px solid ${T.border}` }}
      >
        {/* mobile logo */}
        <div className="flex lg:hidden items-center gap-2 mb-8">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center text-xs font-black"
               style={{ background: `linear-gradient(135deg,${T.indigo},${T.purple})` }}>
            SW
          </div>
          <span className="text-white font-bold">Shadow Warden</span>
        </div>

        <div className="w-full max-w-sm">

          {/* ── STEP: credentials ── */}
          {step === "credentials" && (
            <>
              {/* tab switcher */}
              <div className="flex rounded-lg p-1 mb-8" style={{ background: "rgba(255,255,255,0.04)", border: `1px solid ${T.border}` }}>
                {(["signin", "register"] as Tab[]).map(t => (
                  <button
                    key={t}
                    onClick={() => { setTab(t); setError(""); }}
                    className="flex-1 py-2 rounded-md text-[13px] font-semibold transition-all"
                    style={tab === t
                      ? { background: `linear-gradient(135deg,${T.indigo},${T.purple})`, color: "#fff" }
                      : { color: T.subtle }
                    }
                  >
                    {t === "signin" ? "Sign In" : "Create Account"}
                  </button>
                ))}
              </div>

              <h1 className="text-xl font-bold mb-1" style={{ color: T.text }}>
                {tab === "signin" ? "Welcome back" : "Get started"}
              </h1>
              <p className="text-[13px] mb-6" style={{ color: T.muted }}>
                {tab === "signin"
                  ? "Enter your credentials to access the SOC dashboard."
                  : "Create your account to begin securing your AI."}
              </p>

              {/* passkey fast-path */}
              {canPasskeyLogin && (
                <>
                  <button
                    type="button"
                    onClick={handlePasskeyLogin}
                    disabled={loading}
                    className="w-full py-2.5 rounded-lg text-sm font-semibold mb-4 flex items-center justify-center gap-2 transition-colors disabled:opacity-40"
                    style={{ border: `1px solid ${T.border}`, color: T.text, background: "rgba(255,255,255,0.03)" }}
                  >
                    <Fingerprint size={16} style={{ color: T.indigo }} />
                    Sign in with Passkey
                  </button>
                  <div className="flex items-center gap-3 mb-4">
                    <div className="flex-1 h-px" style={{ background: T.border }} />
                    <span className="text-[11px]" style={{ color: T.subtle }}>or continue with password</span>
                    <div className="flex-1 h-px" style={{ background: T.border }} />
                  </div>
                </>
              )}

              <form onSubmit={handleCredentials} className="space-y-3">
                <FieldInput
                  type="email"
                  placeholder="Email address"
                  value={email}
                  onChange={setEmail}
                  autoFocus
                  autoComplete="email"
                />
                <FieldInput
                  type="password"
                  placeholder="API key / password"
                  value={pw}
                  onChange={setPw}
                  autoComplete="current-password"
                />
                {error && <p className="text-[12px] text-red-400">{error}</p>}
                <PrimaryBtn type="submit" disabled={!pw || loading}>
                  {loading ? "Verifying…" : (
                    <>{tab === "signin" ? "Continue" : "Create Account"} <ChevronRight size={14} /></>
                  )}
                </PrimaryBtn>
              </form>

              {passkeySupported && !canPasskeyLogin && (
                <p className="text-center text-[11px] mt-4" style={{ color: T.subtle }}>
                  You can register a passkey after signing in.
                </p>
              )}
            </>
          )}

          {/* ── STEP: TOTP ── */}
          {step === "totp" && (
            <>
              <div className="flex items-center justify-center w-12 h-12 rounded-2xl mx-auto mb-6"
                   style={{ background: "rgba(99,102,241,0.1)", border: `1px solid rgba(99,102,241,0.2)` }}>
                <Shield size={22} style={{ color: T.indigo }} />
              </div>
              <h1 className="text-xl font-bold text-center mb-1" style={{ color: T.text }}>
                Two-factor verification
              </h1>
              <p className="text-[13px] text-center mb-8" style={{ color: T.muted }}>
                Enter the 6-digit code from your authenticator app.
              </p>

              <div className="flex justify-center mb-6">
                <TotpInputs onComplete={handleTotp} />
              </div>

              {loading && (
                <p className="text-center text-[13px] mb-4" style={{ color: T.muted }}>Verifying…</p>
              )}
              {error && <p className="text-center text-[12px] text-red-400 mb-4">{error}</p>}

              <GhostBtn onClick={() => { setStep("credentials"); setError(""); }}>
                ← Back
              </GhostBtn>

              <p className="text-center text-[11px] mt-4" style={{ color: T.subtle }}>
                No authenticator? If 2FA is disabled, enter any 6 digits.
              </p>
            </>
          )}

          {/* ── STEP: passkey prompt ── */}
          {step === "passkey_prompt" && (
            <>
              <div className="flex items-center justify-center w-12 h-12 rounded-2xl mx-auto mb-6"
                   style={{ background: "rgba(99,102,241,0.1)", border: `1px solid rgba(99,102,241,0.2)` }}>
                <Fingerprint size={22} style={{ color: T.indigo }} />
              </div>
              <h1 className="text-xl font-bold text-center mb-1" style={{ color: T.text }}>
                Set up a passkey
              </h1>
              <p className="text-[13px] text-center mb-8" style={{ color: T.muted }}>
                Skip passwords next time — sign in with Face ID, Touch ID, or your device PIN.
              </p>

              {error && <p className="text-center text-[12px] text-red-400 mb-4">{error}</p>}

              <div className="space-y-3">
                <PrimaryBtn onClick={handlePasskeyRegister} disabled={loading || !passkeySupported}>
                  <Fingerprint size={15} />
                  {loading ? "Setting up…" : "Set up passkey"}
                </PrimaryBtn>
                <GhostBtn onClick={() => { router.push("/"); router.refresh(); }}>
                  Skip for now
                </GhostBtn>
              </div>

              {!passkeySupported && (
                <p className="text-center text-[11px] mt-4 text-amber-500">
                  Your browser doesn't support passkeys.
                </p>
              )}
            </>
          )}

          {/* step indicator */}
          {step !== "credentials" && (
            <div className="flex justify-center gap-1.5 mt-8">
              {(["credentials", "totp", "passkey_prompt"] as Step[]).map((s, i) => (
                <div
                  key={s}
                  className="rounded-full transition-all"
                  style={{
                    width: step === s ? 20 : 6, height: 6,
                    background: step === s ? T.indigo
                      : (["credentials", "totp", "passkey_prompt"].indexOf(step) > i ? T.purple : T.border),
                  }}
                />
              ))}
            </div>
          )}
        </div>

        <p className="text-[11px] mt-8" style={{ color: T.subtle }}>
          Shadow Warden AI · SOC Operations Centre
        </p>
      </div>
    </div>
  );
}
