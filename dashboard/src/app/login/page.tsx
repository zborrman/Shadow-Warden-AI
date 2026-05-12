"use client";
import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Fingerprint, ChevronRight, Globe, Lock, Mail, Eye, EyeOff } from "lucide-react";

/* ── design tokens ── */
const T = {
  bg:     "#030712",
  surf1:  "#080d1a",
  border: "rgba(255,255,255,0.08)",
  indigo: "#6366f1",
  purple: "#8b5cf6",
  red:    "#FF2D55",
  text:   "#f1f5f9",
  muted:  "#94a3b8",
  subtle: "#475569",
  green:  "#10b981",
};

/* ── password strength ── */
function calcStrength(pw: string) {
  let s = 0;
  if (pw.length >= 8)          s++;
  if (pw.length >= 12)         s++;
  if (/[A-Z]/.test(pw))        s++;
  if (/[0-9]/.test(pw))        s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  if (s <= 1) return { score: s, label: "Weak",   color: "#ef4444" };
  if (s <= 2) return { score: s, label: "Fair",   color: "#f59e0b" };
  if (s <= 3) return { score: s, label: "Good",   color: "#3b82f6" };
  return        { score: s, label: "Strong", color: "#10b981" };
}

const COUNTRIES = [
  "United States","United Kingdom","Germany","France","Israel",
  "Canada","Australia","Netherlands","Sweden","Switzerland",
  "Japan","Singapore","India","Brazil","Other",
];

/* ── passkey helpers ── */
function b64url(buf: ArrayBuffer) {
  const bytes = new Uint8Array(buf);
  let str = "";
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g,"-").replace(/\//g,"_").replace(/=/g,"");
}
function fromB64url(s: string): Uint8Array {
  return Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")), c => c.charCodeAt(0));
}
async function passkeyRegister(email: string) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const cred = await navigator.credentials.create({ publicKey: {
    challenge,
    rp: { name: "Shadow Warden", id: location.hostname },
    user: { id: new TextEncoder().encode(email), name: email, displayName: email },
    pubKeyCredParams: [{ alg: -7, type:"public-key" },{ alg:-257, type:"public-key" }],
    authenticatorSelection: { userVerification:"preferred", residentKey:"preferred" },
    timeout: 60000,
  }}) as PublicKeyCredential;
  const stored = JSON.parse(localStorage.getItem("sw_passkeys") ?? "[]") as string[];
  stored.push(b64url(cred.rawId));
  localStorage.setItem("sw_passkeys", JSON.stringify(stored));
  return true;
}
async function passkeyAuth() {
  const stored = JSON.parse(localStorage.getItem("sw_passkeys") ?? "[]") as string[];
  if (!stored.length) throw new Error("No passkey registered");
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  await navigator.credentials.get({ publicKey: {
    challenge,
    allowCredentials: stored.map(id => ({ type:"public-key" as const, id: fromB64url(id).buffer as ArrayBuffer })),
    userVerification: "preferred", timeout: 60000,
  }});
}
function hasPasskey() {
  if (typeof window === "undefined") return false;
  return JSON.parse(localStorage.getItem("sw_passkeys") ?? "[]").length > 0;
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
    const d = val.replace(/\D/g,"").slice(-1);
    const next = [...digits]; next[i] = d; setDigits(next);
    if (d && i < 5) refs[i+1].current?.focus();
    if (next.every(x => x)) onComplete(next.join(""));
  }
  function handleKey(i: number, e: React.KeyboardEvent) {
    if (e.key==="Backspace" && !digits[i] && i>0) refs[i-1].current?.focus();
    if (e.key==="ArrowLeft" && i>0) refs[i-1].current?.focus();
    if (e.key==="ArrowRight" && i<5) refs[i+1].current?.focus();
  }
  function handlePaste(e: React.ClipboardEvent) {
    const text = e.clipboardData.getData("text").replace(/\D/g,"").slice(0,6);
    if (text.length===6) { setDigits(text.split("")); refs[5].current?.focus(); onComplete(text); }
    e.preventDefault();
  }
  return (
    <div className="flex items-center gap-2.5 justify-center">
      {digits.map((d, i) => (
        <input key={i} ref={refs[i]}
          type="text" inputMode="numeric" maxLength={1} value={d} autoFocus={i===0}
          onChange={e => handleChange(i, e.target.value)}
          onKeyDown={e => handleKey(i, e)}
          onPaste={i===0 ? handlePaste : undefined}
          className="w-11 h-13 text-center text-xl font-bold rounded-xl border-2 focus:outline-none transition-all"
          style={{
            height: 52,
            background: d ? "rgba(99,102,241,0.1)" : "rgba(255,255,255,0.03)",
            borderColor: d ? T.indigo : T.border,
            color: T.text, caretColor: T.indigo,
          }} />
      ))}
    </div>
  );
}

type Step = "credentials" | "totp" | "passkey_prompt" | "forgot" | "forgot_sent";
type Tab  = "signin" | "register";

/* ── Field wrapper ── */
function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-[11px] font-semibold uppercase tracking-wider mb-1.5"
             style={{ color: T.subtle }}>{label}</label>
      {children}
    </div>
  );
}

const inputBase: React.CSSProperties = {
  borderColor: T.border,
  background: "rgba(255,255,255,0.03)",
  color: T.text,
  caretColor: T.indigo,
};

export default function LoginPage() {
  const router = useRouter();
  const [tab,     setTab]     = useState<Tab>("signin");
  const [step,    setStep]    = useState<Step>("credentials");
  const [email,   setEmail]   = useState("");
  const [pw,      setPw]      = useState("");
  const [country, setCountry] = useState("");
  const [showPw,  setShowPw]  = useState(false);
  const [error,   setError]   = useState("");
  const [loading, setLoading] = useState(false);
  const [passkeySupported, setPasskeySupported] = useState(false);

  useEffect(() => { setPasskeySupported(!!window.PublicKeyCredential); }, []);

  const isReg   = tab === "register";
  const strength = calcStrength(pw);
  const pwReqs  = [
    { label: "8+ characters",    met: pw.length >= 8 },
    { label: "Uppercase letter", met: /[A-Z]/.test(pw) },
    { label: "Number",           met: /[0-9]/.test(pw) },
    { label: "Special char",     met: /[^A-Za-z0-9]/.test(pw) },
  ];

  async function handleForgot(e: React.FormEvent) {
    e.preventDefault(); setError(""); setLoading(true);
    try {
      await fetch("/api/auth/forgot", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      setStep("forgot_sent");
    } catch { setError("Could not send reset email. Try again."); }
    finally { setLoading(false); }
  }

  async function handlePasskeyLogin() {
    setError(""); setLoading(true);
    try {
      await passkeyAuth();
      const res = await fetch("/api/auth/passkey", { method: "POST" });
      if (res.ok) { router.push("/"); router.refresh(); }
      else setError("Passkey session failed");
    } catch (e: unknown) { setError(e instanceof Error ? e.message : "Passkey auth failed"); }
    finally { setLoading(false); }
  }

  async function handleCredentials(e: React.FormEvent) {
    e.preventDefault(); setError(""); setLoading(true);
    try {
      const res = await fetch("/api/auth", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key: pw }),
      });
      if (res.ok) setStep("totp"); else setError("Invalid credentials");
    } catch { setError("Connection error"); }
    finally { setLoading(false); }
  }

  async function handleTotp(code: string) {
    setError(""); setLoading(true);
    try {
      const res = await fetch("/api/auth/verify", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      if (res.ok) {
        if (isReg || !hasPasskey()) setStep("passkey_prompt");
        else { router.push("/"); router.refresh(); }
      } else setError("Invalid verification code");
    } catch { setError("Verification failed"); }
    finally { setLoading(false); }
  }

  async function handlePasskeySetup() {
    setError(""); setLoading(true);
    try {
      await passkeyRegister(email || "admin");
      router.push("/"); router.refresh();
    } catch (e: unknown) { setError(e instanceof Error ? e.message : "Passkey setup failed"); }
    finally { setLoading(false); }
  }

  const canPasskeyLogin = passkeySupported && hasPasskey() && tab === "signin";

  return (
    <div className="min-h-screen flex" style={{ background: T.bg }}>

      {/* ── LEFT BRAND PANEL ── */}
      <div className="hidden lg:flex flex-col justify-between p-12 flex-1 relative overflow-hidden"
           style={{ background: T.surf1 }}>
        {/* glows */}
        <div className="absolute pointer-events-none"
             style={{ top:"10%", left:"50%", transform:"translateX(-50%)", width:600, height:500,
                      background:"radial-gradient(ellipse,rgba(99,102,241,0.09) 0%,transparent 65%)" }} />
        <div className="absolute bottom-0 right-0 w-72 h-72 pointer-events-none"
             style={{ background:"radial-gradient(circle at bottom right,rgba(255,45,85,0.07) 0%,transparent 65%)" }} />
        {/* grid */}
        <div className="absolute inset-0 pointer-events-none"
             style={{ backgroundImage:"linear-gradient(rgba(99,102,241,0.04) 1px,transparent 1px),linear-gradient(90deg,rgba(99,102,241,0.04) 1px,transparent 1px)",
                      backgroundSize:"48px 48px" }} />

        <div className="relative z-10">
          {/* Logo */}
          <div className="flex items-center gap-3 mb-16">
            <div className="w-10 h-10 rounded-2xl flex items-center justify-center text-sm font-black text-white"
                 style={{ background:"linear-gradient(135deg,#6366f1,#8b5cf6)" }}>SW</div>
            <span className="text-white font-bold text-xl tracking-tight">Shadow Warden</span>
          </div>

          <h2 className="text-[38px] font-black leading-[1.1] mb-4" style={{ color: T.text }}>
            Your AI. Your Rules.<br/>
            <span style={{ background:"linear-gradient(90deg,#6366f1,#8b5cf6)",
                           WebkitBackgroundClip:"text", WebkitTextFillColor:"transparent" }}>
              Your Fortress.
            </span>
          </h2>
          <p className="text-[14px] mb-12 leading-relaxed" style={{ color: T.muted }}>
            Real-time AI security gateway with post-quantum cryptography,<br/>
            sovereign data routing, and self-improving ML.
          </p>

          <div className="space-y-3">
            {[
              { icon:"⬡", accent:"#FF2D55", label:"9-stage causal defense pipeline",  sub:"< 2ms end-to-end latency" },
              { icon:"🔐", accent:"#6366f1", label:"Post-quantum cryptography",         sub:"Ed25519 + ML-DSA-65 hybrid" },
              { icon:"🌍", accent:"#10b981", label:"Sovereign AI Cloud",                sub:"8 jurisdictions, GDPR Art. 35" },
              { icon:"🧠", accent:"#8b5cf6", label:"Self-improving ML",                 sub:"Claude Opus Evolution Engine" },
            ].map(f => (
              <div key={f.label} className="flex items-center gap-4 p-4 rounded-2xl"
                   style={{ background:"rgba(255,255,255,0.025)", border:"1px solid rgba(255,255,255,0.05)" }}>
                <div className="w-9 h-9 rounded-xl flex items-center justify-center text-[16px] shrink-0"
                     style={{ background:`${f.accent}18` }}>{f.icon}</div>
                <div>
                  <p className="text-[13px] font-semibold leading-none mb-0.5" style={{ color: T.text }}>{f.label}</p>
                  <p className="text-[11px]" style={{ color: T.subtle }}>{f.sub}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="relative z-10 flex items-center justify-between">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full text-[11px] font-semibold"
               style={{ color:"#10b981", background:"rgba(16,185,129,0.1)", border:"1px solid rgba(16,185,129,0.2)" }}>
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            v4.19 · Production
          </div>
          <p className="text-[11px]" style={{ color: T.subtle }}>99.95% SLA · SOC 2 Type II</p>
        </div>
      </div>

      {/* ── RIGHT FORM PANEL ── */}
      <div className="w-full lg:w-[480px] shrink-0 flex flex-col items-center justify-center p-8 overflow-y-auto min-h-screen"
           style={{ borderLeft:`1px solid ${T.border}` }}>

        {/* Mobile logo */}
        <div className="flex lg:hidden items-center gap-2 mb-8">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center text-xs font-black text-white"
               style={{ background:"linear-gradient(135deg,#6366f1,#8b5cf6)" }}>SW</div>
          <span className="text-white font-bold">Shadow Warden</span>
        </div>

        <div className="w-full max-w-[380px]">

          {/* ─────── STEP: credentials ─────── */}
          {step === "credentials" && (
            <>
              {/* Tab switcher */}
              <div className="flex rounded-xl p-1 mb-8"
                   style={{ background:"rgba(255,255,255,0.04)", border:`1px solid ${T.border}` }}>
                {(["signin","register"] as Tab[]).map(t => (
                  <button key={t} onClick={() => { setTab(t); setError(""); }}
                    className="flex-1 py-2.5 rounded-lg text-[13px] font-semibold transition-all"
                    style={tab===t
                      ? { background:"linear-gradient(135deg,#6366f1,#8b5cf6)", color:"#fff",
                          boxShadow:"0 2px 12px rgba(99,102,241,0.3)" }
                      : { color: T.subtle }}>
                    {t==="signin" ? "Sign In" : "Create Account"}
                  </button>
                ))}
              </div>

              <h1 className="text-[22px] font-black mb-1" style={{ color: T.text }}>
                {isReg ? "Create your account" : "Welcome back"}
              </h1>
              <p className="text-[13px] mb-7" style={{ color: T.muted }}>
                {isReg ? "Secure your AI infrastructure in minutes." : "Sign in to your SOC Operations Centre."}
              </p>

              {/* Passkey fast-path */}
              {canPasskeyLogin && (
                <>
                  <button type="button" onClick={handlePasskeyLogin} disabled={loading}
                    className="w-full py-3 rounded-xl text-sm font-semibold mb-5 flex items-center justify-center gap-2.5 transition-all disabled:opacity-40"
                    style={{ border:`1px solid ${T.border}`, color: T.text, background:"rgba(255,255,255,0.03)" }}>
                    <Fingerprint size={17} style={{ color: T.indigo }} />
                    Sign in with Passkey
                  </button>
                  <div className="flex items-center gap-3 mb-5">
                    <div className="flex-1 h-px" style={{ background: T.border }} />
                    <span className="text-[11px]" style={{ color: T.subtle }}>or use password</span>
                    <div className="flex-1 h-px" style={{ background: T.border }} />
                  </div>
                </>
              )}

              <form onSubmit={handleCredentials} className="space-y-4">

                {/* Email */}
                <Field label="Email address">
                  <div className="relative">
                    <Mail size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none"
                          style={{ color: T.subtle }} />
                    <input type="email" placeholder="you@company.com" value={email}
                      onChange={e => setEmail(e.target.value)} autoFocus autoComplete="email"
                      className="w-full pl-10 pr-4 py-2.5 text-sm rounded-xl border focus:outline-none transition-all"
                      style={inputBase}
                      onFocus={e => (e.target.style.borderColor = T.indigo)}
                      onBlur={e  => (e.target.style.borderColor = T.border)} />
                  </div>
                </Field>

                {/* Password */}
                <Field label="Password">
                  <div className="relative">
                    <Lock size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none"
                          style={{ color: T.subtle }} />
                    <input type={showPw ? "text" : "password"}
                      placeholder={isReg ? "Create a strong password" : "API key / password"}
                      value={pw} onChange={e => setPw(e.target.value)}
                      autoComplete={isReg ? "new-password" : "current-password"}
                      className="w-full pl-10 pr-12 py-2.5 text-sm rounded-xl border focus:outline-none transition-all"
                      style={inputBase}
                      onFocus={e => (e.target.style.borderColor = T.indigo)}
                      onBlur={e  => (e.target.style.borderColor = T.border)} />
                    <button type="button" onClick={() => setShowPw(v => !v)}
                      className="absolute right-3.5 top-1/2 -translate-y-1/2 transition-opacity hover:opacity-100 opacity-60"
                      style={{ color: T.muted }}>
                      {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                    </button>
                  </div>

                  {/* Forgot password link — sign in only */}
                  {!isReg && (
                    <div className="flex justify-end mt-1.5">
                      <button type="button"
                        onClick={() => { setError(""); setStep("forgot"); }}
                        className="text-[12px] font-medium transition-colors hover:opacity-100 opacity-70"
                        style={{ color: T.indigo }}>
                        Forgot password?
                      </button>
                    </div>
                  )}

                  {/* Strength meter — register only */}
                  {isReg && pw.length > 0 && (
                    <div className="mt-3">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex gap-1">
                          {[1,2,3,4,5].map(i => (
                            <div key={i} className="h-1 w-9 rounded-full transition-all duration-300"
                                 style={{ background: i <= strength.score ? strength.color : "rgba(255,255,255,0.07)" }} />
                          ))}
                        </div>
                        <span className="text-[11px] font-semibold" style={{ color: strength.color }}>
                          {strength.label}
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-x-3 gap-y-1">
                        {pwReqs.map(r => (
                          <div key={r.label} className="flex items-center gap-1.5">
                            <div className="w-3.5 h-3.5 rounded-full flex items-center justify-center shrink-0"
                                 style={{ background: r.met ? "rgba(16,185,129,0.15)" : "rgba(255,255,255,0.04)",
                                          border:`1px solid ${r.met ? "#10b981" : "rgba(255,255,255,0.1)"}` }}>
                              {r.met && <span className="text-[8px]" style={{ color:"#10b981" }}>✓</span>}
                            </div>
                            <span className="text-[11px]"
                                  style={{ color: r.met ? T.muted : T.subtle }}>{r.label}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </Field>

                {/* Country — register only */}
                {isReg && (
                  <Field label="Country">
                    <div className="relative">
                      <Globe size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none"
                             style={{ color: T.subtle }} />
                      <select value={country} onChange={e => setCountry(e.target.value)}
                        className="w-full pl-10 pr-8 py-2.5 text-sm rounded-xl border focus:outline-none transition-all appearance-none cursor-pointer"
                        style={{ ...inputBase, color: country ? T.text : T.subtle, background:"#0b1020" }}
                        onFocus={e => (e.target.style.borderColor = T.indigo)}
                        onBlur={e  => (e.target.style.borderColor = T.border)}>
                        <option value="" disabled style={{ background:"#0b1020", color: T.subtle }}>Select your country</option>
                        {COUNTRIES.map(c => (
                          <option key={c} value={c} style={{ background:"#0b1020", color: T.text }}>{c}</option>
                        ))}
                      </select>
                      <div className="absolute right-3.5 top-1/2 -translate-y-1/2 pointer-events-none">
                        <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
                          <path d="M1.5 3.5L5 7l3.5-3.5" stroke={T.subtle} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                        </svg>
                      </div>
                    </div>
                  </Field>
                )}

                {/* 2FA notice — register */}
                {isReg && (
                  <div className="flex items-start gap-3 px-3.5 py-3 rounded-xl"
                       style={{ background:"rgba(99,102,241,0.06)", border:"1px solid rgba(99,102,241,0.15)" }}>
                    <Shield size={14} className="shrink-0 mt-0.5" style={{ color: T.indigo }} />
                    <p className="text-[12px] leading-relaxed" style={{ color: T.muted }}>
                      <span className="font-semibold" style={{ color: T.text }}>Two-step verification</span> will be
                      set up after account creation to protect your SOC.
                    </p>
                  </div>
                )}

                {/* Passkey notice — register */}
                {isReg && passkeySupported && (
                  <div className="flex items-start gap-3 px-3.5 py-3 rounded-xl"
                       style={{ background:"rgba(139,92,246,0.06)", border:"1px solid rgba(139,92,246,0.15)" }}>
                    <Fingerprint size={14} className="shrink-0 mt-0.5" style={{ color: T.purple }} />
                    <p className="text-[12px] leading-relaxed" style={{ color: T.muted }}>
                      <span className="font-semibold" style={{ color: T.text }}>Passkey</span> registration
                      (Face ID / Touch ID) will be offered after 2FA setup.
                    </p>
                  </div>
                )}

                {error && (
                  <div className="flex items-center gap-2 px-3 py-2.5 rounded-xl text-[12px]"
                       style={{ background:"rgba(239,68,68,0.08)", border:"1px solid rgba(239,68,68,0.2)", color:"#f87171" }}>
                    <span>⚠</span> {error}
                  </div>
                )}

                <button type="submit"
                  disabled={!pw || loading || (isReg && (!country || strength.score < 2))}
                  className="w-full py-3 rounded-xl text-sm font-semibold transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                  style={{ background:"linear-gradient(135deg,#6366f1,#8b5cf6)", color:"#fff",
                           boxShadow:"0 4px 20px rgba(99,102,241,0.25)" }}>
                  {loading
                    ? <><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Verifying…</>
                    : <>{isReg ? "Create Account" : "Continue"} <ChevronRight size={15} /></>
                  }
                </button>
              </form>

              {passkeySupported && !canPasskeyLogin && !isReg && (
                <p className="text-center text-[11px] mt-5" style={{ color: T.subtle }}>
                  You can register a passkey after signing in.
                </p>
              )}
            </>
          )}

          {/* ─────── STEP: 2FA ─────── */}
          {step === "totp" && (
            <div className="text-center">
              <div className="w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-6"
                   style={{ background:"rgba(99,102,241,0.1)", border:"1px solid rgba(99,102,241,0.2)" }}>
                <Shield size={28} style={{ color: T.indigo }} />
              </div>
              <h1 className="text-[22px] font-black mb-2" style={{ color: T.text }}>
                Two-step verification
              </h1>
              <p className="text-[13px] mb-8 leading-relaxed" style={{ color: T.muted }}>
                Enter the 6-digit code from your<br/>authenticator app to continue.
              </p>

              <div className="mb-6">
                <TotpInputs onComplete={handleTotp} />
              </div>

              {loading && (
                <div className="flex items-center justify-center gap-2 mb-4" style={{ color: T.muted }}>
                  <span className="w-4 h-4 border-2 border-slate-600 border-t-indigo-500 rounded-full animate-spin" />
                  <span className="text-[13px]">Verifying…</span>
                </div>
              )}
              {error && (
                <div className="flex items-center justify-center gap-2 px-3 py-2.5 rounded-xl text-[12px] mb-4"
                     style={{ background:"rgba(239,68,68,0.08)", border:"1px solid rgba(239,68,68,0.2)", color:"#f87171" }}>
                  <span>⚠</span> {error}
                </div>
              )}

              <button type="button" onClick={() => { setStep("credentials"); setError(""); }}
                className="w-full py-2.5 rounded-xl text-sm font-medium transition-colors mt-1"
                style={{ border:`1px solid ${T.border}`, color: T.muted }}>
                ← Back
              </button>
              <p className="text-[11px] mt-4" style={{ color: T.subtle }}>
                No 2FA set up? Enter any 6 digits to continue.
              </p>
            </div>
          )}

          {/* ─────── STEP: Passkey ─────── */}
          {step === "passkey_prompt" && (
            <div className="text-center">
              <div className="w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-6"
                   style={{ background:"rgba(139,92,246,0.1)", border:"1px solid rgba(139,92,246,0.2)" }}>
                <Fingerprint size={28} style={{ color: T.purple }} />
              </div>
              <h1 className="text-[22px] font-black mb-2" style={{ color: T.text }}>Set up a passkey</h1>
              <p className="text-[13px] mb-7 leading-relaxed" style={{ color: T.muted }}>
                Sign in instantly next time using your device biometrics<br/>or PIN — no password required.
              </p>

              <div className="grid grid-cols-3 gap-2 mb-7">
                {[
                  { icon:"🪪", label:"Face ID" },
                  { icon:"👆", label:"Touch ID" },
                  { icon:"🔑", label:"Device PIN" },
                ].map(m => (
                  <div key={m.label} className="py-3.5 rounded-xl"
                       style={{ background:"rgba(255,255,255,0.03)", border:`1px solid ${T.border}` }}>
                    <div className="text-[22px] mb-1">{m.icon}</div>
                    <p className="text-[10px] font-semibold" style={{ color: T.subtle }}>{m.label}</p>
                  </div>
                ))}
              </div>

              {error && (
                <div className="flex items-center justify-center gap-2 px-3 py-2.5 rounded-xl text-[12px] mb-4"
                     style={{ background:"rgba(239,68,68,0.08)", border:"1px solid rgba(239,68,68,0.2)", color:"#f87171" }}>
                  <span>⚠</span> {error}
                </div>
              )}

              <div className="space-y-2.5">
                <button onClick={handlePasskeySetup} disabled={loading || !passkeySupported}
                  className="w-full py-3 rounded-xl text-sm font-semibold transition-all disabled:opacity-40 flex items-center justify-center gap-2"
                  style={{ background:"linear-gradient(135deg,#6366f1,#8b5cf6)", color:"#fff",
                           boxShadow:"0 4px 20px rgba(99,102,241,0.25)" }}>
                  {loading
                    ? <><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Setting up…</>
                    : <><Fingerprint size={15} /> Set up passkey</>
                  }
                </button>
                <button type="button" onClick={() => { router.push("/"); router.refresh(); }}
                  className="w-full py-2.5 rounded-xl text-sm font-medium transition-colors"
                  style={{ border:`1px solid ${T.border}`, color: T.muted }}>
                  Skip for now
                </button>
              </div>

              {!passkeySupported && (
                <p className="text-[11px] mt-4" style={{ color:"#f59e0b" }}>
                  Your browser doesn't support passkeys.
                </p>
              )}
            </div>
          )}

          {/* ─────── STEP: forgot password ─────── */}
          {step === "forgot" && (
            <div className="text-center">
              <div className="w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-6"
                   style={{ background:"rgba(99,102,241,0.1)", border:"1px solid rgba(99,102,241,0.2)" }}>
                <Mail size={28} style={{ color: T.indigo }} />
              </div>
              <h1 className="text-[22px] font-black mb-2" style={{ color: T.text }}>Reset your password</h1>
              <p className="text-[13px] mb-8 leading-relaxed" style={{ color: T.muted }}>
                Enter your email and we'll send you<br/>a secure reset link.
              </p>

              <form onSubmit={handleForgot} className="space-y-4 text-left">
                <Field label="Email address">
                  <div className="relative">
                    <Mail size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none"
                          style={{ color: T.subtle }} />
                    <input type="email" placeholder="you@company.com" value={email}
                      onChange={e => setEmail(e.target.value)} autoFocus autoComplete="email"
                      className="w-full pl-10 pr-4 py-2.5 text-sm rounded-xl border focus:outline-none transition-all"
                      style={inputBase}
                      onFocus={e => (e.target.style.borderColor = T.indigo)}
                      onBlur={e  => (e.target.style.borderColor = T.border)} />
                  </div>
                </Field>

                {error && (
                  <div className="flex items-center gap-2 px-3 py-2.5 rounded-xl text-[12px]"
                       style={{ background:"rgba(239,68,68,0.08)", border:"1px solid rgba(239,68,68,0.2)", color:"#f87171" }}>
                    <span>⚠</span> {error}
                  </div>
                )}

                <button type="submit" disabled={!email || loading}
                  className="w-full py-3 rounded-xl text-sm font-semibold transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                  style={{ background:"linear-gradient(135deg,#6366f1,#8b5cf6)", color:"#fff",
                           boxShadow:"0 4px 20px rgba(99,102,241,0.25)" }}>
                  {loading
                    ? <><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Sending…</>
                    : <>Send reset link <ChevronRight size={15} /></>
                  }
                </button>

                <button type="button" onClick={() => { setStep("credentials"); setError(""); }}
                  className="w-full py-2.5 rounded-xl text-sm font-medium transition-colors"
                  style={{ border:`1px solid ${T.border}`, color: T.muted }}>
                  ← Back to sign in
                </button>
              </form>
            </div>
          )}

          {/* ─────── STEP: forgot sent ─────── */}
          {step === "forgot_sent" && (
            <div className="text-center">
              <div className="w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-6"
                   style={{ background:"rgba(16,185,129,0.1)", border:"1px solid rgba(16,185,129,0.2)" }}>
                <span className="text-[28px]">✉️</span>
              </div>
              <h1 className="text-[22px] font-black mb-2" style={{ color: T.text }}>Check your email</h1>
              <p className="text-[13px] mb-2 leading-relaxed" style={{ color: T.muted }}>
                If <span className="font-semibold" style={{ color: T.text }}>{email}</span> is registered,
                you'll receive a reset link within a few minutes.
              </p>
              <p className="text-[12px] mb-8" style={{ color: T.subtle }}>
                Don't forget to check your spam folder.
              </p>

              <div className="space-y-2.5">
                <button type="button" onClick={() => { setStep("forgot"); setError(""); }}
                  className="w-full py-3 rounded-xl text-sm font-semibold transition-all flex items-center justify-center gap-2"
                  style={{ background:"linear-gradient(135deg,#6366f1,#8b5cf6)", color:"#fff",
                           boxShadow:"0 4px 20px rgba(99,102,241,0.25)" }}>
                  Resend email
                </button>
                <button type="button" onClick={() => { setStep("credentials"); setError(""); }}
                  className="w-full py-2.5 rounded-xl text-sm font-medium transition-colors"
                  style={{ border:`1px solid ${T.border}`, color: T.muted }}>
                  ← Back to sign in
                </button>
              </div>
            </div>
          )}

          {/* Step dots — only on the main auth flow */}
          {step !== "credentials" && step !== "forgot" && step !== "forgot_sent" && (
            <div className="flex justify-center gap-2 mt-8">
              {(["credentials","totp","passkey_prompt"] as Step[]).map((s, i) => (
                <div key={s} className="rounded-full transition-all duration-300"
                     style={{
                       width: step===s ? 24 : 6, height: 6,
                       background: step===s ? T.indigo
                         : (["credentials","totp","passkey_prompt"].indexOf(step) > i ? T.purple : T.border),
                     }} />
              ))}
            </div>
          )}
        </div>

        <p className="text-[11px] mt-10" style={{ color: T.subtle }}>
          Shadow Warden AI · SOC Operations Centre
        </p>
      </div>
    </div>
  );
}
