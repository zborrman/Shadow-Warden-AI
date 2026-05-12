"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Shield, Key, Globe, BookOpen, Users, CreditCard, AlertTriangle,
  CheckCircle, Plus, Trash2, Eye, EyeOff, Copy, HelpCircle,
  Activity, RefreshCcw, Zap, Lock, Bot, Cpu, ChevronRight,
  TriangleAlert, Check,
} from "lucide-react";
import { cn } from "@/lib/utils";

// ─── Design tokens (match sw-* from design system) ──────────────────
const sw = {
  bg:        "#050810",
  surf1:     "#0a0e1a",
  surf2:     "#0d1220",
  surf3:     "#111828",
  surf4:     "#1a2236",
  border:    "rgba(124,58,237,0.14)",
  borderStr: "rgba(124,58,237,0.30)",
  indigo:    "#7c3aed",
  indigoLt:  "#a78bfa",
  green:     "#10b981",
  amber:     "#f59e0b",
  red:       "#ef4444",
  redLt:     "#f87171",
  fg1:       "#f1f5f9",
  fg2:       "#cbd5e1",
  fg3:       "#94a3b8",
  fg4:       "#64748b",
};

// ─── Types ────────────────────────────────────────────────────────────
type Sensitivity = "strict" | "balanced" | "lenient";

interface PipelineSettings {
  semanticBrain:     boolean;
  evolutionEngine:   boolean;
  gdprStrict:        boolean;
  sensitivity:       Sensitivity;
  rateLimit:         number;
  cachingEnabled:    boolean;
  topologyGuard:     boolean;
  obfuscationDecode: boolean;
  secretRedaction:   boolean;
  phishGuard:        boolean;
}

interface ApiKeyEntry {
  id:        string;
  name:      string;
  prefix:    string;
  created:   string;
  last_used: string | null;
  requests:  number;
}

interface WebhookEntry {
  id:     string;
  url:    string;
  events: string[];
  active: boolean;
}

// ─── Defaults ─────────────────────────────────────────────────────────
const DEFAULT_PIPELINE: PipelineSettings = {
  semanticBrain:     true,
  evolutionEngine:   false,
  gdprStrict:        true,
  sensitivity:       "balanced",
  rateLimit:         240,
  cachingEnabled:    true,
  topologyGuard:     true,
  obfuscationDecode: true,
  secretRedaction:   true,
  phishGuard:        true,
};

const STORAGE_KEY = "sw_pipeline_settings";
const KEYS_KEY    = "sw_api_keys";
const HOOKS_KEY   = "sw_webhooks";

// ─── Persistence helpers ──────────────────────────────────────────────
function loadSettings(): PipelineSettings {
  if (typeof window === "undefined") return DEFAULT_PIPELINE;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? { ...DEFAULT_PIPELINE, ...JSON.parse(raw) } : DEFAULT_PIPELINE;
  } catch { return DEFAULT_PIPELINE; }
}

function saveSettings(s: PipelineSettings) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(s));
}

function loadApiKeys(): ApiKeyEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(KEYS_KEY);
    return raw ? JSON.parse(raw) : [
      { id: "k1", name: "Production", prefix: "sw-prod-xxxx", created: "2026-01-15", last_used: "2 min ago", requests: 148320 },
      { id: "k2", name: "Development", prefix: "sw-dev-xxxx", created: "2026-03-02", last_used: "1 hr ago",  requests: 4201 },
    ];
  } catch { return []; }
}

function loadWebhooks(): WebhookEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(HOOKS_KEY);
    return raw ? JSON.parse(raw) : [
      { id: "wh1", url: "https://hooks.slack.com/services/xxx", events: ["BLOCK", "HIGH"], active: true },
    ];
  } catch { return []; }
}

// ─── Sub-components ───────────────────────────────────────────────────
function Toggle({ on, onChange }: { on: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      onClick={() => onChange(!on)}
      role="switch"
      aria-checked={on}
      style={{
        width: 36, height: 20, borderRadius: 100, border: "none", flexShrink: 0,
        background: on ? sw.indigo : sw.surf4,
        position: "relative", cursor: "pointer", transition: "background 0.2s",
      }}
    >
      <div style={{
        width: 14, height: 14, borderRadius: "50%", background: "#fff",
        position: "absolute", top: 3, left: on ? 19 : 3, transition: "left 0.2s",
      }} />
    </button>
  );
}

function Segmented({
  options, value, onChange,
}: { options: string[]; value: string; onChange: (v: string) => void }) {
  return (
    <div style={{
      display: "inline-flex", background: sw.surf2,
      border: `1px solid ${sw.border}`, borderRadius: 8, padding: 3, gap: 2,
    }}>
      {options.map(opt => (
        <button key={opt} onClick={() => onChange(opt)} style={{
          padding: "5px 12px", borderRadius: 5, border: "none", fontSize: 12,
          color: value === opt ? sw.fg1 : sw.fg4,
          background: value === opt ? sw.surf3 : "transparent",
          boxShadow: value === opt ? `0 0 0 1px ${sw.borderStr}` : "none",
          cursor: "pointer", fontFamily: "inherit", textTransform: "capitalize",
          transition: "all 0.15s",
        }}>
          {opt}
        </button>
      ))}
    </div>
  );
}

function ExplainBox({ children }: { children: React.ReactNode }) {
  return (
    <div style={{
      marginTop: 10, padding: "10px 14px",
      background: "rgba(124,58,237,0.06)",
      border: `1px solid rgba(124,58,237,0.20)`,
      borderLeft: `2px solid ${sw.indigo}`,
      borderRadius: 6, fontSize: 12.5, color: sw.fg2, lineHeight: 1.6,
    }}>
      <div style={{
        fontSize: 9.5, fontWeight: 700, color: sw.indigo,
        textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 6,
        fontFamily: "var(--font-mono, monospace)",
      }}>Best practice</div>
      {children}
    </div>
  );
}

function SettingRow({
  title, hint, tag, meta, explain, children,
}: {
  title: string;
  hint: string;
  tag?: { label: string; color: string; bg: string };
  meta?: React.ReactNode;
  explain?: React.ReactNode;
  children: React.ReactNode;
}) {
  const [showHelp, setShowHelp] = useState(false);
  return (
    <div style={{
      display: "grid", gridTemplateColumns: "1fr auto",
      gap: 24, alignItems: "flex-start",
      padding: "16px 0", borderBottom: `1px solid ${sw.border}`,
    }}>
      <div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
          <span style={{ fontSize: 14, fontWeight: 600, color: sw.fg1 }}>{title}</span>
          {tag && (
            <span style={{
              fontFamily: "var(--font-mono, monospace)", fontSize: 9,
              padding: "1px 6px", borderRadius: 4, fontWeight: 700,
              letterSpacing: "0.06em", textTransform: "uppercase",
              background: tag.bg, color: tag.color,
            }}>{tag.label}</span>
          )}
          {explain && (
            <button
              onClick={() => setShowHelp(h => !h)}
              style={{
                width: 16, height: 16, borderRadius: "50%", border: `1px solid ${sw.borderStr}`,
                background: "transparent", color: sw.fg3, fontSize: 9, fontWeight: 700,
                cursor: "pointer", display: "inline-flex", alignItems: "center",
                justifyContent: "center", padding: 0, fontFamily: "inherit",
              }}
            >?</button>
          )}
        </div>
        <div style={{ fontSize: 12.5, color: sw.fg2, lineHeight: 1.5, maxWidth: 520 }}>{hint}</div>
        {meta && (
          <div style={{
            marginTop: 5, fontFamily: "var(--font-mono, monospace)",
            fontSize: 10.5, color: sw.fg4, letterSpacing: "0.04em",
          }}>{meta}</div>
        )}
        {showHelp && explain && <ExplainBox>{explain}</ExplainBox>}
      </div>
      <div style={{ paddingTop: 2 }}>{children}</div>
    </div>
  );
}

// ─── Tab panels ───────────────────────────────────────────────────────

function FilterPipelinePanel({
  settings, setSettings,
}: { settings: PipelineSettings; setSettings: (s: PipelineSettings) => void }) {
  const set = <K extends keyof PipelineSettings>(k: K, v: PipelineSettings[K]) =>
    setSettings({ ...settings, [k]: v });

  return (
    <>
      {/* 9-layer stages — quick toggles */}
      <div style={{
        background: sw.surf2, border: `1px solid ${sw.border}`,
        borderRadius: 10, padding: "14px 18px", marginBottom: 4,
      }}>
        <div style={{
          fontSize: 10, fontWeight: 700, textTransform: "uppercase",
          letterSpacing: "0.1em", color: sw.fg4,
          fontFamily: "var(--font-mono, monospace)", marginBottom: 12,
        }}>Pipeline stages</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px 24px" }}>
          {([
            ["topologyGuard",     "Topology Guard",      "β₀/β₁ Betti numbers, <2ms"],
            ["obfuscationDecode", "Obfuscation Decoder", "base64/hex/ROT13/homoglyphs"],
            ["secretRedaction",   "Secret Redaction",    "15 patterns + entropy scan"],
            ["semanticBrain",     "SemanticBrain ML",    "MiniLM + Poincaré, ~15ms"],
            ["phishGuard",        "PhishGuard",          "URL + social engineering"],
            ["cachingEnabled",    "Redis Cache",         "5-min TTL, SHA-256 content hash"],
          ] as [keyof PipelineSettings, string, string][]).map(([k, label, note]) => (
            <div key={k} style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
              <Toggle on={settings[k] as boolean} onChange={v => set(k, v as PipelineSettings[typeof k])} />
              <div>
                <div style={{ fontSize: 12.5, fontWeight: 600, color: sw.fg1 }}>{label}</div>
                <div style={{ fontSize: 10.5, color: sw.fg4, fontFamily: "var(--font-mono, monospace)" }}>{note}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <SettingRow
        title="EvolutionEngine"
        hint="Auto-generate new detection rules from blocked attacks via Claude Opus. Hot-reloads without restart."
        tag={{ label: "Beta", color: "#fbbf24", bg: "rgba(251,191,36,0.14)" }}
        explain={<>Enable in <strong style={{ color: sw.fg1 }}>staging first</strong>. Consumes Anthropic API credits. Review generated corpus weekly under <strong style={{ color: sw.fg1 }}>Rules → Auto-generated</strong>.</>}
      >
        <Toggle on={settings.evolutionEngine} onChange={v => set("evolutionEngine", v)} />
      </SettingRow>

      <SettingRow
        title="GDPR strict mode"
        hint="Never log request content — only metadata (type, length, timing) is persisted. Required for EU deployments."
        tag={{ label: "EU · SOC 2", color: "#22d3ee", bg: "rgba(34,211,238,0.12)" }}
        meta={<>Endpoints <strong style={{ color: sw.fg3 }}>/gdpr/export</strong> and <strong style={{ color: sw.fg3 }}>/gdpr/purge</strong> rely on this</>}
        explain={<>Required for EU deployments and SOC 2. Disabling is only safe in air-gapped dev environments. Turning off will log raw content — never do this in production.</>}
      >
        <Toggle on={settings.gdprStrict} onChange={v => set("gdprStrict", v)} />
      </SettingRow>

      <SettingRow
        title="Sensitivity profile"
        hint={<>Tradeoff between false-positive rate and recall. <strong style={{ color: sw.fg1 }}>Balanced</strong> works for most workloads.</> as unknown as string}
        explain={<><strong style={{ color: sw.fg1 }}>Strict</strong> blocks more, may flag legitimate prompts. <strong style={{ color: sw.fg1 }}>Balanced</strong> is recommended for most. <strong style={{ color: sw.fg1 }}>Lenient</strong> for chatbots where UX matters more than security.</>}
      >
        <Segmented
          options={["strict", "balanced", "lenient"]}
          value={settings.sensitivity}
          onChange={v => set("sensitivity", v as Sensitivity)}
        />
      </SettingRow>

      <SettingRow
        title="Rate limit (per API key)"
        hint="Hard cap on requests per API key per minute. Above 1,000 may require dedicated Redis."
        explain={<>Use 60 for dev keys, 600+ for production. Going above 1,000 req/min may require dedicated Redis. Check <strong style={{ color: sw.fg1 }}>Dashboard → Metrics → p99 latency</strong> before raising.</>}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input
            type="number"
            value={settings.rateLimit}
            min={1} max={10000}
            onChange={e => set("rateLimit", Number(e.target.value))}
            style={{
              background: sw.surf2, border: `1px solid ${sw.border}`,
              borderRadius: 8, color: sw.fg1,
              fontFamily: "var(--font-mono, monospace)", fontSize: 12.5,
              padding: "6px 10px", width: 90, textAlign: "right", outline: "none",
            }}
          />
          <span style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 11, color: sw.fg4 }}>req/min</span>
        </div>
      </SettingRow>
    </>
  );
}

function ApiKeysPanel() {
  const [keys, setKeys]       = useState<ApiKeyEntry[]>([]);
  const [showNew, setShowNew] = useState(false);
  const [newName, setNewName] = useState("");
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});
  const [copied, setCopied]   = useState<string | null>(null);

  useEffect(() => { setKeys(loadApiKeys()); }, []);
  const persist = (k: ApiKeyEntry[]) => { setKeys(k); localStorage.setItem(KEYS_KEY, JSON.stringify(k)); };

  const createKey = () => {
    if (!newName.trim()) return;
    const id = `k${Date.now()}`;
    const newKey: ApiKeyEntry = {
      id, name: newName.trim(),
      prefix: `sw-${newName.toLowerCase().slice(0,4)}-${Math.random().toString(36).slice(2,6)}`,
      created: new Date().toISOString().split("T")[0],
      last_used: null, requests: 0,
    };
    persist([...keys, newKey]);
    setNewName(""); setShowNew(false);
  };

  const revoke = (id: string) => persist(keys.filter(k => k.id !== id));

  const copy = (text: string, id: string) => {
    navigator.clipboard.writeText(text).catch(() => {});
    setCopied(id);
    setTimeout(() => setCopied(null), 1500);
  };

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
        <p style={{ fontSize: 12.5, color: sw.fg3, margin: 0 }}>
          API keys authenticate requests to <code style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 11 }}>/filter</code> and all warden endpoints.
        </p>
        <button
          onClick={() => setShowNew(true)}
          style={{
            display: "flex", alignItems: "center", gap: 6,
            padding: "7px 14px", borderRadius: 8, border: "none",
            background: `linear-gradient(135deg, ${sw.indigo}, #8b5cf6)`,
            color: "#fff", fontSize: 12.5, fontWeight: 600, cursor: "pointer",
          }}
        >
          <Plus size={13} /> New key
        </button>
      </div>

      {showNew && (
        <div style={{
          background: sw.surf2, border: `1px solid ${sw.borderStr}`,
          borderRadius: 10, padding: 16, marginBottom: 16,
        }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: sw.fg1, marginBottom: 10 }}>New API key</div>
          <div style={{ display: "flex", gap: 8 }}>
            <input
              placeholder="Key name (e.g. Production)"
              value={newName}
              onChange={e => setNewName(e.target.value)}
              onKeyDown={e => e.key === "Enter" && createKey()}
              autoFocus
              style={{
                flex: 1, background: sw.surf3, border: `1px solid ${sw.border}`,
                borderRadius: 8, color: sw.fg1, fontSize: 13, padding: "7px 12px",
                outline: "none", fontFamily: "inherit",
              }}
            />
            <button onClick={createKey} style={{
              padding: "7px 16px", borderRadius: 8, border: "none",
              background: sw.indigo, color: "#fff", fontSize: 12.5, fontWeight: 600, cursor: "pointer",
            }}>Create</button>
            <button onClick={() => setShowNew(false)} style={{
              padding: "7px 12px", borderRadius: 8, border: `1px solid ${sw.border}`,
              background: "transparent", color: sw.fg3, fontSize: 12.5, cursor: "pointer",
            }}>Cancel</button>
          </div>
        </div>
      )}

      <div style={{ border: `1px solid ${sw.border}`, borderRadius: 10, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
          <thead>
            <tr style={{ background: sw.surf2, borderBottom: `1px solid ${sw.border}` }}>
              {["Name", "Key", "Created", "Last used", "Requests", ""].map(h => (
                <th key={h} style={{
                  padding: "9px 14px", textAlign: "left", fontWeight: 600,
                  fontSize: 10, textTransform: "uppercase", letterSpacing: "0.08em",
                  color: sw.fg4, fontFamily: "var(--font-mono, monospace)",
                }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {keys.map((k, i) => (
              <tr key={k.id} style={{
                borderBottom: i < keys.length - 1 ? `1px solid ${sw.border}` : "none",
                transition: "background 0.15s",
              }}
                onMouseEnter={e => (e.currentTarget.style.background = sw.surf2)}
                onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
              >
                <td style={{ padding: "12px 14px", fontWeight: 600, color: sw.fg1 }}>{k.name}</td>
                <td style={{ padding: "12px 14px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <code style={{
                      fontFamily: "var(--font-mono, monospace)", fontSize: 11,
                      color: sw.fg3, letterSpacing: "0.04em",
                    }}>{revealed[k.id] ? k.prefix + "••••••••" : k.prefix.slice(0, 12) + "••••"}</code>
                    <button onClick={() => setRevealed(r => ({ ...r, [k.id]: !r[k.id] }))} style={{ background: "none", border: "none", cursor: "pointer", color: sw.fg4, padding: 0 }}>
                      {revealed[k.id] ? <EyeOff size={12} /> : <Eye size={12} />}
                    </button>
                    <button onClick={() => copy(k.prefix, k.id)} style={{ background: "none", border: "none", cursor: "pointer", color: copied === k.id ? sw.green : sw.fg4, padding: 0 }}>
                      {copied === k.id ? <Check size={12} /> : <Copy size={12} />}
                    </button>
                  </div>
                </td>
                <td style={{ padding: "12px 14px", color: sw.fg4, fontFamily: "var(--font-mono, monospace)", fontSize: 11 }}>{k.created}</td>
                <td style={{ padding: "12px 14px", color: k.last_used ? sw.fg3 : sw.fg4, fontFamily: "var(--font-mono, monospace)", fontSize: 11 }}>{k.last_used ?? "never"}</td>
                <td style={{ padding: "12px 14px", color: sw.fg3, fontFamily: "var(--font-mono, monospace)", fontSize: 11 }}>{k.requests.toLocaleString()}</td>
                <td style={{ padding: "12px 14px" }}>
                  <button onClick={() => revoke(k.id)} style={{
                    padding: "4px 10px", borderRadius: 6, border: `1px solid rgba(239,68,68,0.25)`,
                    background: "transparent", color: sw.redLt, fontSize: 11,
                    cursor: "pointer", display: "flex", alignItems: "center", gap: 4,
                  }}>
                    <Trash2 size={11} /> Revoke
                  </button>
                </td>
              </tr>
            ))}
            {keys.length === 0 && (
              <tr><td colSpan={6} style={{ padding: "24px 14px", textAlign: "center", color: sw.fg4, fontSize: 12.5 }}>No API keys — create one above.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function WebhooksPanel() {
  const [hooks, setHooks]   = useState<WebhookEntry[]>([]);
  const [newUrl, setNewUrl] = useState("");
  const [testing, setTesting] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<Record<string, "ok" | "err">>({});

  useEffect(() => { setHooks(loadWebhooks()); }, []);
  const persist = (h: WebhookEntry[]) => { setHooks(h); localStorage.setItem(HOOKS_KEY, JSON.stringify(h)); };

  const addHook = () => {
    if (!newUrl.trim() || !newUrl.startsWith("http")) return;
    const id = `wh${Date.now()}`;
    persist([...hooks, { id, url: newUrl.trim(), events: ["BLOCK", "HIGH"], active: true }]);
    setNewUrl("");
  };

  const remove = (id: string) => persist(hooks.filter(h => h.id !== id));
  const toggle = (id: string) => persist(hooks.map(h => h.id === id ? { ...h, active: !h.active } : h));

  const test = async (h: WebhookEntry) => {
    setTesting(h.id);
    try {
      await fetch(h.url, {
        method: "POST", mode: "no-cors",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: "ping", source: "shadow-warden-test", ts: Date.now() }),
      });
      setTestResult(r => ({ ...r, [h.id]: "ok" }));
    } catch {
      setTestResult(r => ({ ...r, [h.id]: "err" }));
    }
    setTesting(null);
    setTimeout(() => setTestResult(r => { const n = { ...r }; delete n[h.id]; return n; }), 3000);
  };

  const EVENT_OPTS = ["BLOCK", "HIGH", "MEDIUM", "ALLOW", "SHADOW_BAN", "SECRET_FOUND"];

  const toggleEvent = (id: string, ev: string) => {
    persist(hooks.map(h => {
      if (h.id !== id) return h;
      const evts = h.events.includes(ev) ? h.events.filter(e => e !== ev) : [...h.events, ev];
      return { ...h, events: evts };
    }));
  };

  return (
    <div>
      <div style={{
        background: "rgba(124,58,237,0.05)", border: `1px solid rgba(124,58,237,0.18)`,
        borderRadius: 8, padding: "10px 14px", marginBottom: 18, fontSize: 12.5, color: sw.fg3,
      }}>
        Webhooks fire a <code style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 11 }}>POST</code> request to your URL on each selected event.
        Shadow Warden sends HMAC-SHA256 signed payloads — verify the <code style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 11 }}>X-Warden-Signature</code> header.
      </div>

      <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
        <input
          placeholder="https://hooks.example.com/..."
          value={newUrl}
          onChange={e => setNewUrl(e.target.value)}
          onKeyDown={e => e.key === "Enter" && addHook()}
          style={{
            flex: 1, background: sw.surf2, border: `1px solid ${sw.border}`,
            borderRadius: 8, color: sw.fg1, fontSize: 13, padding: "8px 12px",
            outline: "none", fontFamily: "inherit",
          }}
        />
        <button onClick={addHook} style={{
          padding: "8px 16px", borderRadius: 8, border: "none",
          background: `linear-gradient(135deg, ${sw.indigo}, #8b5cf6)`,
          color: "#fff", fontSize: 12.5, fontWeight: 600, cursor: "pointer",
          display: "flex", alignItems: "center", gap: 6,
        }}><Plus size={13} /> Add</button>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {hooks.map(h => (
          <div key={h.id} style={{
            background: sw.surf2, border: `1px solid ${sw.border}`,
            borderRadius: 10, padding: "14px 16px",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
              <div style={{
                width: 8, height: 8, borderRadius: "50%", flexShrink: 0,
                background: h.active ? sw.green : sw.fg4,
              }} />
              <code style={{
                flex: 1, fontFamily: "var(--font-mono, monospace)", fontSize: 12,
                color: sw.fg2, wordBreak: "break-all",
              }}>{h.url}</code>
              <button onClick={() => toggle(h.id)} style={{
                padding: "3px 10px", borderRadius: 6, border: `1px solid ${sw.border}`,
                background: "transparent", color: h.active ? sw.green : sw.fg4,
                fontSize: 11, cursor: "pointer",
              }}>{h.active ? "Active" : "Paused"}</button>
              <button onClick={() => test(h)} disabled={testing === h.id} style={{
                padding: "3px 10px", borderRadius: 6, border: `1px solid ${sw.borderStr}`,
                background: "transparent", color: testResult[h.id] === "ok" ? sw.green : testResult[h.id] === "err" ? sw.red : sw.indigoLt,
                fontSize: 11, cursor: "pointer",
              }}>
                {testing === h.id ? "Sending…" : testResult[h.id] === "ok" ? "✓ Sent" : testResult[h.id] === "err" ? "✗ Failed" : "Test"}
              </button>
              <button onClick={() => remove(h.id)} style={{ background: "none", border: "none", cursor: "pointer", color: sw.fg4, padding: 0 }}>
                <Trash2 size={13} />
              </button>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
              {EVENT_OPTS.map(ev => (
                <button key={ev} onClick={() => toggleEvent(h.id, ev)} style={{
                  padding: "2px 8px", borderRadius: 4, border: `1px solid`,
                  borderColor: h.events.includes(ev) ? sw.indigo : sw.border,
                  background: h.events.includes(ev) ? "rgba(124,58,237,0.15)" : "transparent",
                  color: h.events.includes(ev) ? sw.indigoLt : sw.fg4,
                  fontSize: 10, fontWeight: 600, cursor: "pointer",
                  fontFamily: "var(--font-mono, monospace)", textTransform: "uppercase",
                  letterSpacing: "0.06em",
                }}>{ev}</button>
              ))}
            </div>
          </div>
        ))}
        {hooks.length === 0 && (
          <div style={{ textAlign: "center", color: sw.fg4, fontSize: 12.5, padding: "24px 0" }}>No webhooks yet.</div>
        )}
      </div>
    </div>
  );
}

function PlaceholderPanel({ label, icon: Icon }: { label: string; icon: React.ElementType }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "60px 24px", color: sw.fg4 }}>
      <Icon size={32} style={{ marginBottom: 12, opacity: 0.4 }} />
      <div style={{ fontSize: 14, fontWeight: 600, color: sw.fg3, marginBottom: 6 }}>{label}</div>
      <div style={{ fontSize: 12.5, textAlign: "center", maxWidth: 320 }}>
        This section is configured via the <code style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 11 }}>warden/main.py</code> FastAPI gateway.
        Use the SOVA agent or contact your administrator.
      </div>
    </div>
  );
}

function DangerZonePanel({ onReset }: { onReset: () => void }) {
  const [confirm, setConfirm] = useState(false);
  return (
    <div>
      <div style={{
        background: "rgba(239,68,68,0.04)", border: `1px solid rgba(239,68,68,0.18)`,
        borderRadius: 10, padding: "16px 20px", marginBottom: 12,
      }}>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 600, color: sw.fg1, marginBottom: 4 }}>Reset pipeline settings</div>
            <div style={{ fontSize: 12.5, color: sw.fg2 }}>Restore all Filter Pipeline settings to their factory defaults. Does not affect API keys or webhooks.</div>
          </div>
          {confirm ? (
            <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
              <button onClick={() => { onReset(); setConfirm(false); }} style={{
                padding: "7px 14px", borderRadius: 7, border: "none",
                background: sw.red, color: "#fff", fontSize: 12.5, fontWeight: 600, cursor: "pointer",
              }}>Confirm reset</button>
              <button onClick={() => setConfirm(false)} style={{
                padding: "7px 14px", borderRadius: 7, border: `1px solid ${sw.border}`,
                background: "transparent", color: sw.fg2, fontSize: 12.5, cursor: "pointer",
              }}>Cancel</button>
            </div>
          ) : (
            <button onClick={() => setConfirm(true)} style={{
              flexShrink: 0, padding: "7px 14px", borderRadius: 7,
              border: `1px solid rgba(239,68,68,0.30)`,
              background: "transparent", color: sw.redLt, fontSize: 12.5, cursor: "pointer",
            }}>Reset to defaults</button>
          )}
        </div>
      </div>

      <div style={{
        background: "rgba(239,68,68,0.04)", border: `1px solid rgba(239,68,68,0.18)`,
        borderRadius: 10, padding: "16px 20px",
      }}>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 600, color: sw.fg1, marginBottom: 4 }}>Purge all request logs</div>
            <div style={{ fontSize: 12.5, color: sw.fg2 }}>Permanently delete all logs. Required for GDPR Art. 17 "right to erasure" requests. Irreversible.</div>
            <div style={{ marginTop: 6, fontFamily: "var(--font-mono, monospace)", fontSize: 10.5, color: sw.fg4 }}>
              Endpoint: <span style={{ color: sw.fg3 }}>DELETE /gdpr/purge</span>
            </div>
          </div>
          <button
            onClick={() => window.open("https://api.shadow-warden-ai.com/gdpr/purge", "_blank")}
            style={{
              flexShrink: 0, padding: "7px 14px", borderRadius: 7,
              border: `1px solid rgba(239,68,68,0.30)`,
              background: "transparent", color: sw.redLt, fontSize: 12.5, cursor: "pointer",
            }}
          >Open GDPR console</button>
        </div>
      </div>
    </div>
  );
}

// ─── Sidebar nav items ────────────────────────────────────────────────
type Tab = "pipeline" | "apikeys" | "webhooks" | "rules" | "team" | "billing" | "danger";

const TABS: { id: Tab; label: string; icon: React.ElementType; count?: number; danger?: boolean }[] = [
  { id: "pipeline", label: "Filter pipeline",  icon: Shield },
  { id: "apikeys",  label: "API keys",          icon: Key,     count: 2 },
  { id: "webhooks", label: "Webhooks",           icon: Globe },
  { id: "rules",    label: "Rules",              icon: BookOpen },
  { id: "team",     label: "Team",               icon: Users,   count: 5 },
  { id: "billing",  label: "Billing",            icon: CreditCard },
  { id: "danger",   label: "Danger zone",        icon: AlertTriangle, danger: true },
];

// ─── Panel titles ─────────────────────────────────────────────────────
const PANEL_META: Record<Tab, { title: string; sub: string }> = {
  pipeline: { title: "Filter pipeline",  sub: "Tune how Shadow Warden inspects every AI request before it leaves your perimeter." },
  apikeys:  { title: "API keys",         sub: "Manage keys used to authenticate requests to /filter and all warden endpoints." },
  webhooks: { title: "Webhooks",         sub: "Forward BLOCK, HIGH, and SECRET_FOUND events to external systems in real time." },
  rules:    { title: "Detection rules",  sub: "Semantic guard rules that define what patterns trigger a FLAG or BLOCK verdict." },
  team:     { title: "Team",             sub: "Members with access to this tenant's dashboard and settings." },
  billing:  { title: "Billing",          sub: "Subscription tier, usage, and add-on marketplace." },
  danger:   { title: "Danger zone",      sub: "Destructive operations — proceed with care." },
};

// ─── Main page ────────────────────────────────────────────────────────
export default function SettingsPage() {
  const [tab, setTab]           = useState<Tab>("pipeline");
  const [settings, setSettings] = useState<PipelineSettings>(DEFAULT_PIPELINE);
  const [health, setHealth]     = useState<"ok" | "warn" | "loading">("loading");
  const [saving, setSaving]     = useState(false);
  const [saved, setSaved]       = useState(false);
  const [lastSaved, setLastSaved] = useState<string | null>(null);

  // Load persisted settings on mount
  useEffect(() => { setSettings(loadSettings()); }, []);

  // Poll health endpoint
  const checkHealth = useCallback(async () => {
    try {
      const res = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL ?? "https://api.shadow-warden-ai.com"}/health`,
        { cache: "no-store", signal: AbortSignal.timeout(3000) }
      );
      setHealth(res.ok ? "ok" : "warn");
    } catch {
      setHealth("warn");
    }
  }, []);

  useEffect(() => {
    checkHealth();
    const id = setInterval(checkHealth, 30_000);
    return () => clearInterval(id);
  }, [checkHealth]);

  const handleSave = async () => {
    setSaving(true);
    saveSettings(settings);
    // Attempt to PATCH live config if endpoint exists
    try {
      await fetch(
        `${process.env.NEXT_PUBLIC_API_URL ?? "https://api.shadow-warden-ai.com"}/config`,
        {
          method: "PATCH",
          headers: { "Content-Type": "application/json", "X-API-Key": "" },
          body: JSON.stringify({
            semantic_threshold: settings.sensitivity === "strict" ? 0.60 : settings.sensitivity === "balanced" ? 0.72 : 0.85,
            rate_limit_per_key: settings.rateLimit,
            gdpr_strict: settings.gdprStrict,
            evolution_enabled: settings.evolutionEngine,
          }),
          signal: AbortSignal.timeout(3000),
        }
      );
    } catch { /* fail-open — settings already persisted to localStorage */ }
    setSaving(false);
    setSaved(true);
    setLastSaved(new Date().toLocaleTimeString());
    setTimeout(() => setSaved(false), 2500);
  };

  const handleReset = () => {
    setSettings(DEFAULT_PIPELINE);
    saveSettings(DEFAULT_PIPELINE);
    setLastSaved(new Date().toLocaleTimeString());
  };

  const meta = PANEL_META[tab];

  return (
    <div style={{
      padding: 22, display: "grid",
      gridTemplateColumns: "200px 1fr",
      gap: 18, minHeight: "calc(100vh - 40px)",
      fontFamily: "Inter, system-ui, sans-serif",
    }}>
      {/* ── Settings sidebar ── */}
      <aside style={{
        background: sw.surf1, border: `1px solid ${sw.border}`,
        borderRadius: 12, padding: "14px 10px",
        display: "flex", flexDirection: "column", gap: 2,
        alignSelf: "start",
      }}>
        <div style={{
          fontFamily: "var(--font-mono, monospace)", fontSize: 10,
          color: sw.fg4, textTransform: "uppercase",
          letterSpacing: "0.10em", padding: "4px 10px 10px",
        }}>Settings</div>
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              display: "flex", alignItems: "center", gap: 10,
              padding: "8px 10px", borderRadius: 8, border: "none",
              fontSize: 13, cursor: "pointer", width: "100%", textAlign: "left",
              fontFamily: "inherit", transition: "background 0.15s",
              color: tab === t.id ? sw.fg1 : t.danger ? "#f87171" : sw.fg2,
              background: tab === t.id ? "rgba(124,58,237,0.12)" : "transparent",
              boxShadow: tab === t.id ? `inset 2px 0 0 ${sw.indigo}` : "none",
            }}
          >
            <t.icon size={14} style={{ color: tab === t.id ? sw.indigoLt : t.danger ? "#f87171" : sw.fg4, flexShrink: 0 }} />
            {t.label}
            {t.count !== undefined && (
              <span style={{
                marginLeft: "auto",
                fontFamily: "var(--font-mono, monospace)", fontSize: 10,
                color: sw.fg4, background: sw.surf3,
                padding: "1px 6px", borderRadius: 100,
              }}>{t.count}</span>
            )}
          </button>
        ))}
      </aside>

      {/* ── Main panel ── */}
      <section style={{
        background: sw.surf1, border: `1px solid ${sw.border}`,
        borderRadius: 12, overflow: "hidden",
        display: "flex", flexDirection: "column",
      }}>
        {/* Header */}
        <div style={{
          padding: "18px 24px 16px",
          borderBottom: `1px solid ${sw.border}`,
          display: "flex", alignItems: "flex-start",
          justifyContent: "space-between",
        }}>
          <div>
            <h2 style={{ margin: 0, fontSize: 18, fontWeight: 700, letterSpacing: "-0.015em", color: sw.fg1 }}>
              {meta.title}
            </h2>
            <div style={{ fontSize: 12, color: sw.fg3, marginTop: 3 }}>{meta.sub}</div>
          </div>
          <div style={{
            display: "inline-flex", alignItems: "center", gap: 5,
            padding: "3px 9px", borderRadius: 100,
            background: health === "ok" ? "rgba(16,185,129,0.10)" : health === "warn" ? "rgba(245,158,11,0.10)" : "rgba(100,116,139,0.10)",
            border: `1px solid ${health === "ok" ? "rgba(16,185,129,0.25)" : health === "warn" ? "rgba(245,158,11,0.25)" : "rgba(100,116,139,0.20)"}`,
            color: health === "ok" ? sw.green : health === "warn" ? sw.amber : sw.fg4,
            fontSize: 10, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em",
            flexShrink: 0, marginLeft: 16,
          }}>
            <span style={{ width: 5, height: 5, borderRadius: "50%", background: "currentColor" }} />
            {health === "loading" ? "Checking…" : health === "ok" ? "All systems healthy" : "API unreachable"}
          </div>
        </div>

        {/* Body */}
        <div style={{ padding: "4px 24px 18px", flex: 1 }}>
          {tab === "pipeline" && <FilterPipelinePanel settings={settings} setSettings={setSettings} />}
          {tab === "apikeys"  && <ApiKeysPanel />}
          {tab === "webhooks" && <WebhooksPanel />}
          {tab === "rules"    && <PlaceholderPanel label="Detection rules" icon={BookOpen} />}
          {tab === "team"     && <PlaceholderPanel label="Team members"    icon={Users} />}
          {tab === "billing"  && <PlaceholderPanel label="Billing & plans" icon={CreditCard} />}
          {tab === "danger"   && <DangerZonePanel onReset={handleReset} />}
        </div>

        {/* Footer */}
        <div style={{
          padding: "14px 24px",
          borderTop: `1px solid ${sw.border}`,
          background: sw.surf2,
          display: "flex", alignItems: "center",
          justifyContent: "space-between",
          fontSize: 12, color: sw.fg4,
        }}>
          <span>
            {lastSaved
              ? <>Last saved <strong style={{ color: sw.fg2, fontFamily: "var(--font-mono, monospace)" }}>{lastSaved}</strong></>
              : "No unsaved changes"}
          </span>
          <div style={{ display: "flex", gap: 8 }}>
            <button
              onClick={handleReset}
              style={{
                padding: "7px 14px", borderRadius: 7,
                border: `1px solid ${sw.border}`,
                background: "transparent", color: sw.fg2,
                fontSize: 12.5, fontWeight: 500, cursor: "pointer", fontFamily: "inherit",
              }}
            >Reset to defaults</button>
            <button
              onClick={handleSave}
              disabled={saving}
              style={{
                padding: "7px 16px", borderRadius: 7, border: "none",
                background: saved ? sw.green : `linear-gradient(135deg, ${sw.indigo}, #8b5cf6)`,
                color: "#fff", fontSize: 12.5, fontWeight: 600,
                cursor: saving ? "wait" : "pointer", fontFamily: "inherit",
                display: "flex", alignItems: "center", gap: 6,
                transition: "background 0.3s",
              }}
            >
              {saved ? <><Check size={13} /> Saved</> : saving ? "Saving…" : "Save changes"}
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}
