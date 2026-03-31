'use client'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, API_URL } from '@/lib/api'
import { TopBar } from '@/components/layout/TopBar'
import {
  Chrome, Globe, Shield, Download, Copy, Check,
  CheckCircle, Circle, ExternalLink, Puzzle,
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────────
interface ApiKey {
  id: string; label: string; key_prefix: string
  rate_limit: number; active: boolean
}

// ── Copy button ────────────────────────────────────────────────────────────────
function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button onClick={copy} className="btn-secondary px-3 py-1.5 text-xs flex items-center gap-1.5">
      {copied
        ? <><Check className="w-3.5 h-3.5 text-green-400" /> Copied</>
        : <><Copy className="w-3.5 h-3.5" /> {label ?? 'Copy'}</>
      }
    </button>
  )
}

// ── Step indicator ─────────────────────────────────────────────────────────────
function Step({ n, title, done, children }: {
  n: number; title: string; done?: boolean; children: React.ReactNode
}) {
  return (
    <div className="flex gap-4">
      <div className="flex flex-col items-center">
        <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold shrink-0
          ${done ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                 : 'bg-brand-400/10 text-brand-400 border border-brand-400/20'}`}>
          {done ? <Check className="w-4 h-4" /> : n}
        </div>
        <div className="w-px flex-1 bg-white/[0.06] mt-2" />
      </div>
      <div className="pb-8 flex-1">
        <p className="font-semibold text-white mb-3">{title}</p>
        {children}
      </div>
    </div>
  )
}

// ── Browser card ───────────────────────────────────────────────────────────────
function BrowserCard({ icon: Icon, name, badge, href }: {
  icon: React.ElementType; name: string; badge?: string; href: string
}) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="card-glow p-5 flex flex-col items-center gap-3 hover:border-brand-400/30 transition-colors group"
    >
      <Icon className="w-8 h-8 text-slate-300 group-hover:text-white transition-colors" />
      <div className="text-center">
        <p className="text-sm font-semibold text-white">{name}</p>
        {badge && <p className="text-xs text-slate-500 mt-0.5">{badge}</p>}
      </div>
      <div className="flex items-center gap-1 text-xs text-brand-400 font-medium">
        <Download className="w-3.5 h-3.5" /> Install
      </div>
    </a>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function ExtensionPage() {
  const { data: keys = [] } = useQuery<ApiKey[]>({
    queryKey: ['api-keys'],
    queryFn: () => api.get('/api-keys').then(r => r.data),
  })

  const activeKey = keys.find(k => k.active)
  const gatewayUrl = API_URL.replace('/portal', '')

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <TopBar title="Browser Extension" />

      <div className="flex-1 overflow-y-auto p-6 space-y-6">

        {/* Hero */}
        <div className="card-glow p-6 flex items-start gap-5">
          <div className="w-14 h-14 rounded-2xl bg-brand-gradient flex items-center justify-center shrink-0">
            <Puzzle className="w-7 h-7 text-white" />
          </div>
          <div className="flex-1">
            <h2 className="text-xl font-bold text-white">Shadow Warden Browser Extension</h2>
            <p className="text-slate-400 text-sm mt-1 leading-relaxed">
              Real-time AI data protection for ChatGPT, Claude.ai, Gemini, and Copilot.
              Intercepts every prompt before it reaches the cloud, applying your organisation's
              data policy automatically.
            </p>
            <div className="flex flex-wrap gap-2 mt-3">
              {['PII detection', 'Secret redaction', 'Policy enforcement', 'YELLOW-zone redirect to local AI', 'GPO / MDM support'].map(f => (
                <span key={f} className="text-xs bg-white/[0.05] border border-white/[0.08] rounded-full px-2.5 py-1 text-slate-300">
                  {f}
                </span>
              ))}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* Left: setup steps */}
          <div className="lg:col-span-2 space-y-6">

            {/* Install */}
            <div className="card-glow p-6">
              <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-5">
                Install
              </h3>
              <div className="grid grid-cols-3 gap-3">
                <BrowserCard
                  icon={Chrome}
                  name="Chrome"
                  badge="v88+"
                  href="https://chrome.google.com/webstore"
                />
                <BrowserCard
                  icon={Globe}
                  name="Firefox"
                  badge="v109+"
                  href="https://addons.mozilla.org"
                />
                <BrowserCard
                  icon={Globe}
                  name="Edge"
                  badge="Chromium"
                  href="https://microsoftedge.microsoft.com/addons"
                />
              </div>
              <p className="text-xs text-slate-500 mt-3">
                Not yet published to stores?{' '}
                <a
                  href="https://github.com/zborrman/Shadow-Warden-AI/tree/main/browser-extension"
                  target="_blank" rel="noopener noreferrer"
                  className="text-brand-400 hover:underline inline-flex items-center gap-1"
                >
                  Load unpacked from GitHub <ExternalLink className="w-3 h-3" />
                </a>
              </p>
            </div>

            {/* Setup steps */}
            <div className="card-glow p-6">
              <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-5">
                Setup
              </h3>
              <Step n={1} title="Install the extension" done>
                <p className="text-sm text-slate-400">Use the install buttons above or load unpacked from source.</p>
              </Step>

              <Step n={2} title="Click the extension icon → enter your Gateway URL">
                <div className="bg-dark-800 rounded-xl p-3 flex items-center justify-between gap-3">
                  <code className="text-xs text-brand-400 font-mono break-all">{gatewayUrl}</code>
                  <CopyButton text={gatewayUrl} label="Copy URL" />
                </div>
              </Step>

              <Step n={3} title="Paste your API key">
                {activeKey ? (
                  <div className="space-y-2">
                    <div className="bg-dark-800 rounded-xl p-3 flex items-center justify-between gap-3">
                      <div>
                        <p className="text-xs text-slate-400">{activeKey.label}</p>
                        <code className="text-xs text-slate-300 font-mono">{activeKey.key_prefix}••••••••</code>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-slate-500">{activeKey.rate_limit} req/min</span>
                        <a href="/api-keys/" className="btn-secondary px-3 py-1.5 text-xs">
                          Manage keys
                        </a>
                      </div>
                    </div>
                    <p className="text-xs text-slate-500">
                      Don't have a key yet?{' '}
                      <a href="/api-keys/" className="text-brand-400 hover:underline">Create one in API Keys →</a>
                    </p>
                  </div>
                ) : (
                  <div className="bg-amber-500/5 border border-amber-500/20 rounded-xl p-3">
                    <p className="text-xs text-amber-400">
                      No active API key found.{' '}
                      <a href="/api-keys/" className="underline">Create one in API Keys →</a>
                    </p>
                  </div>
                )}
              </Step>

              <Step n={4} title='Click "Save & Connect" then "Test Connection"'>
                <p className="text-sm text-slate-400">
                  The popup will show a green <span className="text-green-400 font-medium">Protected</span> indicator
                  when the extension can reach your gateway.
                </p>
              </Step>

              {/* Last step — no bottom line */}
              <div className="flex gap-4">
                <div className="w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold shrink-0 bg-green-500/20 text-green-400 border border-green-500/30">
                  <Shield className="w-4 h-4" />
                </div>
                <div className="pb-2 flex-1">
                  <p className="font-semibold text-white mb-1">You're protected</p>
                  <p className="text-sm text-slate-400">
                    Every prompt you type on ChatGPT, Claude.ai, Gemini, and Copilot is now
                    screened by Shadow Warden before being sent to the AI.
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Right: quick-ref */}
          <div className="space-y-4">

            {/* Behaviour guide */}
            <div className="card-glow p-5">
              <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">
                How it works
              </h3>
              <div className="space-y-3">
                {[
                  { color: 'bg-green-500', label: 'GREEN', desc: 'Clean prompt — passes through instantly.' },
                  { color: 'bg-amber-400', label: 'YELLOW', desc: 'Internal data detected — offers redirect to your local AI (Ollama / LM Studio).' },
                  { color: 'bg-red-500',   label: 'RED',    desc: 'PII or confidential data — hard block with full-screen overlay.' },
                ].map(({ color, label, desc }) => (
                  <div key={label} className="flex gap-3">
                    <div className={`w-2.5 h-2.5 rounded-full mt-1 shrink-0 ${color}`} />
                    <div>
                      <p className="text-xs font-semibold text-white">{label}</p>
                      <p className="text-xs text-slate-400 leading-relaxed">{desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Protected sites */}
            <div className="card-glow p-5">
              <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">
                Protected sites
              </h3>
              <div className="space-y-2">
                {[
                  { name: 'ChatGPT', host: 'chatgpt.com' },
                  { name: 'Claude.ai', host: 'claude.ai' },
                  { name: 'Gemini', host: 'gemini.google.com' },
                  { name: 'Copilot', host: 'copilot.microsoft.com' },
                ].map(({ name, host }) => (
                  <div key={host} className="flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
                    <div>
                      <p className="text-sm text-white">{name}</p>
                      <p className="text-xs text-slate-500">{host}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Enterprise */}
            <div className="card-glow p-5">
              <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-3">
                Enterprise (GPO / MDM)
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed mb-3">
                Pre-configure Gateway URL and API key via Windows Registry or
                Intune/Jamf. Users cannot change managed settings.
              </p>
              <a
                href="https://github.com/zborrman/Shadow-Warden-AI/blob/main/browser-extension/INSTALL.md"
                target="_blank" rel="noopener noreferrer"
                className="btn-secondary w-full text-xs py-2 flex items-center justify-center gap-1.5"
              >
                <ExternalLink className="w-3.5 h-3.5" /> GPO deployment guide
              </a>
            </div>

          </div>
        </div>
      </div>
    </div>
  )
}
