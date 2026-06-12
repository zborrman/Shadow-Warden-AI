'use client'
import { useState } from 'react'
import { TopBar } from '@/components/layout/TopBar'
import { Copy, Check, ExternalLink, Terminal, Code2, Zap } from 'lucide-react'

const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? 'https://api.shadow-warden-ai.com'

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button
      onClick={copy}
      className="flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-md transition-colors"
      style={{ background: 'rgba(255,255,255,0.06)', color: copied ? '#30D158' : '#8E8E9E' }}
    >
      {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}

function CodeBlock({ lang, code }: { lang: string; code: string }) {
  const colors: Record<string, string> = { python: '#FFD60A', typescript: '#0A84FF', curl: '#30D158' }
  return (
    <div className="rounded-xl overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.08)' }}>
      <div className="flex items-center justify-between px-4 py-2" style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <span className="text-[11px] font-bold" style={{ color: colors[lang] ?? '#8E8E9E' }}>{lang}</span>
        <CopyButton text={code} />
      </div>
      <pre className="px-4 py-4 text-[12.5px] font-mono leading-relaxed overflow-x-auto text-[#cdd9e5] whitespace-pre">
        {code}
      </pre>
    </div>
  )
}

const EXAMPLES = [
  {
    id: 'python',
    label: 'Python',
    icon: Terminal,
    install: 'pip install shadow-warden',
    code: `from warden_sdk import WardenClient

client = WardenClient(
    api_key="YOUR_API_KEY",
    base_url="${BASE_URL}",
)

# Filter a prompt
result = client.filter("Is this safe?")
print(result.blocked, result.risk_level)

# Chat through the gateway
response = client.chat.completions.create(
    messages=[{"role": "user", "content": "Hello"}],
    model="gpt-4o",
)

# Query SOVA agent
reply = client.agent("What is our threat level?")
print(reply.reply)`,
  },
  {
    id: 'typescript',
    label: 'TypeScript',
    icon: Code2,
    install: 'npm install @shadow-warden/sdk',
    code: `import { WardenClient } from "@shadow-warden/sdk"

const client = new WardenClient({
  apiKey: "YOUR_API_KEY",
  baseUrl: "${BASE_URL}",
})

// Filter a prompt
const result = await client.filter("Is this safe?")
console.log(result.blocked, result.riskLevel)

// Chat through the gateway
const chat = await client.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "Hello" }],
})

// Query SOVA agent
const reply = await client.agent("Threat summary")
console.log(reply.reply)`,
  },
  {
    id: 'curl',
    label: 'cURL',
    icon: Zap,
    install: '# No install needed',
    code: `# Filter endpoint
curl -X POST ${BASE_URL}/filter \\
  -H "X-API-Key: YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"content":"Is this safe?","tenant_id":"default"}'

# OpenAI-compatible chat
curl -X POST ${BASE_URL}/v1/chat/completions \\
  -H "X-API-Key: YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}'

# SOVA agent
curl -X POST ${BASE_URL}/agent/sova \\
  -H "X-API-Key: YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"query":"What is our threat level?"}'`,
  },
]

const endpoints = [
  { method: 'POST', path: '/filter',               desc: '9-layer content filter pipeline',          auth: true  },
  { method: 'POST', path: '/v1/chat/completions',  desc: 'OpenAI-compatible filtered chat proxy',    auth: true  },
  { method: 'POST', path: '/agent/sova',           desc: 'SOVA autonomous agent (Pro+)',             auth: true  },
  { method: 'GET',  path: '/marketplace/listings', desc: 'Browse M2M marketplace listings (Pro+)',   auth: true  },
  { method: 'GET',  path: '/marketplace/stats',    desc: 'Marketplace analytics summary',            auth: true  },
  { method: 'GET',  path: '/health',               desc: 'Gateway health and version info',          auth: false },
  { method: 'GET',  path: '/compliance/posture',   desc: 'Compliance posture across frameworks',     auth: true  },
]

const methodColor: Record<string, string> = {
  GET: '#30D158', POST: '#0A84FF', DELETE: '#FF2D55', PUT: '#FF9F0A',
}

export default function SDKPage() {
  const [tab, setTab] = useState('python')
  const example = EXAMPLES.find(e => e.id === tab)!

  return (
    <div className="flex flex-col min-h-screen">
      <TopBar title="SDK & API Reference" />

      <div className="flex-1 p-6 max-w-4xl mx-auto w-full space-y-8">

        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold mb-1">SDK & API Reference</h1>
          <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
            Integrate Shadow Warden into your stack. Python SDK, TypeScript SDK, and direct REST API.
          </p>
        </div>

        {/* Quick links */}
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          {[
            { label: 'Get your API key', href: '/api-keys/', accent: '#30D158' },
            { label: 'Full SDK docs', href: 'https://shadow-warden-ai.com/sdk', accent: '#BF5AF2', external: true },
            { label: 'API reference', href: 'https://docs.shadow-warden-ai.com', accent: '#0A84FF', external: true },
          ].map(link => (
            <a
              key={link.label}
              href={link.href}
              target={link.external ? '_blank' : undefined}
              rel={link.external ? 'noopener noreferrer' : undefined}
              className="flex items-center justify-between rounded-xl px-4 py-3 text-sm font-semibold transition-all hover:-translate-y-0.5"
              style={{ background: link.accent + '12', border: `1px solid ${link.accent}28`, color: link.accent }}
            >
              {link.label}
              {link.external && <ExternalLink className="w-3.5 h-3.5 opacity-70" />}
            </a>
          ))}
        </div>

        {/* Code examples */}
        <div className="rounded-2xl overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
          {/* Tab bar */}
          <div className="flex" style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid rgba(255,255,255,0.07)' }}>
            {EXAMPLES.map(e => {
              const Icon = e.icon
              const active = tab === e.id
              return (
                <button
                  key={e.id}
                  onClick={() => setTab(e.id)}
                  className="flex items-center gap-1.5 px-4 py-3 text-xs font-semibold transition-colors border-b-2"
                  style={{
                    borderBottomColor: active ? '#30D158' : 'transparent',
                    color: active ? '#30D158' : '#8E8E9E',
                  }}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {e.label}
                </button>
              )
            })}
          </div>

          <div className="p-5 space-y-4">
            {/* Install */}
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>Install</p>
              <div className="flex items-center justify-between rounded-lg px-4 py-2.5" style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)' }}>
                <code className="text-[13px] font-mono text-[#30D158]">{example.install}</code>
                <CopyButton text={example.install} />
              </div>
            </div>

            {/* Code */}
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>Example</p>
              <CodeBlock lang={tab} code={example.code} />
            </div>
          </div>
        </div>

        {/* Endpoint reference */}
        <div>
          <h2 className="text-lg font-bold mb-4">REST Endpoints</h2>
          <div className="rounded-xl overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
            <table className="w-full text-sm">
              <thead>
                <tr style={{ background: 'rgba(255,255,255,0.03)', borderBottom: '1px solid rgba(255,255,255,0.07)' }}>
                  <th className="text-left px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Method</th>
                  <th className="text-left px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Path</th>
                  <th className="text-left px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider hidden md:table-cell" style={{ color: 'var(--text-muted)' }}>Description</th>
                  <th className="text-left px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Auth</th>
                </tr>
              </thead>
              <tbody>
                {endpoints.map((ep, i) => (
                  <tr key={ep.path} style={{ borderBottom: i < endpoints.length - 1 ? '1px solid rgba(255,255,255,0.05)' : undefined }}>
                    <td className="px-4 py-3">
                      <span className="text-[11px] font-bold px-2 py-0.5 rounded" style={{ background: (methodColor[ep.method] ?? '#8E8E9E') + '20', color: methodColor[ep.method] ?? '#8E8E9E' }}>
                        {ep.method}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-[12px]" style={{ color: 'var(--text-primary)' }}>{ep.path}</td>
                    <td className="px-4 py-3 hidden md:table-cell text-xs" style={{ color: 'var(--text-muted)' }}>{ep.desc}</td>
                    <td className="px-4 py-3">
                      {ep.auth
                        ? <span className="text-[10px] font-semibold text-yellow-400">X-API-Key</span>
                        : <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>None</span>
                      }
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Base URL info */}
        <div className="rounded-xl px-5 py-4 flex items-start gap-3" style={{ background: 'rgba(10,132,255,0.08)', border: '1px solid rgba(10,132,255,0.2)' }}>
          <span className="text-lg mt-0.5">ℹ️</span>
          <div className="text-sm" style={{ color: 'var(--text-muted)' }}>
            <span className="font-semibold" style={{ color: 'var(--text-primary)' }}>Base URL: </span>
            <code className="font-mono" style={{ color: '#7dd3fc' }}>{BASE_URL}</code>
            &nbsp;— All requests require an <code className="font-mono">X-API-Key</code> header (except <code className="font-mono">/health</code>).
          </div>
        </div>

      </div>
    </div>
  )
}
