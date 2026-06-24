'use client'
/**
 * /community-hub/hub/[id] — Unified Community Hub
 * Left sidebar with 6 sections:
 *   Overview · Tunnels & Peering · Marketplace · Compliance · Governance · Settings
 */

import { useState, useEffect } from 'react'
import { useParams } from 'next/navigation'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import Link from 'next/link'
import toast from 'react-hot-toast'
import {
  LayoutDashboard, Network, ShoppingCart, ShieldCheck,
  Vote, Settings2, ArrowLeft, Users,
  Bot, Package, TrendingUp, Lock, Download,
  Plus, X, RefreshCw,
  CheckCircle2, AlertTriangle, XCircle,
  DollarSign, ChevronRight, Tag, Signal, Loader2,
  Copy, BadgeCheck, Zap, Layers,
  Mic, MicOff, PhoneOff,
  Pencil, Trash2, Bell, Check,
} from 'lucide-react'
import clsx from 'clsx'
import {
  getCommunity, patchCommunity, getCompliance, getMyTenantId,
  type HubCommunity, type ComplianceControl, type ComplianceReport,
} from '@/lib/communityHubApi'
import {
  agenticCommerceApi,
  type MktAgent, type MktListing, type MktEscrow,
} from '@/lib/agenticCommerceApi'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer,
} from 'recharts'

// ── Types ──────────────────────────────────────────────────────────────────────

type Section = 'overview' | 'tunnels' | 'marketplace' | 'compliance' | 'governance' | 'settings'
type MktTab  = 'agents' | 'assets' | 'trading' | 'escrow' | 'imported'

interface Tunnel {
  tunnel_id:    string
  label:        string
  jurisdiction: string
  protocol:     string
  status:       string
  latency_ms:   number | null
  endpoint:     string
}

interface Proposal {
  proposal_id:   string
  title:         string
  description:   string
  status:        string
  votes_for:     number
  votes_against: number
  created_at:    string
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const WARDEN = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8001'

async function wFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${WARDEN}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
  })
  if (!res.ok) throw new Error(res.status.toString())
  return res.json() as Promise<T>
}

function shortId(id: string, n = 14) {
  return id.length > n ? `${id.slice(0, n - 4)}…${id.slice(-3)}` : id
}

function fmtUsd(n: number) {
  return `$${n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
}

const REGIONS   = ['EU', 'US', 'UK', 'CA', 'SG', 'AU', 'JP', 'CH']
const PROTOCOLS = ['MASQUE_H3', 'MASQUE_H2', 'CONNECT_TCP']

// ── Small UI atoms ─────────────────────────────────────────────────────────────

function Pill({ children, color = 'slate' }: { children: React.ReactNode; color?: string }) {
  const map: Record<string, string> = {
    slate:  'bg-slate-700/50 text-slate-300 border-slate-600/50',
    green:  'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    amber:  'bg-amber-500/15 text-amber-300 border-amber-500/30',
    red:    'bg-red-500/15 text-red-300 border-red-500/30',
    blue:   'bg-blue-500/15 text-blue-300 border-blue-500/30',
    violet: 'bg-violet-500/15 text-violet-300 border-violet-500/30',
  }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium border ${map[color] ?? map.slate}`}>
      {children}
    </span>
  )
}

function Btn({
  children, onClick, variant = 'primary', disabled, loading, size = 'sm', type = 'button',
}: {
  children: React.ReactNode
  onClick?: () => void
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger'
  disabled?: boolean; loading?: boolean; size?: 'sm' | 'xs'; type?: 'button' | 'submit'
}) {
  const sz = size === 'xs' ? 'px-2.5 py-1 text-xs' : 'px-3 py-1.5 text-sm'
  const v: Record<string, string> = {
    primary:   'bg-blue-600 hover:bg-blue-500 text-white',
    secondary: 'bg-white/8 hover:bg-white/12 text-slate-200 border border-white/12',
    ghost:     'text-slate-300 hover:text-white hover:bg-white/8',
    danger:    'bg-red-500/15 hover:bg-red-500/25 text-red-400 border border-red-500/30',
  }
  return (
    <button
      type={type}
      className={`inline-flex items-center gap-1.5 font-medium rounded-lg transition-all disabled:opacity-50 ${sz} ${v[variant]}`}
      onClick={onClick}
      disabled={disabled || loading}
    >
      {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
      {children}
    </button>
  )
}

function SectionHeader({ title, desc, actions }: {
  title: string; desc?: string; actions?: React.ReactNode
}) {
  return (
    <div className="flex items-start justify-between mb-6">
      <div>
        <h2 className="text-lg font-semibold text-white">{title}</h2>
        {desc && <p className="text-sm text-slate-400 mt-0.5">{desc}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  )
}

function EmptyState({ icon: Icon, label, sub, children }: {
  icon: React.ElementType; label: string; sub?: string; children?: React.ReactNode
}) {
  return (
    <div className="rounded-xl border border-dashed border-white/10 p-8 text-center">
      <Icon className="w-8 h-8 text-slate-600 mx-auto mb-2" />
      <p className="text-sm text-slate-400">{label}</p>
      {sub && <p className="text-xs text-slate-600 mt-1">{sub}</p>}
      {children}
    </div>
  )
}

function Skeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div className="space-y-2">
      {[...Array(rows)].map((_, i) => (
        <div key={i} className="h-14 rounded-xl bg-white/3 border border-white/6 animate-pulse" />
      ))}
    </div>
  )
}

// ── Hub sidebar nav ───────────────────────────────────────────────────────────

const NAV: { id: Section; label: string; icon: React.ElementType; accent: string }[] = [
  { id: 'overview',    label: 'Overview',           icon: LayoutDashboard, accent: '#0A84FF' },
  { id: 'tunnels',     label: 'Tunnels & Peering',  icon: Network,         accent: '#30D158' },
  { id: 'marketplace', label: 'Marketplace',         icon: ShoppingCart,   accent: '#BF5AF2' },
  { id: 'compliance',  label: 'Compliance',          icon: ShieldCheck,    accent: '#FF9F0A' },
  { id: 'governance',  label: 'Governance',          icon: Vote,           accent: '#FF6B35' },
  { id: 'settings',    label: 'Settings',            icon: Settings2,      accent: '#8E8E9E' },
]

function HubSidebar({ section, onChange, community }: {
  section: Section; onChange: (s: Section) => void; community?: HubCommunity
}) {
  return (
    <nav className="w-56 shrink-0 border-r border-white/6 flex flex-col min-h-screen sticky top-0">
      {/* Community identity */}
      <div className="px-4 py-4 border-b border-white/6">
        <div className="flex items-center gap-2.5">
          <div
            className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0 text-sm font-bold"
            style={{ background: 'linear-gradient(135deg,#BF5AF2,#0A84FF)', boxShadow: '0 0 14px rgba(191,90,242,.3)' }}
          >
            {community?.name?.charAt(0)?.toUpperCase() ?? '?'}
          </div>
          <div className="min-w-0">
            <div className="text-[13px] font-semibold text-white truncate">{community?.name ?? '—'}</div>
            <div className="text-[10px] text-slate-500 font-mono truncate">
              {community?.community_id ? shortId(community.community_id, 18) : '—'}
            </div>
          </div>
        </div>
      </div>

      {/* Nav items */}
      <div className="flex-1 px-2 py-3 space-y-0.5">
        {NAV.map(item => {
          const Icon = item.icon
          const active = section === item.id
          return (
            <button
              key={item.id}
              onClick={() => onChange(item.id)}
              className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-[12.5px] font-medium transition-all text-left"
              style={{
                color:      active ? item.accent : '#6B7280',
                background: active ? `color-mix(in srgb,${item.accent} 12%,transparent)` : 'transparent',
              }}
            >
              <Icon className="w-3.5 h-3.5 shrink-0" />
              {item.label}
            </button>
          )
        })}
      </div>

      {/* Back link */}
      <div className="px-2 py-3 border-t border-white/6">
        <Link
          href="/community-hub"
          className="flex items-center gap-2 px-3 py-2 rounded-xl text-[12px] text-slate-500 hover:text-slate-300 transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          All Communities
        </Link>
      </div>
    </nav>
  )
}

// ── Voice Commerce Modal ───────────────────────────────────────────────────────

function VoiceCommerceModal({ communityId, onClose }: {
  communityId: string
  onClose: () => void
}) {
  const [sessionId, setSessionId] = useState<string | null>(null)
  const [recording, setRecording] = useState(false)
  const [transcript, setTranscript] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    wFetch<{ session_id: string }>('/voice/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ community_id: communityId, mode: 'commerce' }),
    })
      .then(d => { setSessionId(d.session_id); setLoading(false) })
      .catch(e => { setError(String(e)); setLoading(false) })
  }, [communityId])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="bg-[#0d1220] rounded-2xl border border-white/10 p-6 w-full max-w-md shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl flex items-center justify-center" style={{ background: 'linear-gradient(135deg,#BF5AF2,#0A84FF)' }}>
              <Mic className="w-4 h-4 text-white" />
            </div>
            <div>
              <div className="text-sm font-semibold text-white">Voice Commerce</div>
              <div className="text-[10px] text-slate-500">WebRTC · Session {sessionId ? sessionId.slice(0, 8) + '…' : '—'}</div>
            </div>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-white/6 transition-colors">
            <X className="w-4 h-4 text-slate-400" />
          </button>
        </div>

        {loading && (
          <div className="flex flex-col items-center py-8 gap-3">
            <Loader2 className="w-6 h-6 text-violet-400 animate-spin" />
            <span className="text-xs text-slate-400">Starting voice session…</span>
          </div>
        )}

        {error && (
          <div className="rounded-xl bg-red-500/10 border border-red-500/20 p-4 text-sm text-red-300">
            {error}
          </div>
        )}

        {!loading && !error && sessionId && (
          <>
            {/* Audio visualizer placeholder */}
            <div
              className="rounded-xl border border-white/8 bg-white/3 p-4 mb-4 flex items-center justify-center gap-1 h-20"
              aria-label="Audio visualizer"
            >
              {Array.from({ length: 16 }).map((_, i) => (
                <div
                  key={i}
                  className="w-1 rounded-full transition-all duration-150"
                  style={{
                    height: recording ? `${8 + Math.sin(i * 0.8) * 12 + Math.random() * 14}px` : '6px',
                    background: recording ? `hsl(${260 + i * 6},80%,65%)` : 'rgba(255,255,255,0.12)',
                  }}
                />
              ))}
            </div>

            {/* Transcript */}
            {transcript && (
              <div className="rounded-xl bg-white/3 border border-white/8 p-3 mb-4 text-xs text-slate-300 leading-relaxed max-h-20 overflow-y-auto">
                {transcript}
              </div>
            )}

            {/* Controls */}
            <div className="flex gap-3">
              <button
                onClick={() => setRecording(r => !r)}
                className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl text-sm font-medium transition-all"
                style={{
                  background: recording ? 'rgba(255,59,48,0.15)' : 'rgba(191,90,242,0.15)',
                  border: recording ? '1px solid rgba(255,59,48,0.3)' : '1px solid rgba(191,90,242,0.3)',
                  color: recording ? '#ff3b30' : '#bf5af2',
                }}
              >
                {recording ? <MicOff className="w-4 h-4" /> : <Mic className="w-4 h-4" />}
                {recording ? 'Stop' : 'Start Recording'}
              </button>
              <button
                onClick={onClose}
                className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium bg-white/4 border border-white/8 text-slate-400 hover:text-white transition-colors"
              >
                <PhoneOff className="w-4 h-4" />
                End
              </button>
            </div>

            <div className="mt-3 text-[10px] text-slate-600 text-center">
              Voice intent → VoiceNLU → Marketplace action · X402 micropayments enabled
            </div>
          </>
        )}
      </div>
    </div>
  )
}

// ── Overview ──────────────────────────────────────────────────────────────────

function OverviewSection({ communityId, onNavigate }: {
  communityId: string; onNavigate: (s: Section) => void
}) {
  const tenantId = getMyTenantId()
  const [voiceOpen, setVoiceOpen] = useState(false)

  const { data: community } = useQuery({
    queryKey: ['hub-comm', communityId],
    queryFn:  () => getCommunity(communityId),
  })

  const { data: agentCount = 0 } = useQuery({
    queryKey: ['hub-agent-count', communityId],
    queryFn:  () => agenticCommerceApi.listAgents({ community_id: communityId })
      .then((d: MktAgent[]) => d.length).catch(() => 0),
  })

  const { data: listingCount = 0 } = useQuery({
    queryKey: ['hub-listing-count', communityId],
    queryFn:  () => agenticCommerceApi.listListings({ community_id: communityId })
      .then((d: MktListing[]) => d.length).catch(() => 0),
  })

  const { data: escrowCount = 0 } = useQuery({
    queryKey: ['hub-escrow-count', communityId],
    queryFn:  () => agenticCommerceApi.listEscrows({ status: 'funded' })
      .then((d: MktEscrow[]) => d.length).catch(() => 0),
  })

  const { data: tunnelCount = 0 } = useQuery({
    queryKey: ['hub-tunnel-count', tenantId],
    queryFn:  () => wFetch<Tunnel[]>(`/sovereign/tunnels?tenant_id=${encodeURIComponent(tenantId)}`)
      .then((d: Tunnel[]) => d.filter(t => t.status === 'ACTIVE').length).catch(() => 0),
  })

  interface Readiness {
    community_exists: boolean; keypair_generated: boolean
    audit_enabled: boolean; agents_registered: boolean
    ready_to_trade: boolean; missing_requirements: string[]
  }
  const { data: readiness } = useQuery({
    queryKey: ['mkt-readiness', communityId],
    queryFn:  () => wFetch<Readiness>(`/marketplace/readiness/${encodeURIComponent(communityId)}`).catch(() => null),
    retry: false,
  })

  type ActivityPoint = { date: string; new_members: number; sep_transactions: number }
  const { data: activityData = [] } = useQuery({
    queryKey: ['community-activity', communityId],
    queryFn: () => wFetch<ActivityPoint[]>(
      `/communities/${encodeURIComponent(communityId)}/analytics?days=30`
    ).catch(() => [] as ActivityPoint[]),
    retry: false,
  })

  const c = community

  const metrics = [
    { label: 'Active Agents',  value: agentCount,  icon: Bot,     accent: '#BF5AF2' },
    { label: 'Open Listings',  value: listingCount, icon: Tag,     accent: '#0A84FF' },
    { label: 'Active Escrows', value: escrowCount,  icon: Lock,    accent: '#FF9F0A' },
    { label: 'Live Tunnels',   value: tunnelCount,  icon: Signal,  accent: '#30D158' },
  ]

  return (
    <div>
      {voiceOpen && (
        <VoiceCommerceModal communityId={communityId} onClose={() => setVoiceOpen(false)} />
      )}

      {/* Community card */}
      <div className="rounded-2xl border border-white/8 bg-white/3 p-5 mb-6">
        <div className="flex items-start gap-4">
          <div
            className="w-12 h-12 rounded-xl flex items-center justify-center text-xl font-bold shrink-0"
            style={{ background: 'linear-gradient(135deg,#BF5AF2,#0A84FF)', boxShadow: '0 0 18px rgba(191,90,242,.3)' }}
          >
            {c?.name?.charAt(0)?.toUpperCase() ?? '?'}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-xl font-bold text-white">{c?.name ?? '—'}</h1>
              <Pill color={c?.status === 'active' ? 'green' : 'slate'}>{c?.status ?? '—'}</Pill>
              <Pill color="slate">{c?.visibility ?? '—'}</Pill>
            </div>
            <p className="text-sm text-slate-400 mt-1 max-w-lg">{c?.description || 'No description'}</p>
          </div>
          {/* Voice Commerce launcher */}
          <button
            onClick={() => setVoiceOpen(true)}
            title="Voice Commerce"
            className="shrink-0 w-9 h-9 rounded-xl flex items-center justify-center transition-all hover:scale-105"
            style={{ background: 'rgba(191,90,242,0.12)', border: '1px solid rgba(191,90,242,0.25)' }}
          >
            <Mic className="w-4 h-4 text-violet-400" />
          </button>
        </div>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
        {metrics.map(m => {
          const Icon = m.icon
          return (
            <div key={m.label} className="rounded-xl border border-white/8 bg-white/3 p-4">
              <div
                className="w-7 h-7 rounded-lg flex items-center justify-center mb-3"
                style={{ background: `${m.accent}18`, border: `1px solid ${m.accent}30` }}
              >
                <Icon className="w-3.5 h-3.5" style={{ color: m.accent }} />
              </div>
              <div className="text-2xl font-bold text-white">{m.value}</div>
              <div className="text-xs text-slate-400 mt-0.5">{m.label}</div>
            </div>
          )
        })}
      </div>

      {/* Marketplace Readiness */}
      {readiness && (
        <div className="rounded-xl border border-white/8 bg-white/3 p-4 mb-6">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-medium text-slate-400">Marketplace Readiness</span>
            {readiness.ready_to_trade
              ? <Pill color="green">Ready to trade</Pill>
              : <Pill color="amber">Incomplete</Pill>
            }
          </div>
          <div className="grid grid-cols-2 gap-2">
            {([
              { key: 'community_exists',  label: 'Community created'  },
              { key: 'keypair_generated', label: 'Keypair generated'  },
              { key: 'audit_enabled',     label: 'STIX audit enabled' },
              { key: 'agents_registered', label: 'Agents registered'  },
            ] as const).map(({ key, label }) => {
              const ok = readiness[key]
              return (
                <div key={key} className="flex items-center gap-2">
                  {ok
                    ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    : <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                  }
                  <span className="text-xs text-slate-400">{label}</span>
                </div>
              )
            })}
          </div>
          {!readiness.ready_to_trade && (
            <button
              disabled
              className="mt-3 w-full py-1.5 rounded-lg text-xs font-medium bg-white/4 text-slate-600 cursor-not-allowed border border-white/6"
            >
              Launch Marketplace — complete requirements above first
            </button>
          )}
        </div>
      )}

      {/* Community Activity chart */}
      {activityData.length > 0 && (
        <div className="rounded-xl border border-white/8 bg-white/3 p-4 mb-6">
          <div className="text-xs font-medium text-slate-400 mb-3">Community Activity (30 days)</div>
          <ResponsiveContainer width="100%" height={80}>
            <AreaChart data={activityData} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
              <defs>
                <linearGradient id="gradMembers" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#BF5AF2" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#BF5AF2" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradSep" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#0A84FF" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#0A84FF" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="date" hide />
              <YAxis hide />
              <Tooltip
                contentStyle={{ background: '#0d1220', border: '1px solid rgba(255,255,255,.1)', borderRadius: 8, fontSize: 11 }}
                labelStyle={{ color: '#94a3b8' }}
                itemStyle={{ color: '#e2e8f0' }}
              />
              <Area type="monotone" dataKey="new_members" stroke="#BF5AF2" strokeWidth={1.5} fill="url(#gradMembers)" name="New Members" dot={false} />
              <Area type="monotone" dataKey="sep_transactions" stroke="#0A84FF" strokeWidth={1.5} fill="url(#gradSep)" name="SEP Transactions" dot={false} />
            </AreaChart>
          </ResponsiveContainer>
          <div className="flex gap-4 mt-2">
            <span className="flex items-center gap-1 text-[10px] text-slate-500">
              <span className="w-2 h-2 rounded-full bg-violet-400 inline-block" /> New Members
            </span>
            <span className="flex items-center gap-1 text-[10px] text-slate-500">
              <span className="w-2 h-2 rounded-full bg-blue-400 inline-block" /> SEP Transactions
            </span>
          </div>
        </div>
      )}

      {/* Quick actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {[
          {
            section: 'marketplace' as Section,
            icon: ShoppingCart, accent: '#BF5AF2',
            title: 'Launch Marketplace',
            sub: 'Agents · Assets · Trading · Escrow',
          },
          {
            section: 'tunnels' as Section,
            icon: Network, accent: '#30D158',
            title: 'Tunnels & Peering',
            sub: `${tunnelCount} active tunnel${tunnelCount !== 1 ? 's' : ''}`,
          },
          {
            section: 'compliance' as Section,
            icon: ShieldCheck, accent: '#FF9F0A',
            title: 'Compliance',
            sub: 'Posture · Gaps · Frameworks',
          },
        ].map(a => {
          const Icon = a.icon
          return (
            <button
              key={a.section}
              onClick={() => onNavigate(a.section)}
              className="flex items-center gap-3 p-4 rounded-xl border text-left group transition-all"
              style={{
                borderColor: `${a.accent}25`,
                background:  `${a.accent}08`,
              }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = `${a.accent}12` }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = `${a.accent}08` }}
            >
              <Icon className="w-5 h-5 shrink-0" style={{ color: a.accent }} />
              <div className="flex-1">
                <div className="text-sm font-semibold text-white">{a.title}</div>
                <div className="text-xs text-slate-400 mt-0.5">{a.sub}</div>
              </div>
              <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-slate-400 transition-colors" />
            </button>
          )
        })}
        <Link
          href={`/community-hub/hub/${communityId}/data`}
          className="flex items-center gap-3 p-4 rounded-xl border text-left group transition-all hover:bg-blue-500/8"
          style={{ borderColor: 'rgba(10,132,255,0.15)', background: 'rgba(10,132,255,0.05)' }}
        >
          <Download className="w-5 h-5 shrink-0 text-blue-400" />
          <div className="flex-1">
            <div className="text-sm font-semibold text-white">Data Upload</div>
            <div className="text-xs text-slate-400 mt-0.5">CSV · JSON · SQLite datasets</div>
          </div>
          <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-slate-400 transition-colors" />
        </Link>
      </div>
    </div>
  )
}

// ── Tunnels ───────────────────────────────────────────────────────────────────

const STATUS_DOT: Record<string, string> = {
  ACTIVE:   'bg-emerald-400',
  PENDING:  'bg-blue-400',
  DEGRADED: 'bg-amber-400',
  OFFLINE:  'bg-slate-600',
}

const PEERING_POLICIES = ['MIRROR_ONLY', 'REWRAP_ALLOWED', 'FULL_SYNC']

function TunnelsSection({ communityId }: { communityId: string }) {
  const tenantId = getMyTenantId()
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [label, setLabel] = useState('')
  const [juris, setJuris] = useState('EU')
  const [proto, setProto] = useState('MASQUE_H3')
  const [creating, setCreating] = useState(false)
  const [peeringOn, setPeeringOn] = useState(true)
  const [policy, setPolicy] = useState('MIRROR_ONLY')

  const { data: tunnels = [], isLoading, refetch } = useQuery({
    queryKey: ['tunnels', tenantId],
    queryFn:  () => wFetch<Tunnel[]>(`/sovereign/tunnels?tenant_id=${encodeURIComponent(tenantId)}`),
    retry: false,
  })

  async function create() {
    setCreating(true)
    try {
      await wFetch('/sovereign/tunnels', {
        method: 'POST',
        body: JSON.stringify({
          tenant_id:    tenantId,
          jurisdiction: juris,
          protocol:     proto,
          label:        label || `${juris} Tunnel`,
          endpoint:     `${juris.toLowerCase()}.masque.shadow-warden-ai.com:443`,
        }),
      })
      toast.success('Tunnel created')
      qc.invalidateQueries({ queryKey: ['tunnels'] })
      qc.invalidateQueries({ queryKey: ['hub-tunnel-count'] })
      setShowCreate(false)
      setLabel('')
    } catch (e: any) {
      toast.error(e?.message ?? 'Failed to create tunnel')
    } finally {
      setCreating(false)
    }
  }

  async function probe(tunnelId: string) {
    try {
      await wFetch(`/sovereign/tunnels/${tunnelId}/probe`, { method: 'POST' })
      toast.success('Probe sent')
      refetch()
    } catch {
      toast.error('Probe failed')
    }
  }

  return (
    <div>
      <SectionHeader
        title="Tunnels & Peering"
        desc="MASQUE sovereign tunnels and inter-community federation"
        actions={<Btn onClick={() => setShowCreate(true)}><Plus className="w-3.5 h-3.5" /> Create Tunnel</Btn>}
      />

      {/* Create modal */}
      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-2xl border border-white/10 bg-[#0d1220] shadow-2xl">
            <div className="flex items-center justify-between border-b border-white/8 px-5 py-4">
              <h3 className="text-sm font-semibold text-white">Create Tunnel</h3>
              <button onClick={() => setShowCreate(false)} className="text-slate-400 hover:text-white"><X className="w-4 h-4" /></button>
            </div>
            <div className="px-5 py-4 space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-400">Label</label>
                <input
                  value={label}
                  onChange={e => setLabel(e.target.value)}
                  placeholder="EU Primary Tunnel"
                  className="w-full bg-slate-800/60 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-400">Jurisdiction</label>
                  <select value={juris} onChange={e => setJuris(e.target.value)}
                    className="w-full bg-slate-800/60 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500">
                    {REGIONS.map(r => <option key={r} value={r}>{r}</option>)}
                  </select>
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-400">Protocol</label>
                  <select value={proto} onChange={e => setProto(e.target.value)}
                    className="w-full bg-slate-800/60 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500">
                    {PROTOCOLS.map(p => <option key={p} value={p}>{p}</option>)}
                  </select>
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-2 px-5 py-3 border-t border-white/6">
              <Btn variant="secondary" onClick={() => setShowCreate(false)}>Cancel</Btn>
              <Btn loading={creating} onClick={create}>Create</Btn>
            </div>
          </div>
        </div>
      )}

      {/* Tunnel list */}
      <div className="space-y-2 mb-6">
        {isLoading ? <Skeleton /> : tunnels.length === 0
          ? <EmptyState icon={Network} label="No tunnels configured" sub="Create a MASQUE tunnel to enable sovereign routing" />
          : tunnels.map(t => (
            <div key={t.tunnel_id} className="flex items-center gap-3 rounded-xl border border-white/8 bg-white/3 px-4 py-3">
              <span className={`w-2 h-2 rounded-full shrink-0 ${STATUS_DOT[t.status] ?? 'bg-slate-600'}`} />
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium text-white">{t.label || `Tunnel ${t.tunnel_id.slice(0, 8)}`}</div>
                <div className="text-xs text-slate-500 font-mono truncate">{t.endpoint || '—'}</div>
              </div>
              <Pill color={t.status === 'ACTIVE' ? 'green' : t.status === 'DEGRADED' ? 'amber' : 'slate'}>
                {t.jurisdiction}
              </Pill>
              <span className="text-xs text-slate-500 hidden md:block">{t.protocol}</span>
              {t.latency_ms !== null && <span className="text-xs text-slate-400">{t.latency_ms}ms</span>}
              <Btn variant="ghost" size="xs" onClick={() => probe(t.tunnel_id)}>
                <RefreshCw className="w-3 h-3" />
              </Btn>
            </div>
          ))
        }
      </div>

      {/* Peering settings */}
      <div className="rounded-xl border border-white/8 bg-white/3 p-5">
        <h3 className="text-sm font-semibold text-white mb-4">Federation Settings</h3>
        <div className="flex items-center justify-between mb-5">
          <div>
            <div className="text-sm text-slate-200">Enable Peering</div>
            <div className="text-xs text-slate-500 mt-0.5">Allow other communities to peer with this one</div>
          </div>
          <button
            onClick={() => setPeeringOn(!peeringOn)}
            className={`relative w-11 h-6 rounded-full transition-colors ${peeringOn ? 'bg-blue-600' : 'bg-slate-700'}`}
          >
            <span className={clsx('absolute top-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform', peeringOn ? 'left-5' : 'left-0.5')} />
          </button>
        </div>
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-slate-400">Peering Policy</label>
          <div className="grid grid-cols-3 gap-2">
            {PEERING_POLICIES.map(p => (
              <button
                key={p}
                onClick={() => setPolicy(p)}
                className={clsx(
                  'px-3 py-2 rounded-lg text-xs font-medium border transition-all',
                  policy === p
                    ? 'border-blue-500/50 bg-blue-500/15 text-blue-300'
                    : 'border-slate-700 bg-slate-800/40 text-slate-400 hover:border-slate-600',
                )}
              >
                {p.replace(/_/g, ' ')}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Marketplace ───────────────────────────────────────────────────────────────

const MKT_TABS: { id: MktTab; label: string; icon: React.ElementType }[] = [
  { id: 'agents',   label: 'Agents',        icon: Bot        },
  { id: 'assets',   label: 'Assets',        icon: Package    },
  { id: 'trading',  label: 'Trading Floor', icon: TrendingUp },
  { id: 'escrow',   label: 'Escrow',        icon: Lock       },
  { id: 'imported', label: 'Imported',      icon: Download   },
]

const ASSET_COL: Record<string, string> = {
  rule:    'bg-violet-500/20 text-violet-300 border-violet-500/30',
  model:   'bg-blue-500/20 text-blue-300 border-blue-500/30',
  signals: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
}

const ESCROW_COL: Record<string, string> = {
  pending_deposit: 'text-slate-400',
  funded:          'text-blue-400',
  delivered:       'text-amber-400',
  confirmed:       'text-emerald-400',
  disputed:        'text-red-400',
  resolved_buyer:  'text-emerald-300',
  cancelled:       'text-slate-500',
}

function TradeVolumeChart({ communityId }: { communityId: string }) {
  type VolumePoint = { date: string; volume_usd: number; trades: number }
  const { data: volumeData = [] } = useQuery({
    queryKey: ['trade-volume', communityId],
    queryFn: () => wFetch<VolumePoint[]>(
      `/marketplace/analytics/volume?community_id=${encodeURIComponent(communityId)}&period_days=7`
    ).catch(() => [] as VolumePoint[]),
    retry: false,
  })
  if (volumeData.length === 0) return null
  return (
    <div className="rounded-xl border border-white/8 bg-white/3 p-4 mb-5">
      <div className="text-xs font-medium text-slate-400 mb-3">Trade Volume (7 days)</div>
      <ResponsiveContainer width="100%" height={72}>
        <BarChart data={volumeData} margin={{ top: 2, right: 0, bottom: 0, left: 0 }} barSize={10}>
          <XAxis dataKey="date" hide />
          <YAxis hide />
          <Tooltip
            contentStyle={{ background: '#0d1220', border: '1px solid rgba(255,255,255,.1)', borderRadius: 8, fontSize: 11 }}
            labelStyle={{ color: '#94a3b8' }}
            itemStyle={{ color: '#e2e8f0' }}
            formatter={(v: number) => [`$${v.toFixed(2)}`, 'Volume']}
          />
          <Bar dataKey="volume_usd" fill="#BF5AF2" radius={[2, 2, 0, 0]} name="Volume (USD)" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

function MarketplaceSection({ communityId }: { communityId: string }) {
  const tenantId = getMyTenantId()
  const qc = useQueryClient()
  const [tab, setTab] = useState<MktTab>('agents')

  // Agent reg form
  const [showRegAgent, setShowRegAgent] = useState(false)
  const [agentKey, setAgentKey]         = useState('')
  const [agentName, setAgentName]       = useState('')
  const [agentBudget, setAgentBudget]   = useState(1000)
  const [agentCaps, setAgentCaps]       = useState<string[]>(['marketplace_sell', 'marketplace_buy'])
  const [registering, setRegistering]   = useState(false)

  // Agent table inline state
  const [editNameId, setEditNameId]   = useState<string | null>(null)
  const [editNameVal, setEditNameVal] = useState('')
  const [revokeId, setRevokeId]       = useState<string | null>(null)
  const [budgetEdits, setBudgetEdits] = useState<Record<string, number>>({})
  const [savingBudget, setSavingBudget] = useState<string | null>(null)

  // Listing form
  const [showListing, setShowListing]   = useState(false)
  const [assetId, setAssetId]           = useState('')
  const [assetType, setAssetType]       = useState<'rule' | 'model' | 'signals'>('rule')
  const [price, setPrice]               = useState('')
  const [listingBusy, setListingBusy]   = useState(false)

  // Asset tokenization form
  const [tokenType, setTokenType]       = useState<'rule' | 'model' | 'signals'>('rule')
  const [rulePattern, setRulePattern]   = useState('')
  const [ruleName, setRuleName]         = useState('')
  const [ruleValid, setRuleValid]       = useState<boolean | null>(null)
  const [ruleError, setRuleError]       = useState('')
  const [tokenizing, setTokenizing]     = useState(false)
  const [tokenized, setTokenized]       = useState<{asset_id: string; ipfs_hash: string} | null>(null)

  const { data: agents = [], isLoading: loadA, refetch: refetchA } = useQuery({
    queryKey: ['mkt-agents', communityId],
    queryFn:  () => agenticCommerceApi.listAgents({ community_id: communityId }),
    retry: false,
  })

  // Batch-fetch trust scores for all agents in this community
  const { data: trustMap = {} } = useQuery({
    queryKey: ['mkt-trust-batch', communityId],
    queryFn: async () => {
      const map: Record<string, number> = {}
      await Promise.allSettled(
        (agents as MktAgent[]).map(async a => {
          try {
            const t = await agenticCommerceApi.getAgentTrust(a.agent_id)
            map[a.agent_id] = t.trust_score
          } catch { map[a.agent_id] = 0 }
        })
      )
      return map
    },
    enabled: (agents as MktAgent[]).length > 0,
    staleTime: 60_000,
    retry: false,
  })

  // Agent activity chart data (trades grouped by seller)
  const { data: tradeChartData = [] } = useQuery({
    queryKey: ['mkt-agent-chart', communityId],
    queryFn: async () => {
      try {
        const r = await fetch(`${WARDEN}/marketplace/analytics/agents?period_days=30`)
        if (!r.ok) return []
        const d = await r.json()
        return (d.top_sellers ?? []).slice(0, 8).map((s: { agent_id: string; trades: number; volume_usd: number }) => ({
          name:   s.agent_id.slice(0, 10) + '…',
          trades: s.trades,
          volume: Math.round(s.volume_usd),
        }))
      } catch { return [] }
    },
    staleTime: 120_000,
    retry: false,
  })

  const { data: listings = [], isLoading: loadL } = useQuery({
    queryKey: ['mkt-listings', communityId],
    queryFn:  () => agenticCommerceApi.listListings({ community_id: communityId }),
    retry: false,
  })

  const { data: escrows = [], isLoading: loadE } = useQuery({
    queryKey: ['mkt-escrows'],
    queryFn:  () => agenticCommerceApi.listEscrows(),
    retry: false,
  })

  const { data: purchases = [], isLoading: loadP } = useQuery({
    queryKey: ['mkt-purchases'],
    queryFn:  () => agenticCommerceApi.listPurchases(),
    retry: false,
  })

  async function registerAgent() {
    if (!agentKey.trim()) { toast.error('Public key required'); return }
    setRegistering(true)
    try {
      const agent = await agenticCommerceApi.registerAgent({
        tenant_id:    tenantId,
        community_id: communityId,
        public_key:   agentKey.trim(),
        capabilities: agentCaps.length > 0 ? agentCaps : ['marketplace_sell', 'marketplace_buy'],
      })
      if (agentName.trim() || agentBudget !== 1000) {
        await agenticCommerceApi.patchAgent(agent.agent_id, {
          name: agentName.trim() || undefined,
          budget_limit: agentBudget !== 1000 ? agentBudget : undefined,
        })
      }
      toast.success('Agent registered')
      qc.invalidateQueries({ queryKey: ['mkt-agents'] })
      qc.invalidateQueries({ queryKey: ['hub-agent-count'] })
      setShowRegAgent(false)
      setAgentKey(''); setAgentName(''); setAgentBudget(1000)
      setAgentCaps(['marketplace_sell', 'marketplace_buy'])
    } catch (e: any) {
      toast.error(e?.message ?? 'Registration failed')
    } finally {
      setRegistering(false)
    }
  }

  async function saveAgentName(agentId: string) {
    try {
      await agenticCommerceApi.patchAgent(agentId, { name: editNameVal })
      toast.success('Name saved')
      qc.invalidateQueries({ queryKey: ['mkt-agents', communityId] })
      setEditNameId(null)
    } catch (e: any) { toast.error(e?.message ?? 'Save failed') }
  }

  async function saveAgentBudget(agentId: string) {
    const limit = budgetEdits[agentId]
    if (limit === undefined) return
    setSavingBudget(agentId)
    try {
      await agenticCommerceApi.patchAgent(agentId, { budget_limit: limit })
      toast.success('Budget updated')
      qc.invalidateQueries({ queryKey: ['mkt-agents', communityId] })
    } catch (e: any) { toast.error(e?.message ?? 'Failed') }
    finally { setSavingBudget(null) }
  }

  async function revokeAgent(agentId: string) {
    try {
      await agenticCommerceApi.deactivateAgent(agentId)
      toast.success('Agent revoked')
      qc.invalidateQueries({ queryKey: ['mkt-agents', communityId] })
      qc.invalidateQueries({ queryKey: ['hub-agent-count'] })
      setRevokeId(null)
    } catch (e: any) { toast.error(e?.message ?? 'Failed') }
  }

  async function createListing() {
    if (!assetId.trim()) { toast.error('Asset ID required'); return }
    const p = parseFloat(price)
    if (isNaN(p) || p <= 0) { toast.error('Invalid price'); return }
    const seller = (agents as MktAgent[])[0]
    if (!seller) { toast.error('Register an agent first'); return }
    setListingBusy(true)
    try {
      await agenticCommerceApi.createListing({
        asset_id:        assetId.trim(),
        seller_agent_id: seller.agent_id,
        community_id:    communityId,
        tenant_id:       tenantId,
        asset_type:      assetType,
        price_usd:       p,
      })
      toast.success('Listing created')
      qc.invalidateQueries({ queryKey: ['mkt-listings'] })
      qc.invalidateQueries({ queryKey: ['hub-listing-count'] })
      setShowListing(false)
      setAssetId(''); setPrice('')
    } catch (e: any) {
      toast.error(e?.message ?? 'Failed to create listing')
    } finally {
      setListingBusy(false)
    }
  }

  async function buy(listingId: string) {
    const buyer = (agents as MktAgent[])[0]
    if (!buyer) { toast.error('Register an agent first'); return }
    try {
      await agenticCommerceApi.buyListing(listingId, buyer.agent_id)
      toast.success('Purchase initiated — escrow created')
      qc.invalidateQueries({ queryKey: ['mkt-listings'] })
      qc.invalidateQueries({ queryKey: ['mkt-escrows'] })
      setTab('escrow')
    } catch (e: any) {
      toast.error(e?.message ?? 'Purchase failed')
    }
  }

  async function fund(escrowId: string) {
    try {
      await agenticCommerceApi.fundEscrow(escrowId)
      toast.success('Escrow funded')
      qc.invalidateQueries({ queryKey: ['mkt-escrows'] })
    } catch (e: any) { toast.error(e?.message ?? 'Failed') }
  }

  async function confirm(escrowId: string) {
    try {
      await agenticCommerceApi.confirmReceipt(escrowId)
      toast.success('Receipt confirmed — funds released')
      qc.invalidateQueries({ queryKey: ['mkt-escrows'] })
    } catch (e: any) { toast.error(e?.message ?? 'Failed') }
  }

  // Real-time regex syntax validation (client-side)
  useEffect(() => {
    if (tokenType !== 'rule' || !rulePattern) { setRuleValid(null); setRuleError(''); return }
    try { new RegExp(rulePattern); setRuleValid(true); setRuleError('') }
    catch (e: any) { setRuleValid(false); setRuleError(e.message) }
  }, [rulePattern, tokenType])

  async function tokenizeAsset() {
    const seller = (agents as MktAgent[])[0]
    if (!seller) { toast.error('Register an agent first'); return }
    if (tokenType === 'rule' && ruleValid === false) { toast.error('Fix regex first'); return }
    setTokenizing(true)
    setTokenized(null)
    try {
      const raw = tokenType === 'rule'
        ? { name: ruleName || 'custom_rule', regex_pattern: rulePattern }
        : tokenType === 'model'
        ? { osi_version: '1.0', id: `model-${Date.now()}`, metrics: {}, dimensions: [] }
        : { signals: [{ type: 'pattern', value: rulePattern || 'signal' }] }
      const res = await fetch(`${WARDEN}/marketplace/assets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenant_id: tenantId, seller_agent_id: seller.agent_id, asset_type: tokenType, raw_data: raw }),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        const detail = err.detail
        if (detail?.error === 'rule_validation_failed') {
          setRuleValid(false)
          setRuleError(detail.details?.[0] ?? 'ReDoS unsafe pattern')
          toast.error('Rule failed ReDoS screening')
        } else {
          toast.error(JSON.stringify(detail) ?? 'Tokenization failed')
        }
        return
      }
      const data = await res.json()
      setTokenized({ asset_id: data.asset_id, ipfs_hash: data.ipfs_hash ?? '' })
      toast.success(`Asset tokenized: ${data.asset_id.slice(0, 16)}…`)
      qc.invalidateQueries({ queryKey: ['mkt-agents'] })
    } catch (e: any) {
      toast.error(e?.message ?? 'Tokenization failed')
    } finally {
      setTokenizing(false)
    }
  }

  return (
    <div>
      <SectionHeader
        title="Agentic Marketplace"
        desc={`Community: ${shortId(communityId, 20)}`}
        actions={
          <Link href="/community-hub/agentic-commerce">
            <Btn variant="secondary" size="xs">Full View</Btn>
          </Link>
        }
      />

      {/* Sub-tab bar */}
      <div className="flex gap-1 mb-6 p-1 bg-white/4 rounded-xl border border-white/6 w-fit flex-wrap">
        {MKT_TABS.map(t => {
          const Icon = t.icon
          const active = tab === t.id
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={clsx(
                'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all',
                active ? 'bg-white/10 text-white shadow' : 'text-slate-400 hover:text-slate-200',
              )}
            >
              <Icon className="w-3.5 h-3.5" /> {t.label}
            </button>
          )
        })}
      </div>

      {/* ── Agents ── */}
      {tab === 'agents' && (
        <div className="space-y-5">
          {/* Activity charts row */}
          {tradeChartData.length > 0 && (
            <div className="grid grid-cols-2 gap-4">
              <div className="rounded-xl border border-white/8 bg-white/3 p-4">
                <div className="text-xs font-medium text-slate-400 mb-3">Trades by Agent (30d)</div>
                <BarChart width={280} height={100} data={tradeChartData} margin={{ top: 0, right: 0, bottom: 0, left: -20 }} barSize={12}>
                  <XAxis dataKey="name" tick={{ fontSize: 9, fill: '#64748b' }} />
                  <YAxis tick={{ fontSize: 9, fill: '#64748b' }} />
                  <Bar dataKey="trades" fill="#BF5AF2" radius={[3, 3, 0, 0]} />
                </BarChart>
              </div>
              <div className="rounded-xl border border-white/8 bg-white/3 p-4">
                <div className="text-xs font-medium text-slate-400 mb-3">Volume ($) by Agent (30d)</div>
                <BarChart width={280} height={100} data={tradeChartData} margin={{ top: 0, right: 0, bottom: 0, left: -20 }} barSize={12}>
                  <XAxis dataKey="name" tick={{ fontSize: 9, fill: '#64748b' }} />
                  <YAxis tick={{ fontSize: 9, fill: '#64748b' }} />
                  <Bar dataKey="volume" fill="#30D158" radius={[3, 3, 0, 0]} />
                </BarChart>
              </div>
            </div>
          )}

          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400">{(agents as MktAgent[]).filter(a => a.status === 'active').length} active agents</span>
            <Btn size="xs" onClick={() => setShowRegAgent(true)}><Plus className="w-3 h-3" /> Register Agent</Btn>
          </div>

          {/* DS-01 Agent Table */}
          {loadA ? <Skeleton /> : (agents as MktAgent[]).length === 0
            ? <EmptyState icon={Bot} label="No agents registered" sub="Agents are identified by DID derived from Ed25519 pubkey" />
            : (
              <div className="rounded-xl border border-white/8 overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-white/6 bg-white/2">
                      {['DID', 'Name', 'Status', 'TrustRank', 'Capabilities', 'Budget', 'Actions'].map(h => (
                        <th key={h} className="text-left px-3 py-2.5 text-[11px] font-semibold text-slate-500 uppercase tracking-wide whitespace-nowrap">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/4">
                    {(agents as MktAgent[]).map(a => {
                      const trust = (trustMap as Record<string, number>)[a.agent_id] ?? 0
                      const budgetLimit = (a as any).budget_limit ?? 1000
                      const budgetUsed = 0 // placeholder — real value from Semantic Layer
                      const pct = Math.min((budgetUsed / budgetLimit) * 100, 100)
                      const overBudget = pct >= 100
                      const nearBudget = pct >= 80 && !overBudget
                      const pendingBudget = budgetEdits[a.agent_id] ?? budgetLimit
                      return (
                        <tr
                          key={a.agent_id}
                          className={`hover:bg-white/2 transition-colors ${overBudget ? 'bg-red-500/5' : nearBudget ? 'bg-amber-500/5' : ''}`}
                        >
                          {/* DID */}
                          <td className="px-3 py-2.5">
                            <button
                              onClick={() => { navigator.clipboard.writeText(a.agent_id); toast.success('DID copied') }}
                              className="flex items-center gap-1 group"
                              title={a.agent_id}
                            >
                              <span className="font-mono text-[11px] text-slate-400">{a.agent_id.slice(0, 18)}…</span>
                              <Copy className="w-3 h-3 text-slate-600 group-hover:text-slate-400 shrink-0" />
                            </button>
                          </td>
                          {/* Name inline edit */}
                          <td className="px-3 py-2.5 min-w-[110px]">
                            {editNameId === a.agent_id ? (
                              <div className="flex items-center gap-1">
                                <input
                                  autoFocus
                                  value={editNameVal}
                                  onChange={e => setEditNameVal(e.target.value)}
                                  onKeyDown={e => { if (e.key === 'Enter') saveAgentName(a.agent_id); if (e.key === 'Escape') setEditNameId(null) }}
                                  className="w-24 bg-slate-800 border border-slate-600 rounded px-2 py-0.5 text-xs text-white focus:outline-none focus:border-violet-500"
                                />
                                <button onClick={() => saveAgentName(a.agent_id)} className="text-violet-400 hover:text-violet-300"><Check className="w-3 h-3" /></button>
                                <button onClick={() => setEditNameId(null)} className="text-slate-500 hover:text-slate-300"><X className="w-3 h-3" /></button>
                              </div>
                            ) : (
                              <button
                                onClick={() => { setEditNameId(a.agent_id); setEditNameVal((a as any).name || '') }}
                                className="flex items-center gap-1 group text-xs text-slate-300 hover:text-white"
                              >
                                <span>{(a as any).name || <span className="italic text-slate-600">unnamed</span>}</span>
                                <Pencil className="w-2.5 h-2.5 text-slate-600 group-hover:text-slate-400 shrink-0" />
                              </button>
                            )}
                          </td>
                          {/* Status */}
                          <td className="px-3 py-2.5">
                            <Pill color={a.status === 'active' ? 'green' : a.status === 'suspended' ? 'red' : 'slate'}>
                              {a.status}
                            </Pill>
                          </td>
                          {/* TrustRank */}
                          <td className="px-3 py-2.5">
                            <div className="flex items-center gap-2 min-w-[90px]">
                              <div className="flex-1 h-1.5 rounded-full bg-white/8">
                                <div
                                  className="h-full rounded-full"
                                  style={{
                                    width: `${(trust * 100).toFixed(0)}%`,
                                    background: trust >= 0.7 ? '#30D158' : trust >= 0.4 ? '#FF9F0A' : '#FF453A',
                                  }}
                                />
                              </div>
                              <span className="text-[11px] text-slate-400 w-8 text-right">{(trust * 100).toFixed(0)}%</span>
                            </div>
                          </td>
                          {/* Capabilities */}
                          <td className="px-3 py-2.5">
                            <div className="flex flex-wrap gap-1">
                              {a.capabilities.map(c => (
                                <span key={c} className="text-[10px] px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-400 border border-violet-500/20">
                                  {c.replace('marketplace_', '')}
                                </span>
                              ))}
                            </div>
                          </td>
                          {/* Budget slider */}
                          <td className="px-3 py-2.5 min-w-[160px]">
                            <div className="space-y-1.5">
                              <div className="flex items-center gap-2">
                                <input
                                  type="range" min={100} max={10000} step={100}
                                  value={pendingBudget}
                                  onChange={e => setBudgetEdits(prev => ({ ...prev, [a.agent_id]: Number(e.target.value) }))}
                                  className="w-20 accent-violet-500"
                                />
                                <span className="text-[11px] text-slate-300 w-12">${pendingBudget}</span>
                                {pendingBudget !== budgetLimit && (
                                  <button
                                    onClick={() => saveAgentBudget(a.agent_id)}
                                    disabled={savingBudget === a.agent_id}
                                    className="text-[10px] px-1.5 py-0.5 rounded bg-violet-500/20 text-violet-400 hover:bg-violet-500/30 disabled:opacity-50"
                                  >
                                    {savingBudget === a.agent_id ? '…' : 'Save'}
                                  </button>
                                )}
                              </div>
                              <div className="flex items-center gap-1.5">
                                <div className="flex-1 h-1 rounded-full bg-white/8">
                                  <div
                                    className="h-full rounded-full transition-all"
                                    style={{
                                      width: `${pct}%`,
                                      background: overBudget ? '#FF453A' : nearBudget ? '#FF9F0A' : '#30D158',
                                    }}
                                  />
                                </div>
                                {(nearBudget || overBudget) && (
                                  <Bell className={`w-2.5 h-2.5 ${overBudget ? 'text-red-400' : 'text-amber-400'}`} />
                                )}
                              </div>
                            </div>
                          </td>
                          {/* Actions */}
                          <td className="px-3 py-2.5">
                            {revokeId === a.agent_id ? (
                              <div className="flex items-center gap-1">
                                <span className="text-[10px] text-red-400">Revoke?</span>
                                <button onClick={() => revokeAgent(a.agent_id)} className="text-[10px] px-1.5 py-0.5 rounded bg-red-600/20 text-red-400 hover:bg-red-600/30">Yes</button>
                                <button onClick={() => setRevokeId(null)} className="text-[10px] px-1.5 py-0.5 rounded bg-white/5 text-slate-400 hover:bg-white/10">No</button>
                              </div>
                            ) : (
                              <button
                                onClick={() => setRevokeId(a.agent_id)}
                                className="flex items-center gap-1 text-[10px] px-2 py-1 rounded bg-red-600/10 text-red-400 border border-red-500/20 hover:bg-red-600/20 transition"
                              >
                                <Trash2 className="w-2.5 h-2.5" /> Revoke
                              </button>
                            )}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )
          }

          {/* Register Agent Modal — enhanced */}
          {showRegAgent && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
              <div className="w-full max-w-lg rounded-2xl border border-white/10 bg-[#0d1220] shadow-2xl">
                <div className="flex items-center justify-between border-b border-white/8 px-5 py-4">
                  <h3 className="text-sm font-semibold text-white">Register Agent</h3>
                  <button onClick={() => setShowRegAgent(false)} className="text-slate-400 hover:text-white"><X className="w-4 h-4" /></button>
                </div>
                <div className="px-5 py-4 space-y-4">
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-slate-400">Agent Name (optional)</label>
                    <input
                      value={agentName}
                      onChange={e => setAgentName(e.target.value)}
                      placeholder="e.g. Sales Bot Alpha"
                      className="w-full bg-slate-800/60 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-violet-500"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-slate-400">Ed25519 Public Key (base64)</label>
                    <textarea
                      value={agentKey}
                      onChange={e => setAgentKey(e.target.value)}
                      placeholder="MCowBQYDK2VwAyEA..."
                      rows={3}
                      className="w-full bg-slate-800/60 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white font-mono placeholder-slate-600 focus:outline-none focus:border-violet-500 resize-none"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-slate-400">Capabilities</label>
                    <div className="flex flex-wrap gap-2">
                      {['marketplace_buy', 'marketplace_sell', 'marketplace_negotiate', 'voice_commerce'].map(cap => (
                        <button
                          key={cap}
                          onClick={() => setAgentCaps(prev => prev.includes(cap) ? prev.filter(c => c !== cap) : [...prev, cap])}
                          className={`text-xs px-2.5 py-1 rounded-lg border transition ${agentCaps.includes(cap) ? 'bg-violet-500/20 text-violet-300 border-violet-500/40' : 'bg-white/4 text-slate-400 border-white/10 hover:border-white/20'}`}
                        >
                          {cap.replace('marketplace_', '').replace('_', ' ')}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-slate-400">Monthly Budget: <span className="text-white">${agentBudget}</span></label>
                    <input
                      type="range" min={100} max={10000} step={100}
                      value={agentBudget}
                      onChange={e => setAgentBudget(Number(e.target.value))}
                      className="w-full accent-violet-500"
                    />
                    <div className="flex justify-between text-[10px] text-slate-600">
                      <span>$100</span><span>$10,000</span>
                    </div>
                  </div>
                  <p className="text-xs text-slate-500">
                    DID (<code className="text-slate-400">did:shadow:…</code>) is derived automatically from SHA-256 of your public key.
                  </p>
                </div>
                <div className="flex justify-end gap-2 px-5 py-3 border-t border-white/6">
                  <Btn variant="secondary" onClick={() => setShowRegAgent(false)}>Cancel</Btn>
                  <Btn loading={registering} onClick={registerAgent}>Register</Btn>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Assets ── */}
      {tab === 'assets' && (
        <div className="space-y-4">
          {/* Type selector */}
          <div className="flex gap-2">
            {(['rule', 'model', 'signals'] as const).map(t => (
              <button
                key={t}
                onClick={() => { setTokenType(t); setTokenized(null); setRuleValid(null); setRuleError('') }}
                className={clsx(
                  'px-3 py-1.5 rounded-lg text-xs font-medium border transition-all',
                  tokenType === t
                    ? 'bg-violet-500/20 text-violet-300 border-violet-500/40'
                    : 'bg-white/3 text-slate-500 border-white/8 hover:text-slate-300',
                )}
              >
                {t}
              </button>
            ))}
          </div>

          {/* Rule tokenization */}
          {tokenType === 'rule' && (
            <div className="space-y-3 rounded-xl border border-white/8 bg-white/3 p-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-400">Rule name</label>
                <input
                  value={ruleName} onChange={e => setRuleName(e.target.value)}
                  placeholder="no_jailbreak_act"
                  className="w-full bg-slate-800/60 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-medium text-slate-400">Regex pattern</label>
                  {ruleValid === true && <span className="text-[10px] text-emerald-400 flex items-center gap-1"><CheckCircle2 className="w-3 h-3" /> Valid</span>}
                  {ruleValid === false && <span className="text-[10px] text-red-400 flex items-center gap-1"><XCircle className="w-3 h-3" /> Invalid</span>}
                </div>
                <input
                  value={rulePattern} onChange={e => setRulePattern(e.target.value)}
                  placeholder="(ignore|disregard)\s+all"
                  className={clsx(
                    'w-full bg-slate-800/60 border rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none font-mono',
                    ruleValid === false ? 'border-red-500/60 focus:border-red-500' : 'border-slate-700 focus:border-blue-500',
                  )}
                />
                {ruleError && <p className="text-[11px] text-red-400">{ruleError}</p>}
                <p className="text-[10px] text-slate-600">
                  ReDoS screening runs on submit. Patterns with catastrophic backtracking are rejected with HTTP 422.
                </p>
              </div>
            </div>
          )}

          {/* Model / Signals — simplified form */}
          {tokenType !== 'rule' && (
            <div className="rounded-xl border border-white/8 bg-white/3 p-4">
              <p className="text-xs text-slate-400">
                {tokenType === 'model'
                  ? 'A minimal OSI 1.0 model container will be generated. Add fields via the full Agentic Commerce view.'
                  : 'A signal bundle will be wrapped as a UECIID asset ready for listing.'}
              </p>
            </div>
          )}

          <button
            onClick={tokenizeAsset}
            disabled={tokenizing || (tokenType === 'rule' && ruleValid === false) || (agents as MktAgent[]).length === 0}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium text-white bg-violet-600 hover:bg-violet-500 disabled:opacity-40 disabled:cursor-not-allowed transition"
          >
            {tokenizing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Package className="w-3.5 h-3.5" />}
            {tokenizing ? 'Tokenizing…' : 'Tokenize Asset'}
          </button>

          {(agents as MktAgent[]).length === 0 && (
            <p className="text-xs text-amber-400 flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> Register an agent first (Agents tab)</p>
          )}

          {/* Tokenized result */}
          {tokenized && (
            <div className="rounded-xl border border-emerald-500/25 bg-emerald-500/5 p-4 space-y-2">
              <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold">
                <BadgeCheck className="w-4 h-4" /> Asset tokenized
              </div>
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-slate-500 w-16 shrink-0">UECIID</span>
                  <span className="text-xs font-mono text-white">{tokenized.asset_id}</span>
                  <button onClick={() => navigator.clipboard.writeText(tokenized.asset_id).then(() => toast.success('Copied'))}
                    className="text-slate-500 hover:text-white transition"><Copy className="w-3 h-3" /></button>
                </div>
                {tokenized.ipfs_hash && (
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-slate-500 w-16 shrink-0">IPFS</span>
                    <span className="text-xs font-mono text-slate-300">
                      {tokenized.ipfs_hash.slice(0, 10)}…{tokenized.ipfs_hash.slice(-6)}
                    </span>
                    <button onClick={() => navigator.clipboard.writeText(tokenized.ipfs_hash).then(() => toast.success('Copied'))}
                      className="text-slate-500 hover:text-white transition"><Copy className="w-3 h-3" /></button>
                    <span className="text-[10px] text-emerald-400 flex items-center gap-0.5"><BadgeCheck className="w-3 h-3" /> Verified on IPFS</span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Trading ── */}
      {tab === 'trading' && (
        <div>
          <TradeVolumeChart communityId={communityId} />
          <div className="flex justify-end mb-4">
            <Btn onClick={() => setShowListing(true)}><Plus className="w-3.5 h-3.5" /> Create Listing</Btn>
          </div>
          {loadL ? <Skeleton /> : (listings as MktListing[]).length === 0
            ? <EmptyState icon={TrendingUp} label="No active listings" />
            : <div className="space-y-2">
              {(listings as MktListing[]).map(l => (
                <div key={l.listing_id} className="flex items-center gap-3 rounded-xl border border-white/8 bg-white/3 px-4 py-3">
                  <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium border ${ASSET_COL[l.asset_type] ?? 'bg-slate-700/50 text-slate-400 border-slate-600/50'}`}>
                    {l.asset_type}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-mono text-slate-300 truncate">{shortId(l.asset_id, 22)}</div>
                    <div className="text-xs text-slate-500">by {shortId(l.seller_agent, 18)}</div>
                  </div>
                  <span className="text-sm font-bold text-white">{fmtUsd(l.price_usd)}</span>
                  <Pill color={l.status === 'active' ? 'green' : 'slate'}>{l.status}</Pill>
                  {l.status === 'active' && (
                    <Btn size="xs" onClick={() => buy(l.listing_id)}>Buy</Btn>
                  )}
                </div>
              ))}
            </div>
          }

          {showListing && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
              <div className="w-full max-w-md rounded-2xl border border-white/10 bg-[#0d1220] shadow-2xl">
                <div className="flex items-center justify-between border-b border-white/8 px-5 py-4">
                  <h3 className="text-sm font-semibold text-white">Create Listing</h3>
                  <button onClick={() => setShowListing(false)} className="text-slate-400 hover:text-white"><X className="w-4 h-4" /></button>
                </div>
                <div className="px-5 py-4 space-y-4">
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-slate-400">Asset ID (UECIID)</label>
                    <input value={assetId} onChange={e => setAssetId(e.target.value)} placeholder="SEP-A3f9kP2mN8q"
                      className="w-full bg-slate-800/60 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white font-mono placeholder-slate-600 focus:outline-none focus:border-blue-500" />
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-slate-400">Asset Type</label>
                      <select value={assetType} onChange={e => setAssetType(e.target.value as any)}
                        className="w-full bg-slate-800/60 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500">
                        <option value="rule">Rule</option>
                        <option value="model">Model</option>
                        <option value="signals">Signals</option>
                      </select>
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-slate-400">Price (USD)</label>
                      <input type="number" value={price} onChange={e => setPrice(e.target.value)} placeholder="4.99" min="0.01" step="0.01"
                        className="w-full bg-slate-800/60 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500" />
                    </div>
                  </div>
                </div>
                <div className="flex justify-end gap-2 px-5 py-3 border-t border-white/6">
                  <Btn variant="secondary" onClick={() => setShowListing(false)}>Cancel</Btn>
                  <Btn loading={listingBusy} onClick={createListing}>Create</Btn>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Escrow ── */}
      {tab === 'escrow' && (
        <div>
          {loadE ? <Skeleton /> : (escrows as MktEscrow[]).length === 0
            ? <EmptyState icon={Lock} label="No escrow transactions" sub="Buy a listing to start an escrow" />
            : <div className="space-y-2">
              {(escrows as MktEscrow[]).map(e => (
                <div key={e.escrow_id} className="rounded-xl border border-white/8 bg-white/3 px-4 py-3">
                  <div className="flex items-center gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`text-xs font-semibold uppercase ${ESCROW_COL[e.status] ?? 'text-slate-400'}`}>
                          {e.status.replace(/_/g, ' ')}
                        </span>
                        <span className="text-xs text-slate-600 font-mono">{shortId(e.escrow_id)}</span>
                      </div>
                      <div className="text-xs text-slate-500 mt-0.5 truncate">
                        Buyer: {shortId(e.buyer_agent, 16)} · Seller: {shortId(e.seller_agent, 16)}
                      </div>
                    </div>
                    <span className="text-sm font-bold text-white shrink-0">{fmtUsd(e.amount_usd)}</span>
                    <div className="flex gap-1.5 shrink-0">
                      {e.status === 'pending_deposit' && (
                        <Btn size="xs" onClick={() => fund(e.escrow_id)}>
                          <DollarSign className="w-3 h-3" /> Fund
                        </Btn>
                      )}
                      {e.status === 'delivered' && (
                        <Btn size="xs" onClick={() => confirm(e.escrow_id)}>
                          <CheckCircle2 className="w-3 h-3" /> Confirm
                        </Btn>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          }
        </div>
      )}

      {/* ── Imported ── */}
      {tab === 'imported' && (
        <div>
          {loadP ? <Skeleton /> : (purchases as any[]).filter((p: any) => p.status === 'completed').length === 0
            ? <EmptyState icon={Download} label="No imported assets" sub="Confirmed escrow assets appear here" />
            : <div className="space-y-2">
              {(purchases as any[]).filter((p: any) => p.status === 'completed').map((p: any) => (
                <div key={p.purchase_id} className="rounded-xl border border-white/8 bg-white/3 px-4 py-3 space-y-1.5">
                  <div className="flex items-center gap-3">
                    <Download className="w-4 h-4 text-emerald-400 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-mono text-white truncate">{shortId(p.asset_id, 22)}</div>
                      <div className="text-xs text-slate-500">{fmtUsd(p.price_paid)} · {p.completed_at?.slice(0, 10) ?? '—'}</div>
                    </div>
                    <Pill color="green">imported</Pill>
                  </div>
                  {/* Hot-reload status badges */}
                  <div className="flex gap-2 flex-wrap pl-7">
                    {p.asset_type === 'rule' || !p.asset_type ? (
                      <span className="inline-flex items-center gap-1 text-[10px] text-emerald-400">
                        <Zap className="w-3 h-3" /> Hot-loaded into Evolution Engine
                      </span>
                    ) : null}
                    {p.asset_type === 'model' && (
                      <span className="inline-flex items-center gap-1 text-[10px] text-blue-400">
                        <Layers className="w-3 h-3" /> Registered in Semantic Layer
                      </span>
                    )}
                    {p.ipfs_hash && (
                      <span className="inline-flex items-center gap-1 text-[10px] text-slate-400">
                        IPFS: {String(p.ipfs_hash).slice(0, 8)}…{String(p.ipfs_hash).slice(-4)}
                        <button onClick={() => navigator.clipboard.writeText(p.ipfs_hash).then(() => toast.success('Copied'))}
                          className="hover:text-white transition ml-0.5"><Copy className="w-2.5 h-2.5" /></button>
                        <BadgeCheck className="w-3 h-3 text-emerald-400" />
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          }
        </div>
      )}
    </div>
  )
}

// ── Compliance ────────────────────────────────────────────────────────────────

function ComplianceSection({ communityId }: { communityId: string }) {
  const { data: report, isLoading } = useQuery({
    queryKey: ['hub-compliance', communityId],
    queryFn:  () => getCompliance(communityId),
    retry: false,
  })

  if (isLoading) return (
    <div><SectionHeader title="Compliance" /><Skeleton rows={5} /></div>
  )

  if (!report) return (
    <div>
      <SectionHeader title="Compliance" />
      <EmptyState icon={ShieldCheck} label="No compliance data available">
        <div className="mt-3">
          <Link href="/compliance" className="text-xs text-blue-400 hover:text-blue-300 inline-flex items-center gap-1">
            Open Compliance Dashboard <ChevronRight className="w-3 h-3" />
          </Link>
        </div>
      </EmptyState>
    </div>
  )

  const controls = report.controls ?? []
  const pass  = controls.filter(c => c.status === 'PASS').length
  const score = controls.length > 0 ? Math.round((pass / controls.length) * 100) : 0
  const grade = score >= 80 ? 'A' : score >= 70 ? 'B' : score >= 60 ? 'C' : 'D'
  const scoreColor = score >= 80 ? '#30D158' : score >= 60 ? '#FF9F0A' : '#FF3B30'
  const circ = 2 * Math.PI * 34

  return (
    <div>
      <SectionHeader
        title="Compliance"
        desc={`${pass} / ${controls.length} controls passing`}
        actions={
          <Link href="/compliance"><Btn variant="secondary">Full Dashboard</Btn></Link>
        }
      />

      {/* Score ring */}
      <div className="flex items-center gap-6 rounded-xl border border-white/8 bg-white/3 p-5 mb-6">
        <div className="relative w-20 h-20 shrink-0">
          <svg className="w-20 h-20 -rotate-90" viewBox="0 0 80 80">
            <circle cx="40" cy="40" r="34" fill="none" stroke="rgba(255,255,255,.06)" strokeWidth="8" />
            <circle cx="40" cy="40" r="34" fill="none" stroke={scoreColor} strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={circ.toString()}
              strokeDashoffset={(circ * (1 - score / 100)).toString()} />
          </svg>
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-xl font-bold text-white">{score}</span>
          </div>
        </div>
        <div>
          <div className="text-3xl font-bold text-white">{grade}</div>
          <div className="text-sm text-slate-400 mt-0.5">Overall posture</div>
          <div className="text-xs text-slate-500 mt-1">
            {controls.filter(c => c.status === 'FAIL').length} gaps to address
          </div>
        </div>
      </div>

      {/* Controls list */}
      <div className="space-y-2">
        {controls.map((c: ComplianceControl) => (
          <div key={c.control} className="flex items-center gap-3 rounded-xl border border-white/6 bg-white/2 px-4 py-3">
            {c.status === 'PASS'
              ? <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              : c.status === 'FAIL'
              ? <XCircle className="w-4 h-4 text-red-400 shrink-0" />
              : <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />}
            <div className="flex-1 min-w-0">
              <div className="text-sm text-slate-200">{c.control}</div>
              {c.detail && <div className="text-xs text-slate-500 truncate">{c.detail}</div>}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Governance ────────────────────────────────────────────────────────────────

function GovernanceSection({ communityId }: { communityId: string }) {
  const tenantId = getMyTenantId()
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [title, setTitle]           = useState('')
  const [desc, setDesc]             = useState('')
  const [creating, setCreating]     = useState(false)

  const { data: proposals = [], isLoading, refetch } = useQuery({
    queryKey: ['hub-proposals', communityId],
    queryFn:  () => wFetch<Proposal[]>(
      `/marketplace/proposals?community_id=${encodeURIComponent(communityId)}&tenant_id=${encodeURIComponent(tenantId)}`
    ),
    retry: false,
  })

  async function create() {
    if (!title.trim()) { toast.error('Title required'); return }
    setCreating(true)
    try {
      await wFetch('/marketplace/proposals', {
        method: 'POST',
        body: JSON.stringify({ community_id: communityId, tenant_id: tenantId, title: title.trim(), description: desc.trim() }),
      })
      toast.success('Proposal created')
      refetch()
      setShowCreate(false)
      setTitle(''); setDesc('')
    } catch (e: any) {
      toast.error(e?.message ?? 'Failed')
    } finally {
      setCreating(false)
    }
  }

  async function vote(proposalId: string, v: 'for' | 'against') {
    try {
      await wFetch(`/marketplace/proposals/${proposalId}/vote`, {
        method: 'POST', body: JSON.stringify({ tenant_id: tenantId, vote: v }),
      })
      toast.success(`Voted ${v}`)
      refetch()
    } catch (e: any) { toast.error(e?.message ?? 'Vote failed') }
  }

  return (
    <div>
      <SectionHeader
        title="DAO Governance"
        desc="Propose and vote on community marketplace rules"
        actions={<Btn onClick={() => setShowCreate(true)}><Plus className="w-3.5 h-3.5" /> New Proposal</Btn>}
      />

      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-2xl border border-white/10 bg-[#0d1220] shadow-2xl">
            <div className="flex items-center justify-between border-b border-white/8 px-5 py-4">
              <h3 className="text-sm font-semibold text-white">New Proposal</h3>
              <button onClick={() => setShowCreate(false)} className="text-slate-400 hover:text-white"><X className="w-4 h-4" /></button>
            </div>
            <div className="px-5 py-4 space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-400">Title</label>
                <input value={title} onChange={e => setTitle(e.target.value)} placeholder="Reduce listing fee to 0.5%"
                  className="w-full bg-slate-800/60 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500" />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-400">Description</label>
                <textarea value={desc} onChange={e => setDesc(e.target.value)} placeholder="Context for the proposal..." rows={3}
                  className="w-full bg-slate-800/60 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500 resize-none" />
              </div>
            </div>
            <div className="flex justify-end gap-2 px-5 py-3 border-t border-white/6">
              <Btn variant="secondary" onClick={() => setShowCreate(false)}>Cancel</Btn>
              <Btn loading={creating} onClick={create}>Submit</Btn>
            </div>
          </div>
        </div>
      )}

      {isLoading ? <Skeleton rows={2} /> : (proposals as Proposal[]).length === 0
        ? <EmptyState icon={Vote} label="No proposals yet" sub="Create the first governance proposal for this community" />
        : <div className="space-y-3">
          {(proposals as Proposal[]).map(p => {
            const total  = p.votes_for + p.votes_against
            const forPct = total > 0 ? Math.round((p.votes_for / total) * 100) : 50
            return (
              <div key={p.proposal_id} className="rounded-xl border border-white/8 bg-white/3 p-4">
                <div className="flex items-start justify-between mb-3 gap-3">
                  <div className="min-w-0">
                    <div className="text-sm font-semibold text-white">{p.title}</div>
                    {p.description && <div className="text-xs text-slate-400 mt-0.5">{p.description}</div>}
                  </div>
                  <Pill color={p.status === 'active' ? 'blue' : p.status === 'passed' ? 'green' : 'red'}>
                    {p.status}
                  </Pill>
                </div>
                <div className="flex items-center gap-3 flex-wrap">
                  {(p.votes_for + p.votes_against) > 0 && (
                    <PieChart width={36} height={36}>
                      <Pie
                        data={[
                          { name: 'For',     value: p.votes_for },
                          { name: 'Against', value: p.votes_against },
                        ]}
                        cx={16} cy={16} innerRadius={9} outerRadius={16}
                        paddingAngle={2} dataKey="value" strokeWidth={0}
                      >
                        <Cell fill="#34d399" />
                        <Cell fill="#f87171" />
                      </Pie>
                      <Tooltip
                        contentStyle={{ background: '#0d1220', border: '1px solid rgba(255,255,255,.1)', borderRadius: 6, fontSize: 10, padding: '4px 8px' }}
                        itemStyle={{ color: '#e2e8f0' }}
                      />
                    </PieChart>
                  )}
                  <div className="flex-1 bg-slate-800 rounded-full h-1.5 min-w-[80px]">
                    <div className="h-full bg-emerald-500 rounded-full transition-all" style={{ width: `${forPct}%` }} />
                  </div>
                  <span className="text-xs text-slate-400 shrink-0">{p.votes_for} for · {p.votes_against} against</span>
                  {p.status === 'active' && (
                    <div className="flex gap-1.5 shrink-0">
                      <Btn size="xs" onClick={() => vote(p.proposal_id, 'for')}>For</Btn>
                      <Btn variant="danger" size="xs" onClick={() => vote(p.proposal_id, 'against')}>Against</Btn>
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      }
    </div>
  )
}

// ── Settings ──────────────────────────────────────────────────────────────────

function SettingsSection({ communityId }: { communityId: string }) {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [desc, setDesc] = useState('')
  const [saving, setSaving] = useState(false)

  const { data: community } = useQuery({
    queryKey: ['hub-comm', communityId],
    queryFn:  () => getCommunity(communityId),
  })

  useEffect(() => {
    if (community) {
      setName(community.name)
      setDesc(community.description)
    }
  }, [community])

  async function save() {
    setSaving(true)
    try {
      await patchCommunity(communityId, { name, description: desc })
      toast.success('Settings saved')
      qc.invalidateQueries({ queryKey: ['hub-comm', communityId] })
    } catch (e: any) {
      toast.error(e?.message ?? 'Failed to save')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div>
      <SectionHeader title="Community Settings" />
      <div className="max-w-lg space-y-5">
        <div className="space-y-1.5">
          <label className="text-sm font-medium text-slate-300">Community Name</label>
          <input
            value={name}
            onChange={e => setName(e.target.value)}
            className="w-full bg-slate-800/60 border border-slate-700 rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition"
          />
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium text-slate-300">Description</label>
          <textarea
            value={desc}
            onChange={e => setDesc(e.target.value)}
            rows={4}
            className="w-full bg-slate-800/60 border border-slate-700 rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition resize-none"
          />
        </div>
        <div className="flex items-center gap-3 pt-2 border-t border-white/6">
          <Btn loading={saving} onClick={save}>Save Changes</Btn>
          <Link href={`/community-hub/create?edit=true&id=${communityId}`}>
            <Btn variant="secondary">Full Wizard</Btn>
          </Link>
          <Link href={`/community-hub/${communityId}`}>
            <Btn variant="ghost">Classic View</Btn>
          </Link>
        </div>
      </div>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function CommunityHubPage() {
  const params      = useParams()
  const communityId = Array.isArray(params.id) ? params.id[0] : (params.id ?? '')
  const [section, setSection] = useState<Section>('overview')

  const { data: community } = useQuery({
    queryKey: ['hub-comm', communityId],
    queryFn:  () => getCommunity(communityId),
    enabled:  !!communityId,
  })

  return (
    <div className="flex min-h-screen bg-[#09090f]">
      <HubSidebar section={section} onChange={setSection} community={community} />

      <main className="flex-1 min-w-0 overflow-y-auto">
        <div className="max-w-4xl mx-auto px-6 py-8">
          {section === 'overview'    && <OverviewSection    communityId={communityId} onNavigate={setSection} />}
          {section === 'tunnels'     && <TunnelsSection     communityId={communityId} />}
          {section === 'marketplace' && <MarketplaceSection communityId={communityId} />}
          {section === 'compliance'  && <ComplianceSection  communityId={communityId} />}
          {section === 'governance'  && <GovernanceSection  communityId={communityId} />}
          {section === 'settings'    && <SettingsSection    communityId={communityId} />}
        </div>
      </main>
    </div>
  )
}
