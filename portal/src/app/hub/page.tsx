'use client'
/**
 * Warden Hub — Federated Syndicate Control Center
 *
 * Layout
 * ──────
 *   TopBar
 *   ┌─────────────────────────────┬──────────────────┐
 *   │  Network Map (SVG)          │  Quick Actions   │
 *   ├─────────────────────────────│  Bandwidth Quota │
 *   │  Tunnel List                │  Members / WIDs  │
 *   └─────────────────────────────┴──────────────────┘
 */

import { useState, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Shield, ShieldOff, Link2, Link2Off, Users, Plus,
  Copy, RefreshCw, AlertTriangle, CheckCircle2,
  Zap, Globe, Clock, Download, ChevronRight,
} from 'lucide-react'
import clsx from 'clsx'
import { TopBar } from '@/components/layout/TopBar'
import {
  getTunnels, revokeTunnel, generateUserInvite, generatePlatformManifest,
  getInvites, timeUntil, fmtBytes,
  type Tunnel, type Invite, type HandshakeManifest,
} from '@/lib/hubApi'

// ── Helpers ───────────────────────────────────────────────────────────────────

function statusColor(s: Tunnel['status']) {
  return {
    ACTIVE:  'text-green-400',
    PENDING: 'text-amber-400',
    EXPIRED: 'text-slate-500',
    REVOKED: 'text-red-400',
  }[s] ?? 'text-slate-400'
}

function statusDot(s: Tunnel['status']) {
  return {
    ACTIVE:  'bg-green-400 shadow-[0_0_6px_#4ade80]',
    PENDING: 'bg-amber-400',
    EXPIRED: 'bg-slate-600',
    REVOKED: 'bg-red-500',
  }[s] ?? 'bg-slate-600'
}

function ttlPct(expires_at: string | null): number {
  if (!expires_at) return 100
  const end = new Date(expires_at).getTime()
  const now = Date.now()
  if (now >= end) return 0
  // Assume max 8760h (1 year) as denominator for display
  return Math.min(100, Math.round(((end - now) / (8760 * 3_600_000)) * 100))
}

// ── Network Map ───────────────────────────────────────────────────────────────

function NetworkMap({ tunnels, onRevoke }: {
  tunnels: Tunnel[]
  onRevoke: (id: string) => void
}) {
  const [hovered, setHovered] = useState<string | null>(null)
  const active = tunnels.filter(t => t.status === 'ACTIVE')
  const total  = Math.max(active.length, 1)
  const cx = 200, cy = 200, r = 130

  return (
    <div className="card-glow p-5">
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-semibold text-white flex items-center gap-2">
          <Globe className="w-4 h-4 text-brand-400" />
          Network Map
        </h2>
        <span className="badge badge-active">{active.length} active tunnel{active.length !== 1 ? 's' : ''}</span>
      </div>

      <div className="flex justify-center">
        <svg width="400" height="400" viewBox="0 0 400 400" className="select-none">
          <defs>
            {/* Animated gradient for active lines */}
            <linearGradient id="line-grad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%"   stopColor="#818cf8" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.3" />
            </linearGradient>
            {/* Glow filter */}
            <filter id="glow">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
            {/* Pulse animation keyframes via CSS */}
            <style>{`
              @keyframes dash { to { stroke-dashoffset: -24; } }
              @keyframes pulse-node { 0%,100%{ opacity:.4; r:18; } 50%{ opacity:.15; r:22; } }
              .anim-dash { animation: dash 1.2s linear infinite; }
              .anim-pulse { animation: pulse-node 2s ease-in-out infinite; }
            `}</style>
          </defs>

          {/* Background grid */}
          <circle cx={cx} cy={cy} r={r + 30} fill="none" stroke="white" strokeOpacity="0.03" strokeWidth="1" strokeDasharray="4 8" />
          <circle cx={cx} cy={cy} r={r - 30} fill="none" stroke="white" strokeOpacity="0.02" strokeWidth="1" strokeDasharray="4 8" />

          {/* Tunnel lines */}
          {active.map((t, i) => {
            const angle = (2 * Math.PI * i) / total - Math.PI / 2
            const px    = cx + r * Math.cos(angle)
            const py    = cy + r * Math.sin(angle)
            const isHov = hovered === t.tunnel_id
            return (
              <g key={t.tunnel_id}>
                {/* Glowing base line */}
                <line x1={cx} y1={cy} x2={px} y2={py}
                  stroke="#818cf8" strokeOpacity={isHov ? 0.5 : 0.2} strokeWidth={isHov ? 2 : 1}
                />
                {/* Animated dashes */}
                <line x1={cx} y1={cy} x2={px} y2={py}
                  stroke="url(#line-grad)" strokeOpacity="0.8" strokeWidth="2"
                  strokeDasharray="6 18" className="anim-dash"
                />
              </g>
            )
          })}

          {/* Peer nodes */}
          {active.map((t, i) => {
            const angle = (2 * Math.PI * i) / total - Math.PI / 2
            const px    = cx + r * Math.cos(angle)
            const py    = cy + r * Math.sin(angle)
            const isHov = hovered === t.tunnel_id
            const label = (t.responder_sid ?? t.initiator_sid).slice(0, 12)
            return (
              <g key={t.tunnel_id}
                className="cursor-pointer"
                onMouseEnter={() => setHovered(t.tunnel_id)}
                onMouseLeave={() => setHovered(null)}
              >
                {/* Pulse ring */}
                <circle cx={px} cy={py} r={18} fill="#4ade80" fillOpacity="0.08" className="anim-pulse" />
                {/* Node */}
                <circle cx={px} cy={py} r={12}
                  fill={isHov ? '#1e293b' : '#0f172a'}
                  stroke={isHov ? '#4ade80' : '#334155'}
                  strokeWidth={isHov ? 2 : 1}
                  filter={isHov ? 'url(#glow)' : undefined}
                />
                <text x={px} y={py + 1} textAnchor="middle" dominantBaseline="middle"
                  fontSize="7" fill={isHov ? '#4ade80' : '#94a3b8'} fontFamily="monospace">
                  {label}
                </text>
                {/* Safety number tooltip */}
                {isHov && t.safety_number && (
                  <g>
                    <rect x={px - 38} y={py + 16} width={76} height={22} rx={4}
                      fill="#1e293b" stroke="#334155" strokeWidth="1" />
                    <text x={px} y={py + 27} textAnchor="middle" fontSize="8"
                      fill="#94a3b8" fontFamily="monospace">
                      🔑 {t.safety_number}
                    </text>
                  </g>
                )}
              </g>
            )
          })}

          {/* Centre node — this gateway */}
          <circle cx={cx} cy={cy} r={28} fill="#0f172a" stroke="#818cf8" strokeWidth="2" filter="url(#glow)" />
          <circle cx={cx} cy={cy} r={36} fill="none" stroke="#818cf8" strokeOpacity="0.15" strokeWidth="1" strokeDasharray="4 4" />
          <Shield x={cx - 10} y={cy - 10} width={20} height={20} stroke="#818cf8" fill="none" strokeWidth="1.5" />
          <text x={cx} y={cy + 20} textAnchor="middle" fontSize="8" fill="#94a3b8" fontFamily="monospace">
            THIS GATEWAY
          </text>

          {/* Empty state */}
          {active.length === 0 && (
            <text x={cx} y={cy + 55} textAnchor="middle" fontSize="11" fill="#475569">
              No active tunnels
            </text>
          )}
        </svg>
      </div>

      {/* Hover detail */}
      {hovered && (() => {
        const t = active.find(x => x.tunnel_id === hovered)
        if (!t) return null
        return (
          <div className="mt-2 p-3 bg-dark-700 rounded-xl border border-white/[0.06] text-xs text-slate-300 flex items-center justify-between">
            <div>
              <span className="text-slate-500">Tunnel </span>
              <span className="font-mono">{t.tunnel_id.slice(0, 18)}…</span>
              <span className="ml-3 text-slate-500">expires in </span>
              <span className="text-amber-400">{timeUntil(t.expires_at)}</span>
            </div>
            <button
              onClick={() => onRevoke(t.tunnel_id)}
              className="flex items-center gap-1 px-2 py-1 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 transition-colors"
            >
              <ShieldOff className="w-3 h-3" /> Revoke
            </button>
          </div>
        )
      })()}
    </div>
  )
}

// ── Tunnel Row ────────────────────────────────────────────────────────────────

function TunnelRow({ t, onRevoke }: { t: Tunnel; onRevoke: () => void }) {
  const [expanded, setExpanded] = useState(false)
  const pct = ttlPct(t.expires_at)

  return (
    <div className="border-b border-white/[0.04] last:border-0">
      <div
        className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-white/[0.02] transition-colors"
        onClick={() => setExpanded(e => !e)}
      >
        {/* Status dot */}
        <div className={clsx('w-2 h-2 rounded-full shrink-0', statusDot(t.status))} />

        {/* Peer SID */}
        <div className="flex-1 min-w-0">
          <p className="text-sm font-mono text-slate-200 truncate">
            {t.responder_sid ?? t.initiator_sid}
          </p>
          <p className="text-xs text-slate-500 mt-0.5">
            {t.status} · expires in <span className="text-slate-400">{timeUntil(t.expires_at)}</span>
          </p>
        </div>

        {/* TTL bar */}
        <div className="w-16 hidden sm:block">
          <div className="h-1 bg-dark-600 rounded-full overflow-hidden">
            <div
              className={clsx('h-full rounded-full transition-all', pct > 40 ? 'bg-green-500' : pct > 15 ? 'bg-amber-500' : 'bg-red-500')}
              style={{ width: `${pct}%` }}
            />
          </div>
        </div>

        <ChevronRight className={clsx('w-4 h-4 text-slate-600 transition-transform shrink-0', expanded && 'rotate-90')} />
      </div>

      {expanded && (
        <div className="px-4 pb-4 space-y-3">
          {/* Safety number */}
          {t.safety_number && (
            <div className="flex items-center gap-2 p-2.5 bg-dark-700 rounded-xl text-xs">
              <CheckCircle2 className="w-3.5 h-3.5 text-green-400 shrink-0" />
              <span className="text-slate-400">Safety Number: </span>
              <code className="font-mono text-green-400">{t.safety_number}</code>
              <button
                onClick={() => navigator.clipboard.writeText(t.safety_number!)}
                className="ml-auto text-slate-500 hover:text-slate-300"
              ><Copy className="w-3 h-3" /></button>
            </div>
          )}

          {/* Tunnel ID */}
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <span>ID:</span>
            <code className="font-mono text-slate-400">{t.tunnel_id}</code>
            <button
              onClick={() => navigator.clipboard.writeText(t.tunnel_id)}
              className="text-slate-600 hover:text-slate-400"
            ><Copy className="w-3 h-3" /></button>
          </div>

          {/* Actions */}
          {t.status === 'ACTIVE' && (
            <button
              onClick={onRevoke}
              className="btn-danger w-full flex items-center justify-center gap-2 text-xs"
            >
              <ShieldOff className="w-3.5 h-3.5" />
              Kill-Switch — Revoke Tunnel Immediately
            </button>
          )}
        </div>
      )}
    </div>
  )
}

// ── Quick Actions panel ───────────────────────────────────────────────────────

function QuickActions({
  onGenerateUserInvite,
  onGeneratePlatformManifest,
  loading,
}: {
  onGenerateUserInvite: () => void
  onGeneratePlatformManifest: () => void
  loading: boolean
}) {
  return (
    <div className="card-glow p-5 space-y-3">
      <h2 className="font-semibold text-white flex items-center gap-2 mb-1">
        <Zap className="w-4 h-4 text-brand-400" />
        Quick Actions
      </h2>

      <button
        onClick={onGenerateUserInvite}
        disabled={loading}
        className="btn w-full flex items-center gap-2 text-sm"
      >
        <Users className="w-4 h-4" />
        Invite Individual User
      </button>

      <button
        onClick={onGeneratePlatformManifest}
        disabled={loading}
        className="btn-secondary w-full flex items-center gap-2 text-sm"
      >
        <Link2 className="w-4 h-4" />
        Connect Platform (Manifest)
      </button>
    </div>
  )
}

// ── Manifest modal ────────────────────────────────────────────────────────────

function ManifestModal({ manifest, onClose }: { manifest: HandshakeManifest; onClose: () => void }) {
  const json = JSON.stringify(manifest, null, 2)
  const [copied, setCopied] = useState(false)

  function copy() {
    navigator.clipboard.writeText(json)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  function download() {
    const blob = new Blob([json], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = Object.assign(document.createElement('a'), { href: url, download: `warden-manifest-${manifest.invite_code.slice(0, 8)}.json` })
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-dark-800 border border-white/[0.08] rounded-2xl w-full max-w-lg">
        <div className="p-5 border-b border-white/[0.06] flex items-center justify-between">
          <h3 className="font-semibold text-white flex items-center gap-2">
            <Globe className="w-4 h-4 text-brand-400" />
            Warden Platform Manifest
          </h3>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300 text-lg leading-none">✕</button>
        </div>

        <div className="p-5 space-y-4">
          <div className="flex items-start gap-2 p-3 bg-amber-500/10 border border-amber-500/20 rounded-xl text-xs text-amber-300">
            <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
            Send this manifest to Platform B&apos;s admin via a secure channel.
            Expires in {manifest.ttl_hours}h. One-time use.
          </div>

          <pre className="text-xs font-mono text-slate-300 bg-dark-900 p-4 rounded-xl overflow-auto max-h-64 border border-white/[0.04]">
            {json}
          </pre>

          <div className="grid grid-cols-2 gap-2">
            <button onClick={copy} className="btn-secondary flex items-center justify-center gap-2 text-sm">
              {copied ? <CheckCircle2 className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
              {copied ? 'Copied!' : 'Copy JSON'}
            </button>
            <button onClick={download} className="btn flex items-center justify-center gap-2 text-sm">
              <Download className="w-4 h-4" />
              Download
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Magic Link modal ───────────────────────────────────────────────────────────

function MagicLinkModal({ link, onClose }: { link: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  function copy() { navigator.clipboard.writeText(link); setCopied(true); setTimeout(() => setCopied(false), 2000) }
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-dark-800 border border-white/[0.08] rounded-2xl w-full max-w-md">
        <div className="p-5 border-b border-white/[0.06] flex items-center justify-between">
          <h3 className="font-semibold text-white flex items-center gap-2">
            <Users className="w-4 h-4 text-brand-400" />
            User Invite Link
          </h3>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300 text-lg leading-none">✕</button>
        </div>
        <div className="p-5 space-y-4">
          <div className="flex items-start gap-2 p-3 bg-blue-500/10 border border-blue-500/20 rounded-xl text-xs text-blue-300">
            <CheckCircle2 className="w-3.5 h-3.5 mt-0.5 shrink-0" />
            Send this link to the user. It expires in 24 hours and can only be used once.
          </div>
          <div className="p-3 bg-dark-900 rounded-xl border border-white/[0.04] text-xs font-mono text-slate-300 break-all">
            {link}
          </div>
          <button onClick={copy} className="btn w-full flex items-center justify-center gap-2 text-sm">
            {copied ? <CheckCircle2 className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            {copied ? 'Copied!' : 'Copy Link'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Invite History ────────────────────────────────────────────────────────────

function InviteHistory({ invites }: { invites: Invite[] }) {
  if (!invites.length) return (
    <div className="text-center text-slate-600 text-sm py-4">No invites yet</div>
  )
  return (
    <div className="space-y-1.5">
      {invites.slice(0, 8).map(inv => (
        <div key={inv.invite_code} className="flex items-center gap-2 text-xs">
          <div className={clsx('w-1.5 h-1.5 rounded-full shrink-0', inv.is_used ? 'bg-slate-600' : 'bg-green-400')} />
          <span className="text-slate-400 font-mono truncate flex-1">
            {inv.invite_type === 'SINGLE_USER' ? '👤' : '🔗'} {inv.target_email || inv.invite_type}
          </span>
          <span className={clsx('shrink-0', inv.is_used ? 'text-slate-600' : 'text-slate-500')}>
            {inv.is_used ? 'used' : timeUntil(inv.expires_at)}
          </span>
        </div>
      ))}
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function HubPage() {
  const qc = useQueryClient()
  const [manifest, setManifest]     = useState<HandshakeManifest | null>(null)
  const [magicLink, setMagicLink]   = useState<string | null>(null)

  const { data: tunnels = [], isLoading: loadingTunnels } = useQuery({
    queryKey: ['hub-tunnels'],
    queryFn:  getTunnels,
    refetchInterval: 30_000,
  })

  const { data: invites = [] } = useQuery({
    queryKey: ['hub-invites'],
    queryFn:  getInvites,
    refetchInterval: 60_000,
  })

  const revoke = useMutation({
    mutationFn: revokeTunnel,
    onSuccess:  () => qc.invalidateQueries({ queryKey: ['hub-tunnels'] }),
  })

  const genUserInvite = useMutation({
    mutationFn: () => generateUserInvite({ role: 'MEMBER', ttl_hours: 24 }),
    onSuccess:  (data) => {
      setMagicLink(data.magic_link)
      qc.invalidateQueries({ queryKey: ['hub-invites'] })
    },
  })

  const genManifest = useMutation({
    mutationFn: () => generatePlatformManifest({ ttl_hours: 24, permissions: { allow_rag: true } }),
    onSuccess:  (data) => setManifest(data),
  })

  const isLoading = genUserInvite.isPending || genManifest.isPending

  const handleRevoke = useCallback((id: string) => {
    if (confirm(`Revoke tunnel ${id.slice(0, 18)}…?\n\nThis will crypto-shred the AES key — all in-flight data will become unreadable immediately.`)) {
      revoke.mutate(id)
    }
  }, [revoke])

  const active  = tunnels.filter(t => t.status === 'ACTIVE')
  const pending = tunnels.filter(t => t.status === 'PENDING')

  return (
    <>
      <TopBar title="Warden Hub" />

      <div className="flex-1 p-6 space-y-6 overflow-auto">

        {/* Stats row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            { label: 'Active Tunnels',  value: active.length,  icon: Link2,     color: 'bg-green-500/10 text-green-400' },
            { label: 'Pending',         value: pending.length, icon: Clock,     color: 'bg-amber-500/10 text-amber-400' },
            { label: 'Total Tunnels',   value: tunnels.length, icon: Globe,     color: 'bg-brand-400/10 text-brand-400' },
            { label: 'Invites Sent',    value: invites.length, icon: Users,     color: 'bg-purple-500/10 text-purple-400' },
          ].map(({ label, value, icon: Icon, color }) => (
            <div key={label} className="card-glow p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-slate-500">{label}</p>
                  <p className="text-2xl font-bold text-white mt-0.5">{value}</p>
                </div>
                <div className={clsx('w-9 h-9 rounded-xl flex items-center justify-center', color)}>
                  <Icon className="w-4 h-4" />
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Main grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* Left: Map + Tunnel list */}
          <div className="lg:col-span-2 space-y-5">

            {/* Network Map */}
            <NetworkMap tunnels={tunnels} onRevoke={handleRevoke} />

            {/* Tunnel List */}
            <div className="card-glow overflow-hidden">
              <div className="flex items-center justify-between p-4 border-b border-white/[0.04]">
                <h2 className="font-semibold text-white flex items-center gap-2">
                  <Link2 className="w-4 h-4 text-brand-400" />
                  Tunnels
                </h2>
                <button
                  onClick={() => qc.invalidateQueries({ queryKey: ['hub-tunnels'] })}
                  className="text-slate-500 hover:text-slate-300 transition-colors"
                >
                  <RefreshCw className={clsx('w-4 h-4', loadingTunnels && 'animate-spin')} />
                </button>
              </div>

              {loadingTunnels ? (
                <div className="p-8 text-center text-slate-600 text-sm">Loading tunnels…</div>
              ) : tunnels.length === 0 ? (
                <div className="p-8 text-center space-y-2">
                  <Link2Off className="w-8 h-8 text-slate-700 mx-auto" />
                  <p className="text-slate-500 text-sm">No tunnels yet.</p>
                  <p className="text-slate-600 text-xs">Use &quot;Connect Platform&quot; to establish your first Zero-Trust Tunnel.</p>
                </div>
              ) : (
                tunnels.map(t => (
                  <TunnelRow key={t.tunnel_id} t={t} onRevoke={() => handleRevoke(t.tunnel_id)} />
                ))
              )}
            </div>
          </div>

          {/* Right: Actions + Invites */}
          <div className="space-y-5">

            <QuickActions
              onGenerateUserInvite={() => genUserInvite.mutate()}
              onGeneratePlatformManifest={() => genManifest.mutate()}
              loading={isLoading}
            />

            {/* Kill-All */}
            {active.length > 0 && (
              <div className="card-glow p-4">
                <h2 className="text-sm font-semibold text-red-400 flex items-center gap-2 mb-3">
                  <AlertTriangle className="w-4 h-4" />
                  Emergency Controls
                </h2>
                <button
                  onClick={() => {
                    if (confirm(`KILL ALL ${active.length} ACTIVE TUNNEL(S)?\n\nThis will crypto-shred all shared keys immediately. All in-progress AI requests across all tunnels will fail.`)) {
                      active.forEach(t => revoke.mutate(t.tunnel_id))
                    }
                  }}
                  className="btn-danger w-full flex items-center justify-center gap-2 text-sm"
                >
                  <ShieldOff className="w-4 h-4" />
                  Kill All Tunnels ({active.length})
                </button>
                <p className="text-xs text-slate-600 mt-2 text-center">Crypto-shreds all AES keys instantly</p>
              </div>
            )}

            {/* Invite History */}
            <div className="card-glow p-5">
              <h2 className="font-semibold text-white flex items-center gap-2 mb-4">
                <Plus className="w-4 h-4 text-brand-400" />
                Invite History
              </h2>
              <InviteHistory invites={invites} />
            </div>

          </div>
        </div>
      </div>

      {/* Modals */}
      {manifest   && <ManifestModal  manifest={manifest}  onClose={() => setManifest(null)} />}
      {magicLink  && <MagicLinkModal link={magicLink}     onClose={() => setMagicLink(null)} />}
    </>
  )
}
