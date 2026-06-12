'use client'
import { useState, useEffect, useCallback } from 'react'
import { TopBar } from '@/components/layout/TopBar'
import { ExternalLink, RefreshCw, CheckCircle2, XCircle, AlertTriangle, HelpCircle, Activity } from 'lucide-react'

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'https://api.shadow-warden-ai.com'

type ServiceHealth = {
  name: string
  display: string
  status: 'ok' | 'degraded' | 'down' | 'unknown' | 'partial'
  latency_ms: number | null
  detail: string
}

type DeployStatus = {
  checked_at: string
  overall: 'ok' | 'degraded' | 'down' | 'partial'
  ok_count: number
  total: number
  services: ServiceHealth[]
}

const statusCfg = {
  ok:       { color: '#30D158', label: 'OK',       Icon: CheckCircle2  },
  degraded: { color: '#FF9F0A', label: 'Degraded', Icon: AlertTriangle  },
  down:     { color: '#FF2D55', label: 'Down',     Icon: XCircle       },
  unknown:  { color: '#8E8E9E', label: 'Unknown',  Icon: HelpCircle    },
  partial:  { color: '#BF5AF2', label: 'Partial',  Icon: AlertTriangle  },
} as const

const QUICK_LINKS = [
  { label: 'Grafana',       href: 'http://91.98.234.160:3000',   desc: 'Metrics & alerting'  },
  { label: 'Jaeger Traces', href: 'http://91.98.234.160:16686',  desc: 'Distributed tracing' },
  { label: 'MinIO Console', href: 'http://91.98.234.160:9001',   desc: 'Object storage UI'   },
  { label: 'Prometheus',    href: 'http://91.98.234.160:9090',   desc: 'Raw metrics'         },
  { label: 'API Docs',      href: `${API_URL}/docs`,             desc: 'Swagger docs'        },
  { label: 'API Redoc',     href: `${API_URL}/redoc`,            desc: 'ReDoc reference'     },
]

export default function DeploymentPage() {
  const [data, setData] = useState<DeployStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [lastCheck, setLastCheck] = useState('')

  const fetchStatus = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const res = await fetch(`${API_URL}/deploy/status`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      setData(await res.json())
      setLastCheck(new Date().toLocaleTimeString())
    } catch (e) {
      setError(e instanceof Error ? e.message : 'fetch error')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchStatus()
    const id = setInterval(fetchStatus, 30_000)
    return () => clearInterval(id)
  }, [fetchStatus])

  const overall = data?.overall ?? 'unknown'
  const cfg = statusCfg[overall as keyof typeof statusCfg] ?? statusCfg.unknown

  return (
    <div className="flex flex-col min-h-screen">
      <TopBar title="Deployment & Infrastructure" />

      <div className="flex-1 p-6 max-w-5xl mx-auto w-full space-y-6">

        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold mb-1">Infrastructure Status</h1>
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
              Live health of all 11 Shadow Warden services. Auto-refreshes every 30 s.
            </p>
          </div>
          <button
            onClick={fetchStatus}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
            style={{ background: 'rgba(255,255,255,0.06)', color: 'var(--text-muted)' }}
          >
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>

        {/* Overall banner */}
        {data && (
          <div
            className="rounded-2xl px-5 py-4 flex items-center justify-between"
            style={{
              background: cfg.color + '14',
              border: `1px solid ${cfg.color}30`,
            }}
          >
            <div>
              <div className="flex items-center gap-2">
                <cfg.Icon size={16} style={{ color: cfg.color }} />
                <span className="font-bold text-base" style={{ color: cfg.color }}>
                  {overall === 'ok'       ? 'All Systems Operational' :
                   overall === 'degraded' ? 'Partial Degradation'     :
                   overall === 'down'     ? 'Service Outage'          :
                                           'Some Services Unknown'}
                </span>
              </div>
              <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                {data.ok_count} / {data.total} healthy{lastCheck ? ` · last checked ${lastCheck}` : ''}
              </p>
            </div>
            <div className="text-2xl font-black" style={{ color: cfg.color }}>
              {data.ok_count}/{data.total}
            </div>
          </div>
        )}

        {error && (
          <div
            className="rounded-xl px-4 py-3 text-sm"
            style={{ background: 'rgba(255,45,85,0.1)', border: '1px solid rgba(255,45,85,0.3)', color: '#FF2D55' }}
          >
            Could not reach <code className="font-mono">/deploy/status</code> — {error}
          </div>
        )}

        {/* Two-column layout: services + quick links */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* Service grid */}
          <div className="lg:col-span-2 space-y-2">
            <h2 className="text-sm font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
              Services
            </h2>
            {loading && !data && (
              <div className="space-y-2">
                {Array.from({ length: 8 }).map((_, i) => (
                  <div key={i} className="h-14 rounded-xl animate-pulse" style={{ background: 'rgba(255,255,255,0.04)' }} />
                ))}
              </div>
            )}
            {data?.services.map(svc => {
              const sc = statusCfg[svc.status as keyof typeof statusCfg] ?? statusCfg.unknown
              const SvcIcon = sc.Icon
              return (
                <div
                  key={svc.name}
                  className="rounded-xl px-4 py-3 flex items-center gap-3 border"
                  style={{ borderColor: sc.color + '28', background: sc.color + '0a' }}
                >
                  <SvcIcon size={15} style={{ color: sc.color }} className="shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-sm font-semibold truncate">{svc.display}</span>
                      <span
                        className="text-[10px] font-bold px-1.5 py-0.5 rounded-full shrink-0"
                        style={{ background: sc.color + '20', color: sc.color }}
                      >
                        {sc.label}
                      </span>
                    </div>
                    <p className="text-[11px] truncate" style={{ color: 'var(--text-muted)' }}>{svc.detail}</p>
                  </div>
                  {svc.latency_ms !== null && (
                    <span className="text-[10px] font-mono shrink-0" style={{ color: 'var(--text-muted)' }}>
                      {svc.latency_ms.toFixed(1)} ms
                    </span>
                  )}
                </div>
              )
            })}
          </div>

          {/* Quick links panel */}
          <div className="space-y-3">
            <h2 className="text-sm font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
              Consoles
            </h2>
            {QUICK_LINKS.map(link => (
              <a
                key={link.href}
                href={link.href}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-between rounded-xl px-4 py-3 border transition-all hover:-translate-y-0.5"
                style={{ border: '1px solid rgba(255,255,255,0.07)', background: 'rgba(255,255,255,0.03)' }}
              >
                <div>
                  <p className="text-[13px] font-semibold">{link.label}</p>
                  <p className="text-[11px]" style={{ color: 'var(--text-muted)' }}>{link.desc}</p>
                </div>
                <ExternalLink size={12} style={{ color: 'var(--text-muted)' }} className="shrink-0 ml-2" />
              </a>
            ))}

            {/* API health box */}
            <div
              className="rounded-xl px-4 py-3 border mt-4"
              style={{ border: '1px solid rgba(10,132,255,0.2)', background: 'rgba(10,132,255,0.06)' }}
            >
              <div className="flex items-center gap-2 mb-1">
                <Activity size={13} style={{ color: '#0A84FF' }} />
                <span className="text-xs font-semibold" style={{ color: '#0A84FF' }}>API Base URL</span>
              </div>
              <code className="text-[11px] font-mono text-gray-300 break-all">{API_URL}</code>
            </div>
          </div>
        </div>

      </div>
    </div>
  )
}
