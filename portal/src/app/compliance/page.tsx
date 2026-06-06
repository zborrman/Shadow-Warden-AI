'use client'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Shield, RefreshCw, AlertTriangle, CheckCircle, XCircle, ChevronRight } from 'lucide-react'
import { useTheme } from '@/components/ui/ThemeProvider'

// ── Types ─────────────────────────────────────────────────────────────────────

type Gap = {
  control_id:      string
  description:     string
  severity:        'high' | 'medium' | 'low'
  remediation:     string
  affected_module: string
}

type FrameworkScore = {
  framework:       string
  score:           number
  status:          string
  total_controls:  number
  passed_controls: number
  gaps:            Gap[]
}

type ComplianceReport = {
  tenant_id:       string
  generated_at:    string
  overall_score:   number
  overall_status:  string
  frameworks:      FrameworkScore[]
  recommendations: string[]
}

// ── Constants ─────────────────────────────────────────────────────────────────

const FW_LABEL: Record<string, string> = {
  gdpr: 'GDPR', soc2: 'SOC 2', iso27001: 'ISO 27001', hipaa: 'HIPAA',
}

const FW_COLOR: Record<string, string> = {
  gdpr: '#3b82f6', soc2: '#8b5cf6', iso27001: '#06b6d4', hipaa: '#10b981',
}

const STATUS_COLOR: Record<string, string> = {
  compliant:     '#10b981',
  at_risk:       '#f59e0b',
  non_compliant: '#ef4444',
}

const SEV_COLOR: Record<string, string> = {
  high: '#ef4444', medium: '#f59e0b', low: '#94a3b8',
}

const MODULE_LINKS: Record<string, string> = {
  vendor_governance:  '/vendor-governance/',
  incident_register:  '/incidents/',
  training_records:   '/training/',
  supplier_risk:      '/supplier-risk/',
  secrets_governance: '/settings/?tab=secrets',
  alerting:           '/settings/',
  document_intel:     '/doc-scanner/',
  communities:        '/communities/',
}

// ── API helpers ───────────────────────────────────────────────────────────────

async function fetchReport(tenantId: string): Promise<ComplianceReport> {
  const res = await fetch(`/api/compliance/posture/recalculate?tenant_id=${tenantId}`, { method: 'POST' })
  if (!res.ok) {
    // Fall back to GET posture
    const r2 = await fetch(`/api/compliance/posture/gaps?tenant_id=${tenantId}`)
    if (!r2.ok) throw new Error(`${r2.status}`)
    return r2.json()
  }
  return res.json()
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function CompliancePage() {
  const { theme }  = useTheme()
  const isDark     = theme === 'dark'
  const qc         = useQueryClient()
  const [active, setActive] = useState<string | null>(null)

  const bg        = isDark ? '#080e1a' : '#f8fafc'
  const surface   = isDark ? '#0f172a' : '#ffffff'
  const border    = isDark ? 'rgba(255,255,255,0.08)' : '#e2e8f0'
  const textMain  = isDark ? '#f1f5f9' : '#0f172a'
  const textMuted = isDark ? '#64748b' : '#94a3b8'

  const { data, isLoading, isError, refetch } = useQuery<ComplianceReport>({
    queryKey: ['compliance-posture'],
    queryFn:  () => fetchReport('default'),
    refetchInterval: 30_000,
    retry: false,
  })

  const recalcMutation = useMutation({
    mutationFn: () => fetch('/api/compliance/posture/recalculate?tenant_id=default', { method: 'POST' }),
    onSuccess:  () => qc.invalidateQueries({ queryKey: ['compliance-posture'] }),
  })

  const overall = data?.overall_score ?? 0
  const status  = data?.overall_status ?? 'unknown'
  const statusColor = STATUS_COLOR[status] ?? '#94a3b8'
  const allGaps = data?.frameworks?.flatMap(f => f.gaps) ?? []
  const highCount = allGaps.filter(g => g.severity === 'high').length

  return (
    <div className="flex flex-col min-h-screen" style={{ background: bg }}>

      {/* Header */}
      <div className="px-6 py-4 flex items-center gap-3 shrink-0"
           style={{ background: surface, borderBottom: `1px solid ${border}` }}>
        <div className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
             style={{ background: 'rgba(16,185,129,0.12)' }}>
          <Shield className="w-[18px] h-[18px]" style={{ color: '#10b981' }} />
        </div>
        <div>
          <h1 className="text-[15px] font-bold leading-tight" style={{ color: textMain }}>
            Compliance Posture
          </h1>
          <p className="text-[11px]" style={{ color: textMuted }}>
            Live gap analysis — GDPR · SOC 2 · ISO 27001 · HIPAA
          </p>
        </div>
        <button
          onClick={() => recalcMutation.mutate()}
          className="ml-auto flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-medium transition-all"
          style={{ background: isDark ? 'rgba(255,255,255,0.05)' : '#f1f5f9', color: textMuted }}
        >
          <RefreshCw className={`w-3.5 h-3.5 ${recalcMutation.isPending ? 'animate-spin' : ''}`} />
          Recalculate
        </button>
      </div>

      <div className="flex-1 p-6 space-y-6">

        {isLoading && (
          <div className="flex items-center justify-center h-32">
            <RefreshCw className="w-6 h-6 animate-spin" style={{ color: textMuted }} />
          </div>
        )}

        {isError && (
          <div className="rounded-xl p-4 flex items-center gap-3"
               style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)' }}>
            <AlertTriangle className="w-4 h-4 text-red-400" />
            <p className="text-[13px] text-red-400">
              Compliance service unavailable — check gateway connection.
            </p>
          </div>
        )}

        {data && (
          <>
            {/* Overall score */}
            <div className="rounded-2xl p-6 flex items-center gap-6"
                 style={{ background: surface, border: `1px solid ${border}` }}>
              {/* Ring */}
              <div className="relative w-20 h-20 shrink-0">
                <svg viewBox="0 0 80 80" className="w-20 h-20 -rotate-90">
                  <circle cx="40" cy="40" r="32" fill="none" stroke={isDark ? '#1e293b' : '#f1f5f9'} strokeWidth="8" />
                  <circle cx="40" cy="40" r="32" fill="none" stroke={statusColor} strokeWidth="8"
                    strokeDasharray={`${overall / 100 * 201} 201`} strokeLinecap="round" />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-[13px] font-bold" style={{ color: statusColor }}>{Math.round(overall)}%</span>
                </div>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-[18px] font-bold" style={{ color: textMain }}>
                  Overall Compliance Score
                </p>
                <p className="text-[13px] mt-0.5" style={{ color: statusColor }}>
                  {status.replace('_', ' ').toUpperCase()}
                </p>
                {data.recommendations?.map((r, i) => (
                  <p key={i} className="text-[12px] mt-1" style={{ color: textMuted }}>
                    ⚠ {r}
                  </p>
                ))}
              </div>
              {highCount > 0 && (
                <div className="shrink-0 flex flex-col items-center rounded-xl px-4 py-3"
                     style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)' }}>
                  <span className="text-[22px] font-black text-red-400">{highCount}</span>
                  <span className="text-[10px] font-bold text-red-400">HIGH GAPS</span>
                </div>
              )}
            </div>

            {/* Framework cards */}
            <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {data.frameworks.map(fw => {
                const color = FW_COLOR[fw.framework] ?? '#6366f1'
                const sc    = STATUS_COLOR[fw.status] ?? '#94a3b8'
                return (
                  <button
                    key={fw.framework}
                    onClick={() => setActive(active === fw.framework ? null : fw.framework)}
                    className="rounded-2xl p-4 text-left transition-all duration-200"
                    style={{
                      background: active === fw.framework ? `${color}12` : surface,
                      border: `1px solid ${active === fw.framework ? color + '40' : border}`,
                    }}
                  >
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-[13px] font-bold" style={{ color }}>{FW_LABEL[fw.framework]}</span>
                      <span className="text-[11px] font-bold" style={{ color: sc }}>{Math.round(fw.score)}%</span>
                    </div>
                    <div className="h-1.5 rounded-full mb-3" style={{ background: isDark ? '#1e293b' : '#f1f5f9' }}>
                      <div className="h-full rounded-full transition-all" style={{ width: `${fw.score}%`, background: color }} />
                    </div>
                    <div className="flex items-center justify-between text-[11px]" style={{ color: textMuted }}>
                      <span>{fw.passed_controls}/{fw.total_controls} passed</span>
                      {fw.gaps.length > 0 && (
                        <span className="font-semibold" style={{ color: '#ef4444' }}>
                          {fw.gaps.length} gap{fw.gaps.length !== 1 ? 's' : ''}
                        </span>
                      )}
                    </div>
                  </button>
                )
              })}
            </div>

            {/* Gap detail panel */}
            {active && (() => {
              const fw = data.frameworks.find(f => f.framework === active)
              if (!fw) return null
              return (
                <div className="rounded-2xl p-5 space-y-3"
                     style={{ background: surface, border: `1px solid ${border}` }}>
                  <p className="text-[14px] font-bold" style={{ color: textMain }}>
                    {FW_LABEL[active]} — Gaps
                  </p>
                  {fw.gaps.length === 0 ? (
                    <div className="flex items-center gap-2 text-[13px]" style={{ color: '#10b981' }}>
                      <CheckCircle className="w-4 h-4" />All controls passing
                    </div>
                  ) : (
                    fw.gaps.map(gap => {
                      const link = MODULE_LINKS[gap.affected_module]
                      return (
                        <div key={gap.control_id} className="rounded-xl p-4"
                             style={{ background: isDark ? '#111827' : '#f8fafc', border: `1px solid ${SEV_COLOR[gap.severity]}22` }}>
                          <div className="flex items-start justify-between gap-3 mb-1">
                            <div className="flex items-center gap-2">
                              {gap.severity === 'high'
                                ? <XCircle className="w-4 h-4 shrink-0 text-red-400" />
                                : <AlertTriangle className="w-4 h-4 shrink-0 text-yellow-400" />}
                              <span className="text-[13px] font-semibold" style={{ color: textMain }}>
                                {gap.control_id}
                              </span>
                              <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-md"
                                    style={{ color: SEV_COLOR[gap.severity], background: SEV_COLOR[gap.severity] + '15' }}>
                                {gap.severity.toUpperCase()}
                              </span>
                            </div>
                            {link && (
                              <a href={link}
                                 className="flex items-center gap-1 text-[11px] font-semibold shrink-0 hover:opacity-80 transition-opacity no-underline"
                                 style={{ color: FW_COLOR[active] }}>
                                Fix <ChevronRight className="w-3 h-3" />
                              </a>
                            )}
                          </div>
                          <p className="text-[12px] mb-1" style={{ color: textMuted }}>{gap.description}</p>
                          <p className="text-[11px] font-mono px-2 py-1 rounded-md"
                             style={{ background: isDark ? '#1e293b' : '#f1f5f9', color: textMuted }}>
                            {gap.remediation}
                          </p>
                        </div>
                      )
                    })
                  )}
                </div>
              )
            })()}

            <p className="text-[11px] text-center" style={{ color: textMuted }}>
              Last updated: {new Date(data.generated_at).toLocaleString()} · Auto-refreshes every 30s
            </p>
          </>
        )}
      </div>
    </div>
  )
}
