'use client'

import { useState } from 'react'
import { Shield, Download, CheckCircle, AlertCircle, Clock, Activity,
         Lock, Eye, Database, FileText } from 'lucide-react'

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8001'

// ── Types ──────────────────────────────────────────────────────────────────────

interface TscBlock {
  tsc: string
  controls: string[]
  [key: string]: unknown
}

interface ReportSummary {
  period_days: number
  snapshots_found: number
  generated_at: string
  tsc_summary: {
    security:              { total_confused_deputy_blocks: number; total_pqc_auth_failures: number }
    availability:          { avg_availability_pct: number | null }
    processing_integrity:  { total_clearings: number; total_decimal_violations: number }
    privacy:               { total_gdpr_exports: number }
    confidentiality:       { total_pqc_ops: number }
  }
  daily_snapshots: { date: string; collection_ms: number | null }[]
}

// ── TSC card ───────────────────────────────────────────────────────────────────

function TscCard({
  icon: Icon,
  color,
  bg,
  title,
  tsc,
  stats,
  status,
}: {
  icon: React.ElementType
  color: string
  bg: string
  title: string
  tsc: string
  stats: { label: string; value: string | number }[]
  status: 'pass' | 'warn' | 'na'
}) {
  const statusIcon =
    status === 'pass' ? <CheckCircle className="w-4 h-4 text-green-400" /> :
    status === 'warn' ? <AlertCircle className="w-4 h-4 text-amber-400" /> :
                        <Clock className="w-4 h-4 text-slate-500" />

  return (
    <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-5">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className={`w-9 h-9 rounded-lg ${bg} flex items-center justify-center`}>
            <Icon className={`w-4 h-4 ${color}`} />
          </div>
          <div>
            <p className="text-sm font-semibold text-white">{title}</p>
            <p className="text-xs text-slate-500 font-mono">{tsc}</p>
          </div>
        </div>
        {statusIcon}
      </div>
      <div className="space-y-2">
        {stats.map(({ label, value }) => (
          <div key={label} className="flex items-center justify-between">
            <span className="text-xs text-slate-400">{label}</span>
            <span className="text-xs font-mono text-white/80">{value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Download button ────────────────────────────────────────────────────────────

function DownloadButton({ periodDays }: { periodDays: number }) {
  const [state, setState] = useState<'idle' | 'loading' | 'done' | 'error'>('idle')

  const download = async () => {
    setState('loading')
    try {
      const res = await fetch(
        `${API_BASE}/marketplace/compliance/soc2-report?period_days=${periodDays}&format=zip`,
        { headers: { 'X-Tenant-Tier': 'pro' } }
      )
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: 'Request failed' }))
        throw new Error(err.detail ?? `HTTP ${res.status}`)
      }
      const blob = await res.blob()
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = `soc2_evidence_${periodDays}d.zip`
      a.click()
      URL.revokeObjectURL(url)
      setState('done')
      setTimeout(() => setState('idle'), 3000)
    } catch (err: unknown) {
      console.error('SOC 2 download error:', err)
      setState('error')
      setTimeout(() => setState('idle'), 4000)
    }
  }

  const labels: Record<typeof state, string> = {
    idle:    'Download SOC 2 Artifacts',
    loading: 'Compiling evidence…',
    done:    'Downloaded',
    error:   'Download failed — check tier',
  }
  const colors: Record<typeof state, string> = {
    idle:    'bg-cyan-600 hover:bg-cyan-500 text-white',
    loading: 'bg-slate-700 text-slate-300 cursor-not-allowed',
    done:    'bg-green-700 text-white',
    error:   'bg-red-700 text-white',
  }

  return (
    <button
      onClick={download}
      disabled={state === 'loading'}
      className={`flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-medium transition-colors ${colors[state]}`}
    >
      <Download className="w-4 h-4" />
      {labels[state]}
    </button>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export default function CompliancePage() {
  const [periodDays, setPeriodDays] = useState(90)
  const [report, setReport]         = useState<ReportSummary | null>(null)
  const [loading, setLoading]       = useState(false)
  const [error, setError]           = useState<string | null>(null)

  const loadReport = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(
        `${API_BASE}/marketplace/compliance/soc2-report?period_days=${periodDays}&format=json`,
        { headers: { 'X-Tenant-Tier': 'pro' } }
      )
      if (!res.ok) {
        const body = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }))
        throw new Error(body.detail ?? `HTTP ${res.status}`)
      }
      setReport(await res.json())
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load report')
    } finally {
      setLoading(false)
    }
  }

  const ts = report?.tsc_summary

  return (
    <div className="flex-1 p-6 max-w-3xl space-y-6">

      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 flex items-center justify-center">
            <Shield className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-white">Compliance &amp; Security</h1>
            <p className="text-sm text-slate-500">
              SOC 2 Type II — automated evidence, TSC-mapped daily snapshots
            </p>
          </div>
        </div>
        <span className="text-xs font-mono px-2 py-1 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
          Pro+ required
        </span>
      </div>

      {/* Period selector + load */}
      <div className="card p-5">
        <h2 className="text-sm font-semibold text-white mb-4">Report Period</h2>
        <div className="flex items-center gap-4">
          <div className="flex gap-2">
            {([30, 90, 180, 365] as const).map(d => (
              <button
                key={d}
                onClick={() => setPeriodDays(d)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                  periodDays === d
                    ? 'bg-cyan-600 text-white'
                    : 'bg-white/[0.05] text-slate-400 hover:text-white'
                }`}
              >
                {d}d
              </button>
            ))}
          </div>
          <button
            onClick={loadReport}
            disabled={loading}
            className="px-4 py-1.5 rounded-lg text-xs font-medium bg-white/[0.06] hover:bg-white/[0.1] text-slate-300 transition-colors disabled:opacity-50"
          >
            {loading ? 'Loading…' : 'Load Summary'}
          </button>
        </div>
        {error && (
          <p className="mt-3 text-xs text-red-400 flex items-center gap-2">
            <AlertCircle className="w-3.5 h-3.5" /> {error}
          </p>
        )}
      </div>

      {/* TSC Cards */}
      {report && ts && (
        <>
          <div>
            <h2 className="text-sm font-semibold text-white mb-3">
              Trust Services Criteria — {report.snapshots_found} daily snapshots / {periodDays}d
            </h2>
            <div className="grid grid-cols-2 gap-3">
              <TscCard
                icon={Shield}
                color="text-red-400"
                bg="bg-red-400/10"
                title="Security"
                tsc="CC1–CC8"
                status={ts.security.total_confused_deputy_blocks === 0 ? 'pass' : 'warn'}
                stats={[
                  { label: 'Confused Deputy blocks', value: ts.security.total_confused_deputy_blocks },
                  { label: 'PQC auth failures',      value: ts.security.total_pqc_auth_failures },
                ]}
              />
              <TscCard
                icon={Activity}
                color="text-green-400"
                bg="bg-green-400/10"
                title="Availability"
                tsc="A1"
                status={
                  ts.availability.avg_availability_pct === null ? 'na' :
                  ts.availability.avg_availability_pct >= 99.9 ? 'pass' : 'warn'
                }
                stats={[
                  { label: 'Avg availability',
                    value: ts.availability.avg_availability_pct !== null
                      ? `${ts.availability.avg_availability_pct}%`
                      : 'no data' },
                ]}
              />
              <TscCard
                icon={Database}
                color="text-blue-400"
                bg="bg-blue-400/10"
                title="Processing Integrity"
                tsc="PI1"
                status={ts.processing_integrity.total_decimal_violations === 0 ? 'pass' : 'warn'}
                stats={[
                  { label: 'Clearings verified',   value: ts.processing_integrity.total_clearings },
                  { label: 'Decimal violations',   value: ts.processing_integrity.total_decimal_violations },
                ]}
              />
              <TscCard
                icon={Eye}
                color="text-purple-400"
                bg="bg-purple-400/10"
                title="Privacy"
                tsc="P1–P8"
                status="pass"
                stats={[
                  { label: 'GDPR export requests', value: ts.privacy.total_gdpr_exports },
                ]}
              />
              <TscCard
                icon={Lock}
                color="text-amber-400"
                bg="bg-amber-400/10"
                title="Confidentiality"
                tsc="C1"
                status="pass"
                stats={[
                  { label: 'PQC signing ops', value: ts.confidentiality.total_pqc_ops },
                  { label: 'Encryption at rest', value: 'AES-256 Fernet' },
                ]}
              />
              <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-5 flex flex-col justify-between">
                <div>
                  <p className="text-xs text-slate-400 mb-1">Generated</p>
                  <p className="text-xs font-mono text-white">{report.generated_at.slice(0, 19).replace('T', ' ')} UTC</p>
                </div>
                <div className="mt-4">
                  <p className="text-xs text-slate-400 mb-1">Daily snapshots</p>
                  <div className="flex gap-1 flex-wrap mt-1">
                    {report.daily_snapshots.slice(0, 14).map(s => (
                      <span
                        key={s.date}
                        title={`${s.date} — ${s.collection_ms ?? '?'}ms`}
                        className="w-3 h-3 rounded-sm bg-cyan-500/50"
                      />
                    ))}
                    {report.daily_snapshots.length > 14 && (
                      <span className="text-xs text-slate-500">+{report.daily_snapshots.length - 14}</span>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Download */}
          <div className="card p-5">
            <div className="flex items-start justify-between">
              <div>
                <h2 className="text-sm font-semibold text-white mb-1">Download SOC 2 Artifacts</h2>
                <p className="text-xs text-slate-500">
                  ZIP archive with all {report.snapshots_found} TSC-mapped daily JSON snapshots
                  + manifest. Safe to share with auditors (Deloitte, EY, etc.) — all
                  identifiers are SHA-256[:16] pseudonymised.
                </p>
              </div>
              <FileText className="w-5 h-5 text-slate-600 shrink-0 ml-4 mt-0.5" />
            </div>
            <div className="mt-4 flex items-center gap-3">
              <DownloadButton periodDays={periodDays} />
              <span className="text-xs text-slate-500">
                ~{report.snapshots_found} files · GDPR-safe
              </span>
            </div>
          </div>
        </>
      )}

      {/* Static info */}
      {!report && (
        <div className="card p-5 space-y-4">
          <h2 className="text-sm font-semibold text-white">About SOC 2 Type II Evidence</h2>
          <div className="space-y-3 text-xs text-slate-400">
            <p>Shadow Warden AI collects evidence daily at <span className="font-mono text-slate-300">00:00 UTC</span> via the <span className="font-mono text-cyan-300">sova_soc2_daily_collect</span> ARQ cron job.</p>
            <p>Each snapshot maps to all 5 Trust Services Criteria and is written atomically to <span className="font-mono text-slate-300">data/compliance_archives/</span>. Evidence covers the previous calendar day.</p>
            <p>The 90-day window satisfies the minimum SOC 2 Type II observation period required by most audit firms.</p>
            <p>All DID identifiers, wallet addresses, and agent IDs are SHA-256[:16] pseudonymised before inclusion.</p>
          </div>
          <button
            onClick={loadReport}
            className="px-4 py-2 rounded-lg text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-white transition-colors"
          >
            Load {periodDays}-day summary
          </button>
        </div>
      )}
    </div>
  )
}
