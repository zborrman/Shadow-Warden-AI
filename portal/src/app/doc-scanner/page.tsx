'use client'
import { useState, useRef, useCallback } from 'react'
import type { DragEvent, ChangeEvent } from 'react'
import {
  Upload, FileText, AlertTriangle, CheckCircle,
  XCircle, Eye, EyeOff, Loader2, ScanSearch,
} from 'lucide-react'
import { useTheme } from '@/components/ui/ThemeProvider'

// ── Types ─────────────────────────────────────────────────────────────────────

type FilterResult = {
  allowed:        boolean
  risk_level:     string
  semantic_flags?: string[]
  secrets_found?: string[]
  data_class?:    string
}

type ScanResult = {
  filename:      string
  markdown:      string
  data_class:    string
  secrets_found: string[]
  redacted:      boolean
  word_count:    number
  char_count:    number
  from_cache:    boolean
  filter?:       FilterResult
}

// ── Constants ─────────────────────────────────────────────────────────────────

const RISK_STYLES: Record<string, { bg: string; text: string; label: string }> = {
  allow:  { bg: 'rgba(16,185,129,0.12)',  text: '#10b981', label: 'ALLOW'  },
  low:    { bg: 'rgba(16,185,129,0.12)',  text: '#10b981', label: 'LOW'    },
  medium: { bg: 'rgba(245,158,11,0.12)',  text: '#f59e0b', label: 'MEDIUM' },
  high:   { bg: 'rgba(239,68,68,0.14)',   text: '#ef4444', label: 'HIGH'   },
  block:  { bg: 'rgba(239,68,68,0.18)',   text: '#ef4444', label: 'BLOCK'  },
}

const DC_COLOR: Record<string, string> = {
  GENERAL:    '#60a5fa',
  PHI:        '#f87171',
  PII:        '#fb923c',
  FINANCIAL:  '#fbbf24',
  CLASSIFIED: '#ef4444',
}

const SUPPORTED_FORMATS = [
  'PDF','DOCX','PPTX','XLSX','HTML',
  'JPG','PNG','WEBP','GIF',
  'MP3','WAV','FLAC',
  'ZIP','EPUB','CSV','TXT',
]

const ACCEPT = [
  '.pdf','.docx','.pptx','.xlsx','.xls',
  '.html','.htm',
  '.jpg','.jpeg','.png','.gif','.bmp','.webp',
  '.zip','.epub','.csv','.txt','.md',
  '.mp3','.wav','.flac','.m4a',
].join(',')

// ── Page ──────────────────────────────────────────────────────────────────────

export default function DocScannerPage() {
  const { theme } = useTheme()
  const isDark = theme === 'dark'

  const bg        = isDark ? '#080e1a' : '#f8fafc'
  const surface   = isDark ? '#0f172a' : '#ffffff'
  const border    = isDark ? 'rgba(255,255,255,0.08)' : '#e2e8f0'
  const textMain  = isDark ? '#f1f5f9' : '#0f172a'
  const textMuted = isDark ? '#64748b' : '#94a3b8'

  const [dragging, setDragging]     = useState(false)
  const [file, setFile]             = useState<File | null>(null)
  const [loading, setLoading]       = useState(false)
  const [result, setResult]         = useState<ScanResult | null>(null)
  const [error, setError]           = useState<string | null>(null)
  const [showMd, setShowMd]         = useState(false)
  const inputRef                    = useRef<HTMLInputElement>(null)

  function pickFile(f: File) {
    setFile(f)
    setResult(null)
    setError(null)
  }

  const onDrop = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files[0]
    if (f) pickFile(f)
  }, [])

  function onFileChange(e: ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0]
    if (f) pickFile(f)
  }

  async function scan() {
    if (!file) return
    setLoading(true)
    setError(null)
    setResult(null)

    const fd = new FormData()
    fd.append('file', file)
    fd.append('tenant_id', 'default')

    try {
      const res  = await fetch('/api/doc-scanner', { method: 'POST', body: fd })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail ?? `HTTP ${res.status}`)
      setResult(data as ScanResult)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed — check the gateway connection.')
    } finally {
      setLoading(false)
    }
  }

  const riskKey   = result?.filter?.risk_level?.toLowerCase() ?? 'low'
  const riskStyle = RISK_STYLES[riskKey] ?? RISK_STYLES.low
  const allowed   = result?.filter?.allowed !== false

  return (
    <div className="flex flex-col min-h-screen" style={{ background: bg }}>

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="px-6 py-4 flex items-center gap-3 shrink-0"
           style={{ background: surface, borderBottom: `1px solid ${border}` }}>
        <div className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
             style={{ background: 'rgba(255,45,85,0.12)' }}>
          <ScanSearch className="w-[18px] h-[18px]" style={{ color: '#FF2D55' }} />
        </div>
        <div>
          <h1 className="text-[15px] font-bold leading-tight" style={{ color: textMain }}>Document Scanner</h1>
          <p className="text-[11px]" style={{ color: textMuted }}>
            Convert any file to Markdown and run the 9-layer Warden pipeline
          </p>
        </div>
        <span className="ml-auto text-[10px] font-bold px-2 py-0.5 rounded-full"
              style={{ background: 'rgba(255,45,85,0.1)', color: '#FF2D55' }}>
          FE-50
        </span>
      </div>

      {/* ── Content ────────────────────────────────────────────────────── */}
      <div className="flex-1 p-6">
        <div className="max-w-2xl mx-auto space-y-5">

          {/* Drop zone */}
          <div
            onClick={() => inputRef.current?.click()}
            onDragOver={e => { e.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
            className="rounded-2xl p-8 text-center cursor-pointer transition-all duration-200 select-none"
            style={{
              background: dragging ? 'rgba(255,45,85,0.06)' : surface,
              border: `2px dashed ${dragging ? '#FF2D55' : border}`,
            }}
          >
            <input ref={inputRef} type="file" className="hidden" accept={ACCEPT} onChange={onFileChange} />

            {file ? (
              <div className="flex flex-col items-center gap-2">
                <FileText className="w-8 h-8" style={{ color: '#FF2D55' }} />
                <p className="text-[14px] font-semibold" style={{ color: textMain }}>{file.name}</p>
                <p className="text-[12px]" style={{ color: textMuted }}>
                  {(file.size / 1024).toFixed(1)} KB — click to replace
                </p>
              </div>
            ) : (
              <div className="flex flex-col items-center gap-3">
                <Upload className="w-8 h-8" style={{ color: textMuted }} />
                <div>
                  <p className="text-[14px] font-semibold" style={{ color: textMain }}>
                    Drop a file or click to upload
                  </p>
                  <p className="text-[12px] mt-0.5" style={{ color: textMuted }}>Max 50 MB</p>
                </div>
              </div>
            )}
          </div>

          {/* Format chips */}
          <div className="flex flex-wrap gap-1.5">
            {SUPPORTED_FORMATS.map(f => (
              <span key={f} className="text-[10px] font-semibold px-2 py-0.5 rounded-md"
                    style={{ background: isDark ? 'rgba(255,255,255,0.05)' : '#f1f5f9', color: textMuted }}>
                {f}
              </span>
            ))}
          </div>

          {/* Scan button */}
          <button
            onClick={scan}
            disabled={!file || loading}
            className="w-full py-3 rounded-xl text-[14px] font-bold transition-all duration-200 flex items-center justify-center gap-2"
            style={{
              background: !file || loading ? (isDark ? 'rgba(255,255,255,0.05)' : '#e2e8f0') : '#FF2D55',
              color: !file || loading ? textMuted : '#ffffff',
              cursor: !file || loading ? 'not-allowed' : 'pointer',
              boxShadow: !file || loading ? 'none' : '0 0 20px rgba(255,45,85,0.35)',
            }}
          >
            {loading
              ? <><Loader2 className="w-4 h-4 animate-spin" />Scanning…</>
              : <><ScanSearch className="w-4 h-4" />Scan Document</>}
          </button>

          {/* Error */}
          {error && (
            <div className="rounded-xl p-4 flex items-start gap-3"
                 style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.22)' }}>
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
              <p className="text-[13px] text-red-400">{error}</p>
            </div>
          )}

          {/* ── Results ──────────────────────────────────────────────── */}
          {result && (
            <div className="space-y-4">

              {/* Verdict banner */}
              <div className="rounded-2xl p-5 flex items-center gap-4"
                   style={{ background: riskStyle.bg, border: `1px solid ${riskStyle.text}30` }}>
                {allowed
                  ? <CheckCircle className="w-6 h-6 shrink-0" style={{ color: riskStyle.text }} />
                  : <XCircle     className="w-6 h-6 shrink-0" style={{ color: riskStyle.text }} />}
                <div className="min-w-0">
                  <p className="text-[15px] font-bold" style={{ color: riskStyle.text }}>
                    {allowed ? 'Document Allowed' : 'Document Blocked'}
                  </p>
                  <p className="text-[12px]" style={{ color: riskStyle.text + '99' }}>
                    {result.filename}
                  </p>
                </div>
                <span className="ml-auto shrink-0 text-[11px] font-bold px-2.5 py-1 rounded-full"
                      style={{ background: riskStyle.text + '1a', color: riskStyle.text }}>
                  {riskStyle.label}
                </span>
              </div>

              {/* Metadata grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                  { label: 'Data Class',    value: result.data_class, color: DC_COLOR[result.data_class] ?? '#60a5fa' },
                  { label: 'Words',         value: result.word_count.toLocaleString(), color: textMain },
                  { label: 'Secrets Found', value: String(result.secrets_found.length),
                    color: result.secrets_found.length ? '#f87171' : '#10b981' },
                  { label: 'Cache Hit',     value: result.from_cache ? 'Yes' : 'No',
                    color: result.from_cache ? '#10b981' : textMuted },
                ].map(({ label, value, color }) => (
                  <div key={label} className="rounded-xl p-3"
                       style={{ background: surface, border: `1px solid ${border}` }}>
                    <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: textMuted }}>{label}</p>
                    <p className="text-[14px] font-bold" style={{ color }}>{value}</p>
                  </div>
                ))}
              </div>

              {/* Secrets */}
              {result.secrets_found.length > 0 && (
                <div className="rounded-xl p-4"
                     style={{ background: 'rgba(248,113,113,0.07)', border: '1px solid rgba(248,113,113,0.2)' }}>
                  <p className="text-[12px] font-semibold text-red-400 mb-2">
                    {result.secrets_found.length} secret type(s) detected and redacted
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {result.secrets_found.map(s => (
                      <span key={s} className="text-[11px] font-mono px-2 py-0.5 rounded-md text-red-300"
                            style={{ background: 'rgba(248,113,113,0.12)' }}>
                        {s}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Semantic flags */}
              {(result.filter?.semantic_flags?.length ?? 0) > 0 && (
                <div className="rounded-xl p-4"
                     style={{ background: 'rgba(251,191,36,0.07)', border: '1px solid rgba(251,191,36,0.2)' }}>
                  <p className="text-[12px] font-semibold text-yellow-400 mb-2">Semantic flags detected</p>
                  <div className="flex flex-wrap gap-1.5">
                    {result.filter!.semantic_flags!.map(f => (
                      <span key={f} className="text-[11px] font-mono px-2 py-0.5 rounded-md text-yellow-300"
                            style={{ background: 'rgba(251,191,36,0.12)' }}>
                        {f}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Markdown preview */}
              {result.markdown && (
                <div className="rounded-2xl overflow-hidden" style={{ border: `1px solid ${border}` }}>
                  <button
                    onClick={() => setShowMd(v => !v)}
                    className="w-full flex items-center gap-2 px-5 py-3 text-[12px] font-medium transition-colors"
                    style={{ background: surface, color: textMuted }}
                  >
                    {showMd
                      ? <EyeOff className="w-3.5 h-3.5 shrink-0" />
                      : <Eye    className="w-3.5 h-3.5 shrink-0" />}
                    {showMd ? 'Hide extracted Markdown' : 'Show extracted Markdown'}
                    <span className="ml-auto font-mono text-[10px]">
                      {result.char_count.toLocaleString()} chars
                    </span>
                  </button>
                  {showMd && (
                    <pre className="p-5 text-[11px] leading-relaxed overflow-auto max-h-72 font-mono whitespace-pre-wrap"
                         style={{ background: isDark ? '#060c16' : '#f8fafc', color: textMuted }}>
                      {result.markdown.slice(0, 8_000)}
                      {result.markdown.length > 8_000 ? '\n…(truncated)' : ''}
                    </pre>
                  )}
                </div>
              )}

            </div>
          )}
        </div>
      </div>
    </div>
  )
}
