'use client'
/**
 * /community-hub/hub/[id]/data — Data Upload & Asset Management
 * Phase 4: CSV/JSON drag-drop → preview → register asset → Semantic AI query
 */

import { useState, useRef, useCallback, DragEvent, ChangeEvent } from 'react'
import { useParams } from 'next/navigation'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import Link from 'next/link'
import toast from 'react-hot-toast'
import {
  Upload, Database, FileText, Table2, Zap, Package,
  CheckCircle2, AlertTriangle, Loader2, ArrowLeft, Trash2,
  Search, BarChart2, Tag,
} from 'lucide-react'
import {
  agenticCommerceApi, type MktAsset, type MktAgent,
} from '@/lib/agenticCommerceApi'
import { getMyTenantId } from '@/lib/communityHubApi'

const MAX_ROWS = 1000

// ── CSV / JSON parse ──────────────────────────────────────────────────────────

function parseCSV(text: string): { headers: string[]; rows: string[][] } {
  const lines = text.trim().split('\n').filter(Boolean)
  if (lines.length === 0) return { headers: [], rows: [] }
  const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, ''))
  const rows = lines.slice(1, MAX_ROWS + 1).map(l =>
    l.split(',').map(c => c.trim().replace(/^"|"$/g, ''))
  )
  return { headers, rows }
}

function parseJSON(text: string): { headers: string[]; rows: string[][] } {
  const data = JSON.parse(text)
  const arr: Record<string, unknown>[] = Array.isArray(data) ? data.slice(0, MAX_ROWS) : [data]
  if (arr.length === 0) return { headers: [], rows: [] }
  const headers = Object.keys(arr[0])
  const rows = arr.map(r => headers.map(h => String(r[h] ?? '')))
  return { headers, rows }
}

type ParsedData = {
  name:    string
  ext:     string
  headers: string[]
  rows:    string[][]
  raw:     string
}

// ── Components ────────────────────────────────────────────────────────────────

function Pill({ color, children }: { color: string; children: React.ReactNode }) {
  const map: Record<string, string> = {
    green:  'bg-emerald-400/10 text-emerald-400 border-emerald-400/20',
    blue:   'bg-blue-400/10 text-blue-400 border-blue-400/20',
    violet: 'bg-violet-400/10 text-violet-400 border-violet-400/20',
    amber:  'bg-amber-400/10 text-amber-400 border-amber-400/20',
    slate:  'bg-slate-400/10 text-slate-400 border-slate-400/20',
  }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${map[color] ?? map.slate}`}>
      {children}
    </span>
  )
}

function fmtDate(s: string) {
  return new Date(s).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: '2-digit' })
}

const EXT_COLOR: Record<string, string> = { csv: '#30D158', json: '#FF9F0A', sqlite: '#0A84FF', db: '#0A84FF' }

// ── Upload zone ───────────────────────────────────────────────────────────────

function DropZone({ onFile }: { onFile: (f: File) => void }) {
  const [over, setOver] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  const handle = (f: File) => { if (f) onFile(f) }

  const onDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault(); setOver(false)
    const f = e.dataTransfer.files[0]
    if (f) handle(f)
  }

  const onChange = (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (f) handle(f)
    e.target.value = ''
  }

  return (
    <div
      onDragOver={e => { e.preventDefault(); setOver(true) }}
      onDragLeave={() => setOver(false)}
      onDrop={onDrop}
      onClick={() => inputRef.current?.click()}
      className={`relative flex flex-col items-center justify-center gap-3 rounded-2xl border-2 border-dashed py-14 cursor-pointer transition-all ${
        over ? 'border-blue-500/60 bg-blue-500/5' : 'border-white/10 bg-white/2 hover:border-white/20 hover:bg-white/4'
      }`}
    >
      <input ref={inputRef} type="file" accept=".csv,.json,.sqlite,.db" onChange={onChange} className="hidden" />
      <div className="w-12 h-12 rounded-2xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
        <Upload className="w-5 h-5 text-blue-400" />
      </div>
      <div className="text-center">
        <p className="text-sm font-medium text-white">Drop a file or click to browse</p>
        <p className="text-xs text-slate-400 mt-1">CSV, JSON, SQLite — up to {MAX_ROWS.toLocaleString()} rows</p>
      </div>
      <div className="flex gap-2">
        {['CSV', 'JSON', 'SQLite'].map(t => (
          <span key={t} className="px-2 py-0.5 rounded text-xs bg-white/4 text-slate-400 border border-white/8">{t}</span>
        ))}
      </div>
    </div>
  )
}

// ── Preview table ─────────────────────────────────────────────────────────────

function DataPreview({ data }: { data: ParsedData }) {
  const PREVIEW_ROWS = 8
  return (
    <div className="rounded-xl border border-white/8 bg-white/3 overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-white/6">
        <div
          className="w-6 h-6 rounded flex items-center justify-center text-[10px] font-bold"
          style={{ background: `${EXT_COLOR[data.ext] ?? '#6b7280'}20`, color: EXT_COLOR[data.ext] ?? '#6b7280' }}
        >
          {data.ext.toUpperCase().slice(0, 3)}
        </div>
        <span className="text-sm font-medium text-white">{data.name}</span>
        <Pill color="blue">{data.rows.length.toLocaleString()} rows</Pill>
        <Pill color="slate">{data.headers.length} cols</Pill>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-white/6">
              {data.headers.map(h => (
                <th key={h} className="text-left px-3 py-2 font-medium text-slate-400 whitespace-nowrap">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.rows.slice(0, PREVIEW_ROWS).map((row, i) => (
              <tr key={i} className="border-b border-white/4 hover:bg-white/2">
                {row.map((cell, j) => (
                  <td key={j} className="px-3 py-2 text-slate-300 max-w-[160px] truncate whitespace-nowrap">
                    {cell || <span className="text-slate-600">—</span>}
                  </td>
                ))}
              </tr>
            ))}
            {data.rows.length > PREVIEW_ROWS && (
              <tr>
                <td colSpan={data.headers.length} className="px-3 py-2 text-center text-slate-500">
                  … {data.rows.length - PREVIEW_ROWS} more rows
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Semantic AI query ─────────────────────────────────────────────────────────

function SemanticQuery({ communityId }: { communityId: string }) {
  const WARDEN = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8001'
  const [query, setQuery]   = useState('')
  const [result, setResult] = useState<string>('')
  const [loading, setLoading] = useState(false)

  async function run() {
    if (!query.trim()) return
    setLoading(true); setResult('')
    try {
      const r = await fetch(`${WARDEN}/semantic-layer/ai-query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: query, community_id: communityId }),
      })
      const d = await r.json()
      setResult(d.sql ?? d.result ?? JSON.stringify(d, null, 2))
    } catch (e: unknown) {
      setResult(e instanceof Error ? e.message : 'Query failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="rounded-xl border border-white/8 bg-white/3 p-4">
      <div className="flex items-center gap-2 mb-3">
        <Zap className="w-4 h-4 text-violet-400" />
        <span className="text-sm font-medium text-white">Semantic AI Query</span>
        <Pill color="violet">Pro+</Pill>
      </div>
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && run()}
            placeholder="Ask a question about your data…"
            className="w-full pl-8 pr-3 py-2 bg-white/4 border border-white/8 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-violet-500/40 focus:ring-1 focus:ring-violet-500/20 transition"
          />
        </div>
        <button
          onClick={run}
          disabled={loading || !query.trim()}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium bg-violet-600/20 text-violet-400 border border-violet-500/30 hover:bg-violet-600/30 transition disabled:opacity-50"
        >
          {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <BarChart2 className="w-3.5 h-3.5" />}
          Run
        </button>
      </div>
      {result && (
        <pre className="mt-3 p-3 bg-black/30 rounded-lg text-xs text-slate-300 overflow-x-auto border border-white/6 max-h-48 whitespace-pre-wrap">{result}</pre>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function DataPage() {
  const params      = useParams()
  const communityId = Array.isArray(params.id) ? params.id[0] : (params.id ?? '')
  const tenantId    = getMyTenantId()
  const qc          = useQueryClient()

  const [parsed, setParsed]     = useState<ParsedData | null>(null)
  const [assetType, setAssetType] = useState<'dataset' | 'signals' | 'model'>('dataset')
  const [sellerAgent, setSellerAgent] = useState('')
  const [importing, setImporting] = useState(false)
  const [progress, setProgress]   = useState(0)

  const { data: assets = [], isLoading: assetsLoading } = useQuery({
    queryKey: ['hub-assets', communityId],
    queryFn:  () => agenticCommerceApi.listAssets({ community_id: communityId }),
    retry: false,
  })

  const { data: agents = [] } = useQuery({
    queryKey: ['hub-agents-data', communityId],
    queryFn:  () => agenticCommerceApi.listAgents({ community_id: communityId }),
    retry: false,
  })

  const handleFile = useCallback(async (file: File) => {
    const ext = file.name.split('.').pop()?.toLowerCase() ?? ''
    if (!['csv', 'json', 'sqlite', 'db'].includes(ext)) {
      toast.error('Unsupported file type. Use CSV, JSON, or SQLite.')
      return
    }
    try {
      if (ext === 'sqlite' || ext === 'db') {
        setParsed({ name: file.name, ext, headers: ['binary'], rows: [['SQLite binary — will be stored as-is']], raw: '' })
        return
      }
      const text = await file.text()
      const { headers, rows } = ext === 'csv' ? parseCSV(text) : parseJSON(text)
      setParsed({ name: file.name, ext, headers, rows, raw: text })
    } catch {
      toast.error('Failed to parse file')
    }
  }, [])

  async function importAsset() {
    if (!parsed) return
    const agent = sellerAgent || (agents as MktAgent[])[0]?.agent_id
    if (!agent) { toast.error('Register a marketplace agent first'); return }

    setImporting(true); setProgress(0)
    try {
      const chunkSize = 100
      const totalChunks = Math.ceil(parsed.rows.length / chunkSize)
      const chunks: Record<string, string>[][] = []

      for (let i = 0; i < parsed.rows.length; i += chunkSize) {
        const slice = parsed.rows.slice(i, i + chunkSize).map(row =>
          Object.fromEntries(parsed.headers.map((h, j) => [h, row[j] ?? '']))
        )
        chunks.push(slice)
      }

      let assetId = ''
      for (let ci = 0; ci < chunks.length; ci++) {
        const result = await agenticCommerceApi.registerAsset({
          tenant_id:       tenantId,
          seller_agent_id: agent,
          asset_type:      assetType,
          raw_data:        { records: chunks[ci], batch: ci, total_batches: totalChunks, source: parsed.name },
        })
        if (ci === 0) assetId = result.asset_id
        setProgress(Math.round(((ci + 1) / totalChunks) * 100))
      }

      toast.success(`Imported ${parsed.rows.length} rows as asset ${assetId.slice(0, 12)}…`)
      qc.invalidateQueries({ queryKey: ['hub-assets', communityId] })
      setParsed(null)
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Import failed')
    } finally {
      setImporting(false); setProgress(0)
    }
  }

  return (
    <div className="min-h-screen bg-[#09090f]">
      <div className="max-w-4xl mx-auto px-6 py-8">
        {/* Header */}
        <div className="flex items-center gap-3 mb-8">
          <Link
            href={`/community-hub/hub/${communityId}`}
            className="w-8 h-8 rounded-lg flex items-center justify-center bg-white/4 hover:bg-white/8 transition"
          >
            <ArrowLeft className="w-4 h-4 text-slate-400" />
          </Link>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              <Database className="w-5 h-5 text-blue-400" /> Data Upload &amp; Assets
            </h1>
            <p className="text-sm text-slate-400 mt-0.5">Import datasets and manage community data assets</p>
          </div>
        </div>

        <div className="space-y-6">
          {/* Drop zone */}
          <DropZone onFile={handleFile} />

          {/* Preview + import controls */}
          {parsed && (
            <div className="space-y-4">
              <DataPreview data={parsed} />

              <div className="rounded-xl border border-white/8 bg-white/3 p-4 space-y-4">
                <div className="text-sm font-medium text-white">Import Settings</div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs font-medium text-slate-400 block mb-1.5">Asset Type</label>
                    <select
                      value={assetType}
                      onChange={e => setAssetType(e.target.value as typeof assetType)}
                      className="w-full bg-white/4 border border-white/8 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50 transition"
                    >
                      <option value="dataset">Dataset</option>
                      <option value="signals">Signals</option>
                      <option value="model">Model</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-xs font-medium text-slate-400 block mb-1.5">Seller Agent</label>
                    <select
                      value={sellerAgent}
                      onChange={e => setSellerAgent(e.target.value)}
                      className="w-full bg-white/4 border border-white/8 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500/50 transition"
                    >
                      <option value="">Auto (first agent)</option>
                      {(agents as MktAgent[]).map(a => (
                        <option key={a.agent_id} value={a.agent_id}>
                          {a.agent_id.slice(0, 28)}…
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                {importing && (
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-xs text-slate-400">Importing…</span>
                      <span className="text-xs text-slate-400">{progress}%</span>
                    </div>
                    <div className="h-1.5 bg-white/8 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-blue-500 rounded-full transition-all"
                        style={{ width: `${progress}%` }}
                      />
                    </div>
                  </div>
                )}

                <div className="flex gap-3">
                  <button
                    onClick={importAsset}
                    disabled={importing}
                    className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-blue-600 hover:bg-blue-500 text-white transition disabled:opacity-50"
                  >
                    {importing
                      ? <><Loader2 className="w-4 h-4 animate-spin" /> Importing…</>
                      : <><Upload className="w-4 h-4" /> Import {parsed.rows.length.toLocaleString()} Rows</>
                    }
                  </button>
                  <button
                    onClick={() => setParsed(null)}
                    className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl text-sm font-medium bg-white/4 hover:bg-white/8 text-slate-400 transition"
                  >
                    <Trash2 className="w-3.5 h-3.5" /> Clear
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Semantic AI query */}
          <SemanticQuery communityId={communityId} />

          {/* Asset table */}
          <div className="rounded-xl border border-white/8 bg-white/3 overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-white/6">
              <Package className="w-4 h-4 text-slate-400" />
              <span className="text-sm font-medium text-white">Community Assets</span>
              <span className="ml-auto text-xs text-slate-500">
                {(assets as MktAsset[]).length} total
              </span>
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/6">
                  {['Asset ID', 'Type', 'Seller Agent', 'IPFS Hash', 'Created'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-medium text-slate-400">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {assetsLoading && Array.from({ length: 3 }).map((_, i) => (
                  <tr key={i} className="border-b border-white/4">
                    {Array.from({ length: 5 }).map((_, j) => (
                      <td key={j} className="px-4 py-3">
                        <div className="animate-pulse bg-white/5 rounded h-4" />
                      </td>
                    ))}
                  </tr>
                ))}
                {!assetsLoading && (assets as MktAsset[]).length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-4 py-10 text-center text-slate-500">
                      No assets yet. Upload a file to create one.
                    </td>
                  </tr>
                )}
                {(assets as MktAsset[]).map(a => (
                  <tr key={a.asset_id} className="border-b border-white/4 hover:bg-white/2 transition-colors">
                    <td className="px-4 py-3 font-mono text-xs text-slate-300">
                      {a.asset_id.slice(0, 20)}…
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium"
                        style={{
                          background: `${EXT_COLOR[a.asset_type] ?? '#6b7280'}18`,
                          color: EXT_COLOR[a.asset_type] ?? '#6b7280',
                        }}
                      >
                        <Tag className="w-2.5 h-2.5" />
                        {a.asset_type}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400">
                      {a.seller_agent_id?.slice(0, 18)}…
                    </td>
                    <td className="px-4 py-3">
                      {a.ipfs_hash ? (
                        <a
                          href={`https://ipfs.io/ipfs/${a.ipfs_hash}`}
                          target="_blank"
                          rel="noreferrer"
                          className="font-mono text-xs text-blue-400 hover:text-blue-300 transition"
                        >
                          {a.ipfs_hash.slice(0, 16)}…
                        </a>
                      ) : (
                        <span className="text-slate-600 text-xs">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">{fmtDate(a.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}
