'use client'
/**
 * /community-hub/[id] — Community detail page.
 * Tabs: Overview · Members · Data · Compliance · Evolution
 */

import { useState, useRef } from 'react'
import { useParams } from 'next/navigation'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Users, FileText, ShieldCheck, Zap, Info,
  Plus, Trash2, Upload, Download, CheckCircle2, XCircle,
  AlertTriangle, MinusCircle, ChevronLeft, Edit2, Check, X,
} from 'lucide-react'
import Link from 'next/link'
import clsx from 'clsx'
import { TopBar } from '@/components/layout/TopBar'
import toast from 'react-hot-toast'
import {
  getCommunity, patchCommunity,
  listMembers, addMember, removeMember,
  listFiles, uploadFile,
  getCompliance,
  getEvolutionStats, listEvolutionBundles,
  shareRule, approveRule, rejectRule, importRule,
  fmtBytes, fmtDate, fmtDateShort,
  type HubMember, type HubFile, type ComplianceControl, type EvolutionBundle,
} from '@/lib/communityHubApi'

// ── Shared tab type ───────────────────────────────────────────────────────────

type Tab = 'overview' | 'members' | 'data' | 'compliance' | 'evolution'

const TABS: { id: Tab; label: string; icon: React.ElementType }[] = [
  { id: 'overview',   label: 'Overview',   icon: Info         },
  { id: 'members',    label: 'Members',    icon: Users        },
  { id: 'data',       label: 'Data',       icon: FileText     },
  { id: 'compliance', label: 'Compliance', icon: ShieldCheck  },
  { id: 'evolution',  label: 'Evolution',  icon: Zap          },
]

// ── Flash helper ─────────────────────────────────────────────────────────────

function useFlash() {
  const [msg, setMsg] = useState('')
  const [isErr, setIsErr] = useState(false)
  let t: ReturnType<typeof setTimeout>
  const flash = (text: string, err = false) => {
    clearTimeout(t)
    setMsg(text); setIsErr(err)
    t = setTimeout(() => setMsg(''), 3500)
  }
  return { msg, isErr, flash }
}

// ── Compliance control icon ───────────────────────────────────────────────────

function CtrlIcon({ status }: { status: ComplianceControl['status'] }) {
  if (status === 'PASS') return <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
  if (status === 'FAIL') return <XCircle      className="w-4 h-4 text-red-400     shrink-0" />
  if (status === 'WARN') return <AlertTriangle className="w-4 h-4 text-amber-400  shrink-0" />
  return <MinusCircle className="w-4 h-4 text-dark-500 shrink-0" />
}

// ── Overview tab ─────────────────────────────────────────────────────────────

function OverviewTab({ communityId }: { communityId: string }) {
  const qc = useQueryClient()
  const { flash, msg, isErr } = useFlash()
  const [editing, setEditing] = useState(false)
  const [draftName, setDraftName] = useState('')
  const [draftDesc, setDraftDesc] = useState('')

  const { data: c, isLoading } = useQuery({
    queryKey: ['hub-community', communityId],
    queryFn:  () => getCommunity(communityId),
  })

  const patch = useMutation({
    mutationFn: (p: { name?: string; description?: string }) => patchCommunity(communityId, p),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['hub-community', communityId] })
      setEditing(false)
      toast.success('Description updated.')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  function startEdit() {
    if (!c) return
    setDraftName(c.name)
    setDraftDesc(c.description)
    setEditing(true)
  }

  function saveEdit() {
    if (!c) return
    const p: { name?: string; description?: string } = {}
    if (draftName !== c.name) p.name = draftName
    if (draftDesc !== c.description) p.description = draftDesc
    if (Object.keys(p).length === 0) { setEditing(false); return }
    patch.mutate(p)
  }

  if (isLoading) return <div className="text-dark-400 text-sm py-8 text-center">Loading…</div>
  if (!c) return <div className="text-red-400 text-sm py-8">Community not found.</div>

  return (
    <div className="space-y-5">
      {msg && (
        <div className={clsx('px-4 py-2 rounded-lg text-sm',
          isErr ? 'bg-red-500/15 text-red-400' : 'bg-emerald-500/15 text-emerald-400')}>
          {msg}
        </div>
      )}

      {/* Name / Description card */}
      <div className="card space-y-3">
        <div className="flex items-start justify-between">
          {editing ? (
            <input className="input text-lg font-semibold flex-1 mr-3"
              value={draftName} onChange={e => setDraftName(e.target.value)} />
          ) : (
            <h2 className="text-xl font-semibold">{c.name}</h2>
          )}
          <div className="flex gap-2 shrink-0">
            {editing ? (
              <>
                <button className="btn-primary py-1 px-3 text-sm flex items-center gap-1"
                  onClick={saveEdit} disabled={patch.isPending}>
                  <Check className="w-3.5 h-3.5" /> Save
                </button>
                <button className="btn-secondary py-1 px-3 text-sm flex items-center gap-1"
                  onClick={() => setEditing(false)}>
                  <X className="w-3.5 h-3.5" /> Cancel
                </button>
              </>
            ) : (
              <button className="btn-secondary py-1 px-3 text-sm flex items-center gap-1"
                onClick={startEdit}>
                <Edit2 className="w-3.5 h-3.5" /> Edit
              </button>
            )}
          </div>
        </div>

        {editing ? (
          <textarea className="input w-full min-h-[90px] resize-none text-sm"
            placeholder="Describe this community…"
            value={draftDesc} onChange={e => setDraftDesc(e.target.value)} />
        ) : (
          <p className="text-sm text-dark-400">{c.description || 'No description.'}</p>
        )}
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Members',    value: c.member_count ?? 0                      },
          { label: 'Files',      value: c.data_stats?.total_files ?? 0           },
          { label: 'Storage',    value: `${(c.data_stats?.total_mb ?? 0).toFixed(1)} MB` },
          { label: 'Created',    value: fmtDate(c.created_at)                    },
        ].map(s => (
          <div key={s.label} className="card text-center">
            <p className="font-semibold text-brand-400">{s.value}</p>
            <p className="text-xs text-dark-400 mt-1">{s.label}</p>
          </div>
        ))}
      </div>

      {/* Meta */}
      <div className="card space-y-2 text-sm">
        <Row label="Community ID"  value={<code className="font-mono text-xs">{c.community_id}</code>} />
        <Row label="Visibility"    value={c.visibility} />
        <Row label="Join Policy"   value={c.join_policy} />
        <Row label="Status"        value={c.status} />
        <Row label="Creator"       value={c.creator_tenant_id} />
      </div>
    </div>
  )
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4">
      <span className="text-dark-400">{label}</span>
      <span className="text-right">{value}</span>
    </div>
  )
}

// ── Members tab ───────────────────────────────────────────────────────────────

function MembersTab({ communityId }: { communityId: string }) {
  const qc = useQueryClient()
  const { flash, msg, isErr } = useFlash()
  const [rmConfirm, setRmConfirm] = useState<string | null>(null)
  const [newTid,   setNewTid]   = useState('')
  const [newRole,  setNewRole]  = useState('member')
  const [newDn,    setNewDn]    = useState('')
  const [addBusy,  setAddBusy]  = useState(false)

  const { data: members = [], isLoading } = useQuery({
    queryKey: ['hub-members', communityId],
    queryFn:  () => listMembers(communityId),
  })

  const removeMut = useMutation({
    mutationFn: (mid: string) => removeMember(communityId, mid),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['hub-members', communityId] })
      setRmConfirm(null)
      toast.success('Member removed.')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  async function handleAdd(e: React.FormEvent) {
    e.preventDefault()
    if (!newTid.trim()) return
    setAddBusy(true)
    try {
      await addMember(communityId, newTid.trim(), newRole, newDn.trim())
      qc.invalidateQueries({ queryKey: ['hub-members', communityId] })
      setNewTid(''); setNewDn('')
      toast.success('Member invited.')
    } catch (e: unknown) {
      toast.error((e as Error).message)
    } finally {
      setAddBusy(false)
    }
  }

  const roleBadge = (role: string) => {
    const cls = role === 'owner'  ? 'bg-violet-500/15 text-violet-400'
              : role === 'admin'  ? 'bg-sky-500/15 text-sky-400'
              : role === 'member' ? 'bg-emerald-500/15 text-emerald-400'
              : 'bg-slate-500/15 text-slate-400'
    return <span className={clsx('badge text-xs', cls)}>{role}</span>
  }

  const sortedMembers = [...members].sort((a, b) => b.joined_at.localeCompare(a.joined_at))

  return (
    <div className="space-y-5">
      {/* Add member form */}
      <div className="card">
        <p className="text-sm font-medium mb-3">Add Member</p>
        <form onSubmit={handleAdd} className="flex flex-wrap gap-2">
          <input className="input flex-1 min-w-[180px]" placeholder="Tenant ID"
            value={newTid} onChange={e => setNewTid(e.target.value)} />
          <input className="input flex-1 min-w-[140px]" placeholder="Display name (opt.)"
            value={newDn}  onChange={e => setNewDn(e.target.value)} />
          <select className="input w-32" value={newRole} onChange={e => setNewRole(e.target.value)}>
            <option value="member">member</option>
            <option value="admin">admin</option>
            <option value="observer">observer</option>
          </select>
          <button className="btn-primary flex items-center gap-1.5" type="submit" disabled={addBusy}>
            <Plus className="w-4 h-4" /> {addBusy ? 'Adding…' : 'Add'}
          </button>
        </form>
      </div>

      {/* Members list */}
      <div className="card p-0 overflow-hidden">
        <div className="px-4 py-3 border-b border-dark-700 text-sm font-medium">
          {isLoading ? '…' : `${members.length} member(s)`}
        </div>
        {isLoading ? (
          <div className="p-6 text-center text-dark-400 text-sm">Loading…</div>
        ) : members.length === 0 ? (
          <div className="p-6 text-center text-dark-400 text-sm">No members yet.</div>
        ) : (
          <div className="divide-y divide-dark-700">
            {sortedMembers.map((m: HubMember) => (
              <div key={m.member_id} className="px-4 py-3 flex items-center gap-3 group">
                {/* Avatar */}
                <div className="w-8 h-8 rounded-full bg-brand-400/20 flex items-center justify-center
                                text-xs font-bold text-brand-400 shrink-0">
                  {(m.display_name || m.tenant_id).slice(0, 2).toUpperCase()}
                </div>
                {/* Info */}
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">
                    {m.display_name || m.tenant_id}
                  </p>
                  <p className="text-xs text-dark-400 truncate font-mono">{m.tenant_id}</p>
                </div>
                {roleBadge(m.role)}
                <span className="text-xs text-dark-500 hidden sm:block font-mono">{fmtDateShort(m.joined_at)}</span>

                {/* Delete */}
                {rmConfirm === m.member_id ? (
                  <div className="flex gap-1.5 shrink-0">
                    <button className="btn-danger py-1 px-2 text-xs"
                      onClick={() => removeMut.mutate(m.member_id)}
                      disabled={removeMut.isPending}>
                      Confirm
                    </button>
                    <button className="btn-secondary py-1 px-2 text-xs"
                      onClick={() => setRmConfirm(null)}>
                      Cancel
                    </button>
                  </div>
                ) : (
                  <button
                    className="opacity-0 group-hover:opacity-100 transition-opacity text-red-400
                               hover:text-red-300 p-1 shrink-0"
                    onClick={() => setRmConfirm(m.member_id)}
                    title="Remove member">
                    <Trash2 className="w-4 h-4" />
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Data tab ──────────────────────────────────────────────────────────────────

function DataTab({ communityId }: { communityId: string }) {
  const qc      = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const { flash, msg, isErr } = useFlash()
  const [ctx,    setCtx]    = useState('')
  const [upBusy, setUpBusy] = useState(false)

  const { data: files = [], isLoading } = useQuery({
    queryKey: ['hub-files', communityId],
    queryFn:  () => listFiles(communityId),
  })

  async function handleUpload() {
    const file = fileRef.current?.files?.[0]
    if (!file) { flash('Select a file first.', true); return }
    setUpBusy(true)
    try {
      await uploadFile(communityId, file, ctx)
      qc.invalidateQueries({ queryKey: ['hub-files', communityId] })
      if (fileRef.current) fileRef.current.value = ''
      setCtx('')
      toast.success(`Uploaded: ${file.name}`)
    } catch (e: unknown) {
      toast.error((e as Error).message)
    } finally {
      setUpBusy(false)
    }
  }

  const totalMb = files.reduce((s, f) => s + f.size_bytes, 0) / (1024 ** 2)

  return (
    <div className="space-y-5">
      {/* Stats */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'Files',     value: files.length          },
          { label: 'Storage',   value: `${totalMb.toFixed(1)} MB`  },
          { label: 'Downloads', value: files.reduce((s, f) => s + f.download_count, 0) },
        ].map(s => (
          <div key={s.label} className="card text-center">
            <p className="font-semibold text-brand-400">{s.value}</p>
            <p className="text-xs text-dark-400 mt-1">{s.label}</p>
          </div>
        ))}
      </div>

      {/* Upload area */}
      <div className="card space-y-3">
        <p className="text-sm font-medium">Upload File</p>
        <div className="flex flex-wrap gap-2 items-center">
          <input ref={fileRef} type="file" className="hidden" id="hub-file-input" />
          <label htmlFor="hub-file-input"
            className="btn-secondary flex items-center gap-2 cursor-pointer">
            <Upload className="w-4 h-4" /> Choose file
          </label>
          <input className="input flex-1 min-w-[200px]" placeholder="Context / notes (optional)"
            value={ctx} onChange={e => setCtx(e.target.value)} />
          <button className="btn-primary flex items-center gap-2"
            onClick={handleUpload} disabled={upBusy}>
            {upBusy ? 'Uploading…' : 'Upload →'}
          </button>
        </div>
      </div>

      {/* File list */}
      <div className="card p-0 overflow-hidden">
        <div className="px-4 py-3 border-b border-dark-700 text-sm font-medium">
          {isLoading ? '…' : `${files.length} file(s)`}
        </div>
        {isLoading ? (
          <div className="p-6 text-center text-dark-400 text-sm">Loading…</div>
        ) : files.length === 0 ? (
          <div className="p-6 text-center text-dark-400 text-sm">No files yet.</div>
        ) : (
          <div className="divide-y divide-dark-700">
            {files.map((f: HubFile) => (
              <div key={f.file_id} className="px-4 py-3 flex items-start gap-3">
                <Download className="w-4 h-4 text-dark-500 mt-0.5 shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{f.filename}</p>
                  {f.context && (
                    <p className="text-xs text-dark-400 mt-0.5 italic">{f.context}</p>
                  )}
                  <p className="text-xs text-dark-500 mt-1">
                    {fmtBytes(f.size_bytes)} · {f.content_type} · {fmtDate(f.uploaded_at)}
                    {' · '}{f.download_count} dl
                  </p>
                  <p className="text-xs font-mono text-dark-600 mt-0.5">{f.ueciid}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Compliance tab ────────────────────────────────────────────────────────────

function ComplianceTab({ communityId }: { communityId: string }) {
  const { data: comp, isLoading } = useQuery({
    queryKey: ['hub-compliance', communityId],
    queryFn:  () => getCompliance(communityId),
  })

  if (isLoading) return <div className="text-dark-400 text-sm py-8 text-center">Loading…</div>
  if (!comp) return <div className="text-red-400 text-sm py-4">Failed to load compliance data.</div>

  const statusCls = comp.status === 'COMPLIANT'
    ? 'text-emerald-400 bg-emerald-500/15'
    : comp.status === 'PARTIAL'
    ? 'text-amber-400 bg-amber-500/15'
    : 'text-red-400 bg-red-500/15'

  return (
    <div className="space-y-5">
      {/* Score */}
      <div className="card flex items-center gap-6">
        <div className="relative w-20 h-20 shrink-0">
          <svg viewBox="0 0 36 36" className="w-20 h-20 -rotate-90">
            <circle cx="18" cy="18" r="15.9" fill="none"
              stroke="currentColor" strokeWidth="2.5" className="text-dark-700" />
            <circle cx="18" cy="18" r="15.9" fill="none"
              stroke="currentColor" strokeWidth="2.5"
              className={comp.status === 'COMPLIANT' ? 'text-emerald-400'
                       : comp.status === 'PARTIAL'   ? 'text-amber-400'
                       : 'text-red-400'}
              strokeDasharray={`${comp.score * 100} 100`}
              strokeLinecap="round" />
          </svg>
          <span className="absolute inset-0 flex items-center justify-center text-sm font-bold">
            {Math.round(comp.score * 100)}%
          </span>
        </div>
        <div>
          <p className="text-lg font-semibold">Compliance Score</p>
          <span className={clsx('badge mt-1', statusCls)}>{comp.status}</span>
          <p className="text-xs text-dark-400 mt-2">{fmtDate(comp.generated_at)}</p>
        </div>
      </div>

      {/* Controls */}
      <div className="card p-0 overflow-hidden">
        <div className="px-4 py-3 border-b border-dark-700 text-sm font-medium">Controls</div>
        <div className="divide-y divide-dark-700">
          {comp.controls.map((ctrl, i) => (
            <div key={i} className="px-4 py-3 flex items-start gap-3">
              <CtrlIcon status={ctrl.status} />
              <div>
                <p className="text-sm font-medium">{ctrl.control}</p>
                <p className="text-xs text-dark-400 mt-0.5">{ctrl.detail}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Gaps */}
      {comp.gaps.length > 0 && (
        <div className="card space-y-2">
          <p className="text-sm font-medium text-amber-400">Gaps to Address</p>
          {comp.gaps.map((g, i) => (
            <div key={i} className="bg-amber-500/8 border border-amber-500/20 rounded-lg px-3 py-2 text-sm">
              <span className="font-medium">{g.control}:</span>{' '}
              <span className="text-dark-400">{g.detail}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Evolution tab ─────────────────────────────────────────────────────────────

function EvolutionTab({ communityId }: { communityId: string }) {
  const qc = useQueryClient()
  const { flash, msg, isErr } = useFlash()
  const [ruleType, setRuleType] = useState('jailbreak_signature')
  const [content,  setContent]  = useState('')
  const [shareBusy, setShareBusy] = useState(false)

  const { data: stats } = useQuery({
    queryKey: ['hub-evo-stats', communityId],
    queryFn:  () => getEvolutionStats(communityId),
  })
  const { data: pending = [] } = useQuery({
    queryKey: ['hub-evo-pending', communityId],
    queryFn:  () => listEvolutionBundles(communityId, 'pending_review'),
  })
  const { data: approved = [] } = useQuery({
    queryKey: ['hub-evo-approved', communityId],
    queryFn:  () => listEvolutionBundles(communityId, 'approved'),
  })

  const invalidateAll = () => {
    qc.invalidateQueries({ queryKey: ['hub-evo-stats', communityId] })
    qc.invalidateQueries({ queryKey: ['hub-evo-pending', communityId] })
    qc.invalidateQueries({ queryKey: ['hub-evo-approved', communityId] })
  }

  async function handleShare(e: React.FormEvent) {
    e.preventDefault()
    if (!content.trim()) return
    setShareBusy(true)
    try {
      await shareRule(communityId, ruleType, content.trim())
      setContent('')
      invalidateAll()
      flash('Rule shared — pending review.')
    } catch (ex: unknown) { flash((ex as Error).message, true) }
    finally { setShareBusy(false) }
  }

  const handleApprove = async (bid: string) => {
    try { await approveRule(communityId, bid); invalidateAll(); flash('Approved.') }
    catch (ex: unknown) { flash((ex as Error).message, true) }
  }
  const handleReject = async (bid: string) => {
    try { await rejectRule(communityId, bid); invalidateAll(); flash('Rejected.') }
    catch (ex: unknown) { flash((ex as Error).message, true) }
  }
  const handleImport = async (bid: string) => {
    try { await importRule(communityId, bid); invalidateAll(); flash('Imported into evolution engine.') }
    catch (ex: unknown) { flash((ex as Error).message, true) }
  }

  const statusBadge = (b: EvolutionBundle) => {
    const cls = b.status === 'approved'        ? 'bg-emerald-500/15 text-emerald-400'
              : b.status === 'pending_review'   ? 'bg-amber-500/15 text-amber-400'
              : b.status === 'rejected'         ? 'bg-red-500/15 text-red-400'
              : 'bg-dark-600 text-dark-300'
    return <span className={clsx('badge text-xs', cls)}>{b.status.replace('_', ' ')}</span>
  }

  return (
    <div className="space-y-5">
      {msg && (
        <div className={clsx('px-4 py-2 rounded-lg text-sm',
          isErr ? 'bg-red-500/15 text-red-400' : 'bg-emerald-500/15 text-emerald-400')}>
          {msg}
        </div>
      )}

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Total',   value: stats.total         },
            { label: 'Approved', value: stats.approved     },
            { label: 'Pending',  value: stats.pending      },
            { label: 'Imports',  value: stats.total_imports },
          ].map(s => (
            <div key={s.label} className="card text-center">
              <p className="font-semibold text-brand-400">{s.value}</p>
              <p className="text-xs text-dark-400 mt-1">{s.label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Share rule */}
      <div className="card space-y-3">
        <p className="text-sm font-medium">Share a Rule</p>
        <form onSubmit={handleShare} className="space-y-3">
          <div className="flex gap-2">
            <select className="input w-48 shrink-0" value={ruleType}
              onChange={e => setRuleType(e.target.value)}>
              <option value="jailbreak_signature">Jailbreak Signature</option>
              <option value="embedding_example">Embedding Example</option>
              <option value="regex_pattern">Regex Pattern</option>
              <option value="compound_rule">Compound Rule</option>
            </select>
            <textarea className="input flex-1 min-h-[80px] resize-none text-sm"
              placeholder="Rule content (anonymised)"
              value={content} onChange={e => setContent(e.target.value)} />
          </div>
          <button className="btn-primary" type="submit" disabled={shareBusy}>
            {shareBusy ? 'Sharing…' : 'Share →'}
          </button>
        </form>
      </div>

      {/* Pending approval */}
      {pending.length > 0 && (
        <div className="card space-y-3">
          <p className="text-sm font-medium text-amber-400">Pending Approval ({pending.length})</p>
          {pending.map((b: EvolutionBundle) => (
            <div key={b.bundle_id}
              className="bg-dark-800 rounded-lg p-3 space-y-2">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="badge text-xs bg-dark-600 text-dark-300">{b.rule_type}</span>
                {statusBadge(b)}
                <span className="text-xs text-dark-500 ml-auto">{fmtDate(b.published_at)}</span>
              </div>
              <pre className="text-xs font-mono text-dark-300 truncate whitespace-pre-wrap">
                {b.rule_content.slice(0, 120)}{b.rule_content.length > 120 ? '…' : ''}
              </pre>
              <div className="flex gap-2">
                <button className="btn-primary py-1 px-3 text-xs"
                  onClick={() => handleApprove(b.bundle_id)}>Approve</button>
                <button className="btn-danger py-1 px-3 text-xs"
                  onClick={() => handleReject(b.bundle_id)}>Reject</button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Approved — ready to import */}
      {approved.length > 0 && (
        <div className="card space-y-3">
          <p className="text-sm font-medium text-emerald-400">Approved ({approved.length})</p>
          {approved.map((b: EvolutionBundle) => (
            <div key={b.bundle_id}
              className="bg-dark-800 rounded-lg p-3 space-y-2">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="badge text-xs bg-dark-600 text-dark-300">{b.rule_type}</span>
                <span className="text-xs text-dark-500">
                  {b.import_count} import{b.import_count !== 1 ? 's' : ''}
                </span>
                <button className="btn-primary py-1 px-3 text-xs ml-auto"
                  onClick={() => handleImport(b.bundle_id)}>
                  Import
                </button>
              </div>
              <pre className="text-xs font-mono text-dark-300 truncate">
                {b.rule_content.slice(0, 100)}{b.rule_content.length > 100 ? '…' : ''}
              </pre>
            </div>
          ))}
        </div>
      )}

      {pending.length === 0 && approved.length === 0 && (
        <div className="card text-center py-8 text-dark-400 text-sm">
          No rules yet. Share the first one above.
        </div>
      )}
    </div>
  )
}

// ── Main ──────────────────────────────────────────────────────────────────────

export default function CommunityDetailPage() {
  const params      = useParams<{ id: string }>()
  const communityId = params.id
  const [tab, setTab] = useState<Tab>('overview')

  const { data: c } = useQuery({
    queryKey: ['hub-community', communityId],
    queryFn:  () => getCommunity(communityId),
  })

  return (
    <>
      <TopBar title={c?.name || 'Community'} />

      <div className="p-6 max-w-4xl mx-auto space-y-5">
        {/* Back link */}
        <Link href="/community-hub/"
          className="flex items-center gap-1.5 text-sm text-dark-400 hover:text-brand-400 transition-colors w-fit">
          <ChevronLeft className="w-4 h-4" /> All Communities
        </Link>

        {/* Tab bar */}
        <div className="flex gap-1 bg-dark-800 rounded-lg p-1 overflow-x-auto">
          {TABS.map(t => {
            const Icon = t.icon
            return (
              <button key={t.id}
                onClick={() => setTab(t.id)}
                className={clsx(
                  'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium whitespace-nowrap transition-colors',
                  tab === t.id
                    ? 'bg-brand-400 text-dark-900'
                    : 'text-dark-400 hover:text-dark-100',
                )}>
                <Icon className="w-3.5 h-3.5" />
                {t.label}
              </button>
            )
          })}
        </div>

        {/* Tab content */}
        {tab === 'overview'   && <OverviewTab   communityId={communityId} />}
        {tab === 'members'    && <MembersTab    communityId={communityId} />}
        {tab === 'data'       && <DataTab       communityId={communityId} />}
        {tab === 'compliance' && <ComplianceTab communityId={communityId} />}
        {tab === 'evolution'  && <EvolutionTab  communityId={communityId} />}
      </div>
    </>
  )
}
