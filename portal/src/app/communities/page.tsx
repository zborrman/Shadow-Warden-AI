'use client'
/**
 * portal/src/app/communities/page.tsx
 * ──────────────────────────────────────
 * Business Communities — encrypted vault management.
 *
 * Layout
 * ──────
 *   TopBar
 *   ┌──────────────────┬─────────────────────────────────────────┐
 *   │  Communities     │  [Members | Entities] tabs              │
 *   │  list + create   │  member list / entity list + upload     │
 *   └──────────────────┴─────────────────────────────────────────┘
 */

import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Users, FolderLock, Plus, Trash2, Upload,
  Download, RotateCcw, Shield, ChevronRight,
  FileText, AlertTriangle, CheckCircle2, Lock,
} from 'lucide-react'
import clsx from 'clsx'
import { TopBar } from '@/components/layout/TopBar'
import {
  listCommunities, createCommunity, listMembers, inviteMember,
  removeMember, updateMemberClearance, listEntities, uploadEntity,
  getEntityDetail, deleteEntity, initiateRotation,
  fmtBytes, fmtDate, CLEARANCE_COLORS,
  type Community, type Member, type EntityMeta,
} from '@/lib/communitiesApi'

// ── Helpers ───────────────────────────────────────────────────────────────────

function ClearanceBadge({ level }: { level: string }) {
  return (
    <span className={clsx('badge text-xs', CLEARANCE_COLORS[level] ?? 'bg-slate-500/15 text-slate-300')}>
      {level}
    </span>
  )
}

function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload  = () => resolve((reader.result as string).split(',')[1])
    reader.onerror = reject
    reader.readAsDataURL(file)
  })
}

// ── Members panel ─────────────────────────────────────────────────────────────

function MembersPanel({ community }: { community: Community }) {
  const qc = useQueryClient()
  const [showInvite, setShowInvite] = useState(false)
  const [form, setForm] = useState({ external_id: '', display_name: '', clearance: 'PUBLIC', role: 'MEMBER' })
  const [rotationMsg, setRotationMsg] = useState<string | null>(null)

  const { data: members = [], isLoading } = useQuery({
    queryKey: ['members', community.community_id],
    queryFn:  () => listMembers(community.community_id),
  })

  const invite = useMutation({
    mutationFn: () => inviteMember(community.community_id, form),
    onSuccess:  () => {
      qc.invalidateQueries({ queryKey: ['members', community.community_id] })
      setShowInvite(false)
      setForm({ external_id: '', display_name: '', clearance: 'PUBLIC', role: 'MEMBER' })
    },
  })

  const remove = useMutation({
    mutationFn: (memberId: string) => removeMember(community.community_id, memberId),
    onSuccess:  () => qc.invalidateQueries({ queryKey: ['members', community.community_id] }),
  })

  const changeClearance = useMutation({
    mutationFn: ({ memberId, clearance }: { memberId: string; clearance: string }) =>
      updateMemberClearance(community.community_id, memberId, clearance),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['members', community.community_id] })
      if (data.rotation_required) {
        setRotationMsg('Key rotation required — member was downgraded from a sensitive level.')
      }
    },
  })

  const rotate = useMutation({
    mutationFn: () => initiateRotation(community.community_id),
    onSuccess:  (data) => setRotationMsg(`Rotation initiated: ${data.old_kid} → ${data.new_kid}`),
  })

  return (
    <div className="space-y-4">
      {/* Rotation warning */}
      {rotationMsg && (
        <div className="flex items-start gap-3 p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-300 text-sm">
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
          <div className="flex-1">{rotationMsg}</div>
          <button onClick={() => rotate.mutate()} className="btn-secondary text-xs px-2 py-1">
            Rotate now
          </button>
          <button onClick={() => setRotationMsg(null)} className="text-slate-400 hover:text-white ml-1">✕</button>
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <span className="text-sm text-slate-400">{members.length} member{members.length !== 1 ? 's' : ''}</span>
        <button onClick={() => setShowInvite(v => !v)} className="btn-primary text-xs px-3 py-1.5">
          <Plus className="w-3.5 h-3.5" /> Invite
        </button>
      </div>

      {/* Invite form */}
      {showInvite && (
        <div className="card p-4 space-y-3">
          <p className="text-sm font-medium text-slate-200">Invite member</p>
          <input
            className="input"
            placeholder="External ID (email or user ID)"
            value={form.external_id}
            onChange={e => setForm(f => ({ ...f, external_id: e.target.value }))}
          />
          <input
            className="input"
            placeholder="Display name (optional)"
            value={form.display_name}
            onChange={e => setForm(f => ({ ...f, display_name: e.target.value }))}
          />
          <div className="flex gap-3">
            <select
              className="input flex-1"
              value={form.clearance}
              onChange={e => setForm(f => ({ ...f, clearance: e.target.value }))}
            >
              {['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'].map(c => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
            <select
              className="input flex-1"
              value={form.role}
              onChange={e => setForm(f => ({ ...f, role: e.target.value }))}
            >
              {['MEMBER', 'MODERATOR', 'ADMIN'].map(r => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
          </div>
          <div className="flex gap-2 justify-end">
            <button onClick={() => setShowInvite(false)} className="btn-secondary text-xs px-3 py-1.5">
              Cancel
            </button>
            <button
              onClick={() => invite.mutate()}
              disabled={!form.external_id || invite.isPending}
              className="btn-primary text-xs px-3 py-1.5"
            >
              {invite.isPending ? 'Inviting…' : 'Send invite'}
            </button>
          </div>
          {invite.isError && (
            <p className="text-xs text-red-400">{String((invite.error as Error)?.message)}</p>
          )}
        </div>
      )}

      {/* Member list */}
      {isLoading ? (
        <p className="text-sm text-slate-500 py-4 text-center">Loading…</p>
      ) : members.length === 0 ? (
        <p className="text-sm text-slate-500 py-8 text-center">No members yet. Invite someone.</p>
      ) : (
        <div className="space-y-1">
          {members.map((m: Member) => (
            <div key={m.member_id} className="flex items-center gap-3 px-3 py-2.5 rounded-xl hover:bg-white/[0.03] group">
              <div className="w-8 h-8 rounded-lg bg-dark-700 flex items-center justify-center text-xs font-bold text-brand-400 shrink-0">
                {(m.display_name || m.external_id)[0]?.toUpperCase()}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-slate-200 truncate">
                  {m.display_name || m.external_id}
                </p>
                <p className="text-xs text-slate-500 truncate">{m.external_id}</p>
              </div>
              <span className="text-xs text-slate-500 shrink-0">{m.role}</span>
              <select
                className="text-xs bg-transparent border border-white/10 rounded-lg px-2 py-1 text-slate-300 focus:outline-none focus:border-brand-400/40 shrink-0"
                value={m.clearance}
                onChange={e => changeClearance.mutate({ memberId: m.member_id, clearance: e.target.value })}
              >
                {['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'].map(c => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
              <button
                onClick={() => remove.mutate(m.member_id)}
                className="opacity-0 group-hover:opacity-100 text-slate-500 hover:text-red-400 transition-all p-1"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Entities panel ────────────────────────────────────────────────────────────

function EntitiesPanel({ community }: { community: Community }) {
  const qc = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadClearance, setUploadClearance] = useState('PUBLIC')
  const [uploadError, setUploadError] = useState<string | null>(null)

  const { data: entities = [], isLoading } = useQuery({
    queryKey: ['entities', community.community_id],
    queryFn:  () => listEntities(community.community_id),
  })

  const del = useMutation({
    mutationFn: (entityId: string) => deleteEntity(community.community_id, entityId),
    onSuccess:  () => qc.invalidateQueries({ queryKey: ['entities', community.community_id] }),
  })

  async function handleUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    setUploading(true)
    setUploadError(null)
    try {
      const b64 = await fileToBase64(file)
      await uploadEntity(community.community_id, {
        content_b64:  b64,
        clearance:    uploadClearance,
        content_type: file.type || 'application/octet-stream',
        sender_mid:   'portal-user',
      })
      await qc.invalidateQueries({ queryKey: ['entities', community.community_id] })
    } catch (err: unknown) {
      setUploadError(String((err as Error)?.message ?? 'Upload failed'))
    } finally {
      setUploading(false)
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  async function handleDownload(entity: EntityMeta) {
    try {
      const detail = await getEntityDetail(community.community_id, entity.entity_id)
      if (detail.download_url) {
        window.open(detail.download_url, '_blank')
      } else {
        alert('No download URL available (S3 not configured).')
      }
    } catch {
      alert('Download failed.')
    }
  }

  function fileIcon(contentType: string) {
    if (contentType.startsWith('image/'))       return '🖼'
    if (contentType.startsWith('video/'))       return '🎬'
    if (contentType === 'application/pdf')      return '📄'
    if (contentType.startsWith('text/'))        return '📝'
    if (contentType.includes('zip') || contentType.includes('tar')) return '📦'
    return '🔒'
  }

  return (
    <div className="space-y-4">
      {/* Upload bar */}
      <div className="flex items-center gap-3">
        <select
          className="input w-44 text-sm"
          value={uploadClearance}
          onChange={e => setUploadClearance(e.target.value)}
        >
          {['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'].map(c => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>
        <input ref={fileRef} type="file" className="hidden" onChange={handleUpload} />
        <button
          onClick={() => fileRef.current?.click()}
          disabled={uploading}
          className="btn-primary text-xs px-3 py-1.5"
        >
          <Upload className="w-3.5 h-3.5" />
          {uploading ? 'Encrypting…' : 'Upload file'}
        </button>
        <span className="text-xs text-slate-500">
          {entities.length} file{entities.length !== 1 ? 's' : ''}
        </span>
      </div>

      {uploadError && (
        <p className="text-xs text-red-400 flex items-center gap-1">
          <AlertTriangle className="w-3 h-3" /> {uploadError}
        </p>
      )}

      {/* Entity list */}
      {isLoading ? (
        <p className="text-sm text-slate-500 py-4 text-center">Loading…</p>
      ) : entities.length === 0 ? (
        <div className="py-12 text-center">
          <Lock className="w-8 h-8 text-slate-600 mx-auto mb-3" />
          <p className="text-sm text-slate-500">No encrypted files yet.</p>
          <p className="text-xs text-slate-600 mt-1">Upload a file to store it in the encrypted vault.</p>
        </div>
      ) : (
        <div className="space-y-1">
          {entities.map((e: EntityMeta) => (
            <div key={e.entity_id} className="flex items-center gap-3 px-3 py-2.5 rounded-xl hover:bg-white/[0.03] group">
              <span className="text-xl shrink-0">{fileIcon(e.content_type)}</span>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-slate-200 font-mono truncate">
                  {e.entity_id.slice(0, 8)}…
                </p>
                <p className="text-xs text-slate-500">
                  {fmtBytes(e.byte_size)} · {e.content_type} · {fmtDate(e.created_at)}
                </p>
              </div>
              <ClearanceBadge level={e.clearance} />
              <span className="text-xs text-slate-600 shrink-0 font-mono">{e.kid}</span>
              <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-all">
                <button
                  onClick={() => handleDownload(e)}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-brand-400 hover:bg-brand-400/10 transition-all"
                  title="Download"
                >
                  <Download className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => del.mutate(e.entity_id)}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-red-500/10 transition-all"
                  title="Delete (crypto-shred)"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

type Tab = 'members' | 'entities'

export default function CommunitiesPage() {
  const qc = useQueryClient()
  const [selected, setSelected]   = useState<Community | null>(null)
  const [tab, setTab]             = useState<Tab>('members')
  const [showCreate, setShowCreate] = useState(false)
  const [newName, setNewName]     = useState('')
  const [newDesc, setNewDesc]     = useState('')

  const { data: communities = [], isLoading } = useQuery({
    queryKey: ['communities'],
    queryFn:  listCommunities,
  })

  const create = useMutation({
    mutationFn: () => createCommunity(newName, newDesc),
    onSuccess:  (c) => {
      qc.invalidateQueries({ queryKey: ['communities'] })
      setSelected(c)
      setShowCreate(false)
      setNewName('')
      setNewDesc('')
    },
  })

  return (
    <div className="flex flex-col h-screen">
      <TopBar title="Communities" />

      <div className="flex flex-1 overflow-hidden">
        {/* ── Left: community list ─────────────────────────────────────── */}
        <aside className="w-72 border-r border-white/[0.06] flex flex-col overflow-hidden shrink-0">
          {/* Create button */}
          <div className="px-4 py-3 border-b border-white/[0.06]">
            <button onClick={() => setShowCreate(v => !v)} className="btn-primary w-full text-sm py-2">
              <Plus className="w-4 h-4" /> New community
            </button>
          </div>

          {/* Create form */}
          {showCreate && (
            <div className="px-4 py-3 border-b border-white/[0.06] space-y-2 bg-dark-700/50">
              <input
                className="input text-sm"
                placeholder="Community name"
                value={newName}
                onChange={e => setNewName(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && newName && create.mutate()}
                autoFocus
              />
              <input
                className="input text-sm"
                placeholder="Description (optional)"
                value={newDesc}
                onChange={e => setNewDesc(e.target.value)}
              />
              <div className="flex gap-2">
                <button onClick={() => setShowCreate(false)} className="btn-secondary flex-1 text-xs py-1.5">
                  Cancel
                </button>
                <button
                  onClick={() => create.mutate()}
                  disabled={!newName || create.isPending}
                  className="btn-primary flex-1 text-xs py-1.5"
                >
                  {create.isPending ? 'Creating…' : 'Create'}
                </button>
              </div>
              {create.isError && (
                <p className="text-xs text-red-400">{String((create.error as Error)?.message)}</p>
              )}
            </div>
          )}

          {/* List */}
          <div className="flex-1 overflow-y-auto py-2 px-2">
            {isLoading ? (
              <p className="text-sm text-slate-500 text-center py-8">Loading…</p>
            ) : communities.length === 0 ? (
              <div className="py-12 text-center px-4">
                <FolderLock className="w-8 h-8 text-slate-600 mx-auto mb-3" />
                <p className="text-sm text-slate-500">No communities yet.</p>
              </div>
            ) : (
              communities.map((c: Community) => (
                <button
                  key={c.community_id}
                  onClick={() => { setSelected(c); setTab('members') }}
                  className={clsx(
                    'w-full text-left flex items-center gap-3 px-3 py-2.5 rounded-xl mb-0.5 transition-all',
                    selected?.community_id === c.community_id
                      ? 'bg-brand-400/10 border border-brand-400/20 text-brand-400'
                      : 'text-slate-400 hover:bg-white/[0.04] hover:text-slate-200',
                  )}
                >
                  <div className={clsx(
                    'w-8 h-8 rounded-lg flex items-center justify-center text-sm font-bold shrink-0',
                    selected?.community_id === c.community_id
                      ? 'bg-brand-400/20 text-brand-400'
                      : 'bg-dark-700 text-slate-400',
                  )}>
                    {c.display_name[0]?.toUpperCase()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">{c.display_name}</p>
                    <p className="text-xs text-slate-500 truncate">{c.member_count ?? 0} members</p>
                  </div>
                  <ChevronRight className="w-3.5 h-3.5 shrink-0 opacity-40" />
                </button>
              ))
            )}
          </div>
        </aside>

        {/* ── Right: detail panel ───────────────────────────────────────── */}
        <div className="flex-1 overflow-y-auto">
          {!selected ? (
            <div className="flex flex-col items-center justify-center h-full text-center px-8">
              <Shield className="w-12 h-12 text-slate-600 mb-4" />
              <h2 className="text-lg font-semibold text-slate-300 mb-2">Select a community</h2>
              <p className="text-sm text-slate-500 max-w-xs">
                Choose a community from the left to manage members and encrypted entities.
              </p>
            </div>
          ) : (
            <div className="p-6 max-w-3xl">
              {/* Community header */}
              <div className="flex items-start gap-4 mb-6">
                <div className="w-12 h-12 rounded-2xl bg-brand-gradient flex items-center justify-center text-lg font-bold text-white shrink-0">
                  {selected.display_name[0]?.toUpperCase()}
                </div>
                <div className="flex-1 min-w-0">
                  <h2 className="text-xl font-bold text-white">{selected.display_name}</h2>
                  {selected.description && (
                    <p className="text-sm text-slate-400 mt-0.5">{selected.description}</p>
                  )}
                  <div className="flex items-center gap-3 mt-2">
                    <span className="text-xs text-slate-500 font-mono">kid: {selected.active_kid}</span>
                    <span className={clsx(
                      'text-xs px-2 py-0.5 rounded-full',
                      selected.status === 'ACTIVE'
                        ? 'bg-green-500/15 text-green-400'
                        : 'bg-slate-500/15 text-slate-400',
                    )}>
                      {selected.status}
                    </span>
                  </div>
                </div>
              </div>

              {/* Tabs */}
              <div className="flex gap-1 mb-5 border-b border-white/[0.06] pb-0">
                {([
                  { key: 'members',  label: 'Members',  icon: Users },
                  { key: 'entities', label: 'Vault',    icon: FolderLock },
                ] as { key: Tab; label: string; icon: React.ElementType }[]).map(({ key, label, icon: Icon }) => (
                  <button
                    key={key}
                    onClick={() => setTab(key)}
                    className={clsx(
                      'flex items-center gap-2 px-4 py-2.5 text-sm font-medium rounded-t-lg -mb-px transition-all',
                      tab === key
                        ? 'text-brand-400 border-b-2 border-brand-400 bg-brand-400/5'
                        : 'text-slate-400 hover:text-slate-200',
                    )}
                  >
                    <Icon className="w-4 h-4" />
                    {label}
                  </button>
                ))}
              </div>

              {/* Tab content */}
              {tab === 'members'  && <MembersPanel  community={selected} />}
              {tab === 'entities' && <EntitiesPanel community={selected} />}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
