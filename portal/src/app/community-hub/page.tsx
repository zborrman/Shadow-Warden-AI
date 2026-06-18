'use client'
/**
 * /community-hub — Community Hub list page.
 * Shows owned communities, create form, delete confirmation.
 */

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useRouter } from 'next/navigation'
import { Plus, Trash2, Users, Globe, Lock, ChevronRight, FolderOpen } from 'lucide-react'
import clsx from 'clsx'
import { TopBar } from '@/components/layout/TopBar'
import toast from 'react-hot-toast'
import {
  listMyCommunities,
  deleteCommunity,
  getCommunityStats,
  fmtDateShort,
  type HubCommunity,
} from '@/lib/communityHubApi'

// ── Status/visibility badges ─────────────────────────────────────────────────

function VisBadge({ vis }: { vis: string }) {
  return (
    <span className={clsx('badge text-xs', vis === 'public'
      ? 'bg-emerald-500/15 text-emerald-400'
      : 'bg-slate-500/15 text-slate-400')}>
      {vis === 'public' ? <Globe className="inline w-3 h-3 mr-1" /> : <Lock className="inline w-3 h-3 mr-1" />}
      {vis}
    </span>
  )
}

// ── Main page ────────────────────────────────────────────────────────────────

export default function CommunityHubPage() {
  const qc     = useQueryClient()
  const router = useRouter()
  const [deleteId, setDeleteId] = useState<string | null>(null)

  const { data: communities = [], isLoading } = useQuery({
    queryKey: ['hub-communities'],
    queryFn:  () => listMyCommunities(),
  })

  const { data: stats } = useQuery({
    queryKey: ['hub-stats'],
    queryFn:  getCommunityStats,
  })

  const deleteMut = useMutation({
    mutationFn: deleteCommunity,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['hub-communities'] })
      setDeleteId(null)
      toast.success('Community deleted.')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  return (
    <>
      <TopBar title="Community Hub" />

      <div className="p-6 max-w-6xl mx-auto">
        {/* Stats row */}
        {stats && (
          <div className="grid grid-cols-4 gap-4 mb-6">
            {[
              { label: 'Total',     value: stats.total     },
              { label: 'Active',    value: stats.active    },
              { label: 'Public',    value: stats.public    },
              { label: 'Suspended', value: stats.suspended },
            ].map(s => (
              <div key={s.label} className="card text-center">
                <p className="text-2xl font-bold text-brand-400">{s.value}</p>
                <p className="text-xs text-dark-400 mt-1">{s.label}</p>
              </div>
            ))}
          </div>
        )}

        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold">My Communities</h2>
          <button className="btn-primary flex items-center gap-2"
            onClick={() => router.push('/community-hub/create')}>
            <Plus className="w-4 h-4" /> New Community
          </button>
        </div>



        {/* Community grid */}
        {isLoading ? (
          <div className="text-dark-400 text-sm text-center py-12">Loading communities…</div>
        ) : communities.length === 0 ? (
          <div className="card text-center py-14">
            <FolderOpen className="w-12 h-12 mx-auto text-dark-500 mb-3" />
            <p className="text-dark-400">No communities yet.</p>
            <button className="btn-primary mt-4" onClick={() => router.push('/community-hub/create')}>
              Create your first community
            </button>
          </div>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {[...communities]
              .sort((a, b) => b.created_at.localeCompare(a.created_at))
              .map((c: HubCommunity) => (
              <div key={c.community_id}
                className="card group relative flex flex-col gap-3 cursor-pointer hover:border-brand-400/40 transition-colors"
                onClick={() => router.push(`/community-hub/hub/${c.community_id}`)}>

                {/* Top row */}
                <div className="flex items-start justify-between">
                  <div className="flex-1 min-w-0 pr-2">
                    <p className="font-semibold truncate">{c.name}</p>
                    <p className="text-xs text-dark-400 mt-0.5 font-mono">{c.community_id.slice(0, 12)}…</p>
                  </div>
                  <VisBadge vis={c.visibility} />
                </div>

                {/* Description */}
                {c.description && (
                  <p className="text-sm text-dark-400 line-clamp-2">{c.description}</p>
                )}

                {/* Meta */}
                <div className="flex items-center gap-3 text-xs text-dark-500 mt-auto">
                  <span className="flex items-center gap-1">
                    <Users className="w-3 h-3" />
                    {c.member_count ?? 0} members
                  </span>
                  <span>{c.join_policy}</span>
                  <span className="ml-auto">{fmtDateShort(c.created_at)}</span>
                </div>

                {/* Actions */}
                <div className="flex items-center justify-between pt-1 border-t border-dark-700">
                  <button
                    className="text-xs text-red-400 hover:text-red-300 flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity"
                    onClick={e => { e.stopPropagation(); setDeleteId(c.community_id) }}>
                    <Trash2 className="w-3 h-3" /> Delete
                  </button>
                  <span className="text-xs text-brand-400 flex items-center gap-1 ml-auto">
                    Open <ChevronRight className="w-3 h-3" />
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Delete confirmation */}
      {deleteId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="card w-full max-w-sm mx-4">
            <h2 className="text-lg font-semibold mb-2">Delete Community?</h2>
            <p className="text-sm text-dark-400 mb-5">
              This action cannot be undone. Only the owner can delete a community.
            </p>
            <div className="flex gap-2 justify-end">
              <button className="btn-secondary" onClick={() => setDeleteId(null)}>Cancel</button>
              <button className="btn-danger"
                disabled={deleteMut.isPending}
                onClick={() => deleteMut.mutate(deleteId)}>
                {deleteMut.isPending ? 'Deleting…' : 'Yes, delete'}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
