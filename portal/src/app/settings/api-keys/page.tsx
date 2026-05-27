'use client'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Key, Plus, Trash2, Copy, Check, AlertCircle, CheckCircle2, Eye, EyeOff } from 'lucide-react'
import { settingsApi, type ApiKeyOut, type ApiKeyCreated } from '@/lib/settingsApi'
import { TopBar } from '@/components/layout/TopBar'

function Toast({ msg, ok }: { msg: string; ok: boolean }) {
  return (
    <div className={`fixed bottom-6 right-6 flex items-center gap-2 px-4 py-3 rounded-xl border text-sm font-medium shadow-xl z-50 ${
      ok ? 'bg-green-500/10 border-green-500/20 text-green-400' : 'bg-red-500/10 border-red-500/20 text-red-400'
    }`}>
      {ok ? <CheckCircle2 className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
      {msg}
    </div>
  )
}

function CreatedKeyBanner({ created, onDismiss }: { created: ApiKeyCreated; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false)
  const [revealed, setRevealed] = useState(false)

  function copy() {
    navigator.clipboard.writeText(created.key)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="p-4 rounded-2xl border mb-6" style={{ background: 'rgba(48,209,88,0.06)', borderColor: 'rgba(48,209,88,0.25)' }}>
      <div className="flex items-center gap-2 mb-2">
        <CheckCircle2 className="w-4 h-4 text-green-400" />
        <p className="text-sm font-semibold text-green-400">API key created — copy it now, it won't be shown again</p>
      </div>
      <div className="flex items-center gap-2 mt-3">
        <code className="flex-1 text-xs font-mono p-2.5 rounded-lg bg-black/40 border border-white/10 text-slate-300 overflow-x-auto">
          {revealed ? created.key : created.key.slice(0, 10) + '•'.repeat(32)}
        </code>
        <button onClick={() => setRevealed(r => !r)} className="p-2 rounded-lg border border-white/10 text-slate-400 hover:text-white">
          {revealed ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
        </button>
        <button onClick={copy} className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-white/10 text-slate-400 hover:text-white text-xs font-medium">
          {copied ? <><Check className="w-3.5 h-3.5 text-green-400" /> Copied</> : <><Copy className="w-3.5 h-3.5" /> Copy</>}
        </button>
      </div>
      <button onClick={onDismiss} className="mt-3 text-xs text-slate-500 hover:text-slate-300">Dismiss</button>
    </div>
  )
}

export default function ApiKeysPage() {
  const qc = useQueryClient()
  const [label, setLabel] = useState('')
  const [creating, setCreating] = useState(false)
  const [createdKey, setCreatedKey] = useState<ApiKeyCreated | null>(null)
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null)

  const { data: keys = [] } = useQuery({
    queryKey: ['settings', 'api-keys'],
    queryFn: settingsApi.listApiKeys,
  })

  const createMut = useMutation({
    mutationFn: (l: string) => settingsApi.createApiKey(l),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['settings', 'api-keys'] })
      setCreatedKey(data)
      setLabel('')
      setCreating(false)
      showToast('API key created', true)
    },
    onError: () => showToast('Failed to create key', false),
  })

  const revokeMut = useMutation({
    mutationFn: (id: string) => settingsApi.revokeApiKey(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['settings', 'api-keys'] }); showToast('Key revoked', true) },
    onError: () => showToast('Failed to revoke key', false),
  })

  function showToast(msg: string, ok: boolean) {
    setToast({ msg, ok })
    setTimeout(() => setToast(null), 3000)
  }

  const activeKeys = keys.filter(k => k.active)
  const revokedKeys = keys.filter(k => !k.active)

  return (
    <>
      <TopBar title="API Keys" />
      <div className="flex-1 p-6 max-w-2xl">
        {createdKey && <CreatedKeyBanner created={createdKey} onDismiss={() => setCreatedKey(null)} />}

        <div className="card p-6 mb-5">
          <div className="flex items-center justify-between mb-5">
            <div>
              <h2 className="font-semibold text-white">Active Keys</h2>
              <p className="text-sm text-slate-400 mt-0.5">{activeKeys.length} active key{activeKeys.length !== 1 ? 's' : ''}</p>
            </div>
            <button onClick={() => setCreating(c => !c)} className="btn-primary flex items-center gap-2 text-sm">
              <Plus className="w-4 h-4" /> New key
            </button>
          </div>

          {creating && (
            <form onSubmit={e => { e.preventDefault(); if (label.trim()) createMut.mutate(label.trim()) }}
                  className="flex gap-2 mb-5 p-4 rounded-xl bg-white/[0.03] border border-white/[0.06]">
              <input
                autoFocus
                value={label}
                onChange={e => setLabel(e.target.value)}
                placeholder="Key label (e.g. Production, CI/CD)"
                className="input flex-1"
                maxLength={80}
              />
              <button type="submit" disabled={createMut.isPending || !label.trim()} className="btn-primary text-sm">
                {createMut.isPending ? <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : 'Generate'}
              </button>
              <button type="button" onClick={() => setCreating(false)} className="btn-secondary text-sm">Cancel</button>
            </form>
          )}

          {activeKeys.length === 0 && !creating ? (
            <p className="text-sm text-slate-500 text-center py-6">No active keys. Create your first key above.</p>
          ) : (
            <div className="space-y-1">
              {activeKeys.map(k => <KeyRow key={k.id} k={k} onRevoke={() => revokeMut.mutate(k.id)} />)}
            </div>
          )}
        </div>

        {revokedKeys.length > 0 && (
          <div className="card p-6">
            <h3 className="text-sm font-semibold text-slate-400 mb-3">Revoked Keys ({revokedKeys.length})</h3>
            <div className="space-y-1 opacity-50">
              {revokedKeys.map(k => <KeyRow key={k.id} k={k} revoked />)}
            </div>
          </div>
        )}

        {toast && <Toast {...toast} />}
      </div>
    </>
  )
}

function KeyRow({ k, onRevoke, revoked }: { k: ApiKeyOut; onRevoke?: () => void; revoked?: boolean }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(k.prefix + '...')
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }
  return (
    <div className="flex items-center gap-3 p-3 rounded-xl hover:bg-white/[0.02] transition-colors">
      <div className="w-8 h-8 rounded-lg bg-brand-400/10 flex items-center justify-center shrink-0">
        <Key className="w-3.5 h-3.5 text-brand-400" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-white truncate">{k.label}</p>
        <p className="text-xs text-slate-500 mt-0.5">
          <code className="font-mono">{k.prefix}{'•'.repeat(20)}</code>
          {' · '}Created {new Date(k.created_at).toLocaleDateString()}
          {k.last_used_at && ` · Last used ${new Date(k.last_used_at).toLocaleDateString()}`}
          {k.request_count > 0 && ` · ${k.request_count.toLocaleString()} requests`}
        </p>
      </div>
      {!revoked && (
        <div className="flex items-center gap-1 shrink-0">
          <button onClick={copy} className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors">
            {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
          <button onClick={onRevoke} className="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-red-400/10 transition-colors">
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
    </div>
  )
}
