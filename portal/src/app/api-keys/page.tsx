'use client'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { TopBar } from '@/components/layout/TopBar'
import { Plus, Copy, Check, Trash2, Key, AlertTriangle, X } from 'lucide-react'
import { useForm } from 'react-hook-form'
import { z } from 'zod'
import { zodResolver } from '@hookform/resolvers/zod'

// ── Types ──────────────────────────────────────────────────────────────────────
interface ApiKey {
  id: string; label: string; key_prefix: string
  rate_limit: number; active: boolean
  created_at: string; revoked_at: string | null
}

// ── Copy button ───────────────────────────────────────────────────────────────
function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button onClick={copy} className="btn-secondary px-3 py-1.5 text-xs">
      {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}

// ── Create key modal ──────────────────────────────────────────────────────────
const schema = z.object({
  label:      z.string().max(60).optional(),
  rate_limit: z.coerce.number().int().min(1).max(10000),
})
type Form = z.infer<typeof schema>

function CreateKeyModal({ onClose, onCreated }: {
  onClose: () => void
  onCreated: (key: string) => void
}) {
  const qc = useQueryClient()
  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<Form>({
    resolver: zodResolver(schema),
    defaultValues: { label: 'Default', rate_limit: 60 },
  })
  const mut = useMutation({
    mutationFn: (d: Form) => api.post('/keys', d).then(r => r.data),
    onSuccess:  (data) => {
      qc.invalidateQueries({ queryKey: ['api-keys'] })
      onCreated(data.key)
    },
  })

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-md p-6">
        <div className="flex items-center justify-between mb-5">
          <h2 className="font-semibold text-white">Create API Key</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-200"><X className="w-5 h-5" /></button>
        </div>
        <form onSubmit={handleSubmit(d => mut.mutateAsync(d))} className="space-y-4">
          <div>
            <label className="label">Label</label>
            <input {...register('label')} className="input" placeholder="Production, Staging…" />
            {errors.label && <p className="text-red-400 text-xs mt-1">{errors.label.message}</p>}
          </div>
          <div>
            <label className="label">Rate limit <span className="text-slate-500 font-normal">(req/min)</span></label>
            <input {...register('rate_limit')} type="number" className="input" />
            {errors.rate_limit && <p className="text-red-400 text-xs mt-1">{errors.rate_limit.message}</p>}
          </div>
          {mut.isError && (
            <p className="text-red-400 text-sm flex items-center gap-1">
              <AlertTriangle className="w-4 h-4" /> Failed to create key.
            </p>
          )}
          <div className="flex gap-3 pt-1">
            <button type="button" onClick={onClose} className="btn-secondary flex-1">Cancel</button>
            <button type="submit" disabled={isSubmitting || mut.isPending} className="btn-primary flex-1">
              {(isSubmitting || mut.isPending)
                ? <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                : 'Create Key'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── New key reveal modal ──────────────────────────────────────────────────────
function RevealModal({ apiKey, onClose }: { apiKey: string; onClose: () => void }) {
  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-md p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-xl bg-green-500/10 flex items-center justify-center">
            <Key className="w-5 h-5 text-green-400" />
          </div>
          <div>
            <h2 className="font-semibold text-white">API Key Created</h2>
            <p className="text-xs text-slate-400">Save this now — it will only be shown once</p>
          </div>
        </div>
        <div className="bg-dark-900 border border-white/10 rounded-xl p-4 font-mono text-sm text-brand-400 break-all mb-4">
          {apiKey}
        </div>
        <div className="flex gap-3">
          <CopyButton text={apiKey} />
          <button onClick={onClose} className="btn-primary flex-1">I've saved it</button>
        </div>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function ApiKeysPage() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [newKey, setNewKey]         = useState<string | null>(null)

  const { data: keys = [], isLoading } = useQuery<ApiKey[]>({
    queryKey: ['api-keys'],
    queryFn:  () => api.get('/keys').then(r => r.data),
  })

  const revokeMut = useMutation({
    mutationFn: (id: string) => api.delete(`/keys/${id}`),
    onSuccess:  () => qc.invalidateQueries({ queryKey: ['api-keys'] }),
  })

  return (
    <>
      <TopBar title="API Keys" />
      <div className="flex-1 p-6 space-y-5">

        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <p className="text-slate-400 text-sm">
              Use these keys in the <code className="text-brand-400 bg-brand-400/10 px-1 rounded">X-API-Key</code> header to authenticate requests.
            </p>
          </div>
          <button onClick={() => setShowCreate(true)} className="btn-primary shrink-0">
            <Plus className="w-4 h-4" /> New Key
          </button>
        </div>

        {/* Keys table */}
        <div className="card overflow-hidden">
          {isLoading ? (
            <div className="py-16 flex items-center justify-center">
              <div className="w-6 h-6 border-2 border-brand-400 border-t-transparent rounded-full animate-spin" />
            </div>
          ) : keys.length === 0 ? (
            <div className="py-16 text-center">
              <Key className="w-10 h-10 text-slate-600 mx-auto mb-3" />
              <p className="text-slate-400">No API keys yet</p>
              <button onClick={() => setShowCreate(true)} className="btn-primary mt-4 mx-auto">
                <Plus className="w-4 h-4" /> Create your first key
              </button>
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/[0.06] text-xs text-slate-500 uppercase tracking-wider">
                  <th className="text-left px-5 py-3">Label</th>
                  <th className="text-left px-5 py-3">Key</th>
                  <th className="text-left px-5 py-3">Rate limit</th>
                  <th className="text-left px-5 py-3">Status</th>
                  <th className="text-left px-5 py-3">Created</th>
                  <th className="px-5 py-3" />
                </tr>
              </thead>
              <tbody>
                {keys.map(k => (
                  <tr key={k.id} className="border-b border-white/[0.04] last:border-0 hover:bg-white/[0.02] transition-colors">
                    <td className="px-5 py-3.5 font-medium text-white">{k.label}</td>
                    <td className="px-5 py-3.5 font-mono text-brand-400 text-xs">{k.key_prefix}</td>
                    <td className="px-5 py-3.5 text-slate-300">{k.rate_limit} req/min</td>
                    <td className="px-5 py-3.5">
                      {k.active
                        ? <span className="badge-active">Active</span>
                        : <span className="badge-revoked">Revoked</span>}
                    </td>
                    <td className="px-5 py-3.5 text-slate-400">
                      {new Date(k.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      {k.active && (
                        <button
                          onClick={() => {
                            if (confirm(`Revoke key "${k.label}"? This cannot be undone.`))
                              revokeMut.mutate(k.id)
                          }}
                          className="btn-danger"
                          disabled={revokeMut.isPending}
                        >
                          <Trash2 className="w-3.5 h-3.5" /> Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Usage code example */}
        <div className="card p-5">
          <h3 className="text-sm font-semibold text-white mb-3">Quick start</h3>
          <pre className="bg-dark-900 rounded-xl p-4 text-xs text-slate-300 overflow-x-auto">
{`curl -X POST https://api.shadow-warden-ai.com/filter \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: YOUR_API_KEY" \\
  -d '{"content": "User input to filter"}'`}
          </pre>
        </div>
      </div>

      {showCreate && (
        <CreateKeyModal
          onClose={() => setShowCreate(false)}
          onCreated={key => { setShowCreate(false); setNewKey(key) }}
        />
      )}
      {newKey && <RevealModal apiKey={newKey} onClose={() => setNewKey(null)} />}
    </>
  )
}
