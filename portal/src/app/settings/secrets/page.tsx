'use client'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Shield, Plus, Trash2, Pencil, AlertCircle, CheckCircle2, Clock } from 'lucide-react'
import { settingsApi, type SecretOut } from '@/lib/settingsApi'
import { TopBar } from '@/components/layout/TopBar'
import { z } from 'zod'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'

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

const secretSchema = z.object({
  name: z.string().min(1).max(120).regex(/^[A-Za-z0-9_\-.]+$/, 'Only letters, digits, _ - . allowed'),
  value: z.string().min(1),
  description: z.string().max(255).optional(),
  expires_at: z.string().optional(),
})
type SecretForm = z.infer<typeof secretSchema>

function isExpiringSoon(expiresAt: string | null) {
  if (!expiresAt) return false
  const diff = new Date(expiresAt).getTime() - Date.now()
  return diff > 0 && diff < 30 * 24 * 60 * 60 * 1000
}

function isExpired(expiresAt: string | null) {
  if (!expiresAt) return false
  return new Date(expiresAt).getTime() < Date.now()
}

export default function SecretsPage() {
  const qc = useQueryClient()
  const [creating, setCreating] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null)

  const { data: secrets = [] } = useQuery({
    queryKey: ['settings', 'secrets'],
    queryFn: settingsApi.listSecrets,
  })

  const { register, handleSubmit, reset, formState: { errors, isSubmitting } } = useForm<SecretForm>({
    resolver: zodResolver(secretSchema),
  })

  const createMut = useMutation({
    mutationFn: (d: SecretForm) => settingsApi.createSecret({
      name: d.name, value: d.value,
      description: d.description,
      expires_at: d.expires_at || undefined,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['settings', 'secrets'] })
      reset()
      setCreating(false)
      showToast('Secret created', true)
    },
    onError: () => showToast('Failed to create secret', false),
  })

  const updateMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: SecretForm }) =>
      settingsApi.updateSecret(id, { value: data.value, description: data.description, expires_at: data.expires_at }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['settings', 'secrets'] })
      setEditingId(null)
      reset()
      showToast('Secret updated', true)
    },
    onError: () => showToast('Failed to update secret', false),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => settingsApi.deleteSecret(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['settings', 'secrets'] }); showToast('Secret deleted', true) },
    onError: () => showToast('Failed to delete secret', false),
  })

  function showToast(msg: string, ok: boolean) {
    setToast({ msg, ok })
    setTimeout(() => setToast(null), 3000)
  }

  const expiringSoon = secrets.filter(s => isExpiringSoon(s.expires_at))
  const expired = secrets.filter(s => isExpired(s.expires_at))

  return (
    <>
      <TopBar title="Secrets Vault" />
      <div className="flex-1 p-6 max-w-2xl">
        {(expiringSoon.length > 0 || expired.length > 0) && (
          <div className="mb-5 p-4 rounded-2xl border" style={{ background: 'rgba(245,158,11,0.06)', borderColor: 'rgba(245,158,11,0.25)' }}>
            <div className="flex items-center gap-2 text-amber-400 text-sm font-semibold mb-1">
              <Clock className="w-4 h-4" />
              {expired.length > 0 ? `${expired.length} secret(s) expired` : `${expiringSoon.length} secret(s) expiring within 30 days`}
            </div>
            <p className="text-xs text-amber-500/70">Update or rotate these secrets before expiry to avoid disruptions.</p>
          </div>
        )}

        <div className="card p-6">
          <div className="flex items-center justify-between mb-5">
            <div>
              <h2 className="font-semibold text-white">Encrypted Secrets</h2>
              <p className="text-sm text-slate-400 mt-0.5">{secrets.length} secret{secrets.length !== 1 ? 's' : ''} — Fernet-encrypted at rest</p>
            </div>
            <button onClick={() => { setCreating(c => !c); setEditingId(null); reset() }}
                    className="btn-primary flex items-center gap-2 text-sm">
              <Plus className="w-4 h-4" /> Add secret
            </button>
          </div>

          {creating && (
            <form onSubmit={handleSubmit(d => createMut.mutateAsync(d))}
                  className="p-4 rounded-xl bg-white/[0.03] border border-white/[0.06] mb-5 space-y-3">
              <p className="text-sm font-medium text-white mb-1">New secret</p>
              <div>
                <label className="label">Name</label>
                <input {...register('name')} placeholder="MY_API_KEY" className="input font-mono" />
                {errors.name && <p className="text-red-400 text-xs mt-1">{errors.name.message}</p>}
              </div>
              <div>
                <label className="label">Value</label>
                <input {...register('value')} type="password" placeholder="••••••••" className="input" />
                {errors.value && <p className="text-red-400 text-xs mt-1">{errors.value.message}</p>}
              </div>
              <div>
                <label className="label">Description (optional)</label>
                <input {...register('description')} placeholder="Used by..." className="input" />
              </div>
              <div>
                <label className="label">Expiry date (optional)</label>
                <input {...register('expires_at')} type="date" className="input" />
              </div>
              <div className="flex gap-2 pt-1">
                <button type="submit" disabled={isSubmitting || createMut.isPending} className="btn-primary text-sm">
                  {(isSubmitting || createMut.isPending) ? <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : 'Save'}
                </button>
                <button type="button" onClick={() => { setCreating(false); reset() }} className="btn-secondary text-sm">Cancel</button>
              </div>
            </form>
          )}

          {secrets.length === 0 && !creating ? (
            <p className="text-sm text-slate-500 text-center py-6">No secrets. Add your first encrypted secret above.</p>
          ) : (
            <div className="space-y-1">
              {secrets.map(s => (
                <SecretRow
                  key={s.id}
                  secret={s}
                  isEditing={editingId === s.id}
                  onEdit={() => { setEditingId(s.id); setCreating(false) }}
                  onUpdate={data => updateMut.mutate({ id: s.id, data })}
                  onCancelEdit={() => { setEditingId(null); reset() }}
                  onDelete={() => deleteMut.mutate(s.id)}
                />
              ))}
            </div>
          )}
        </div>

        <div className="mt-4 p-4 rounded-xl text-xs" style={{ background: 'rgba(48,209,88,0.04)', border: '1px solid rgba(48,209,88,0.15)' }}>
          <span className="font-semibold text-green-400">🔒 Encryption: </span>
          <span className="text-slate-500">Fernet symmetric encryption with <code className="font-mono text-slate-400">VAULT_MASTER_KEY</code>. Values are never logged or returned via API — metadata only.</span>
        </div>

        {toast && <Toast {...toast} />}
      </div>
    </>
  )
}

function SecretRow({ secret, isEditing, onEdit, onUpdate, onCancelEdit, onDelete }: {
  secret: SecretOut
  isEditing: boolean
  onEdit: () => void
  onUpdate: (data: SecretForm) => void
  onCancelEdit: () => void
  onDelete: () => void
}) {
  const { register, handleSubmit, formState: { errors } } = useForm<SecretForm>({
    resolver: zodResolver(secretSchema),
    defaultValues: { name: secret.name, description: secret.description, value: '' },
  })

  const expired = isExpired(secret.expires_at)
  const expiring = isExpiringSoon(secret.expires_at)

  if (isEditing) {
    return (
      <form onSubmit={handleSubmit(onUpdate)}
            className="p-4 rounded-xl bg-white/[0.03] border border-brand-400/20 space-y-3 my-1">
        <p className="text-sm font-medium text-white">Editing: <code className="font-mono text-brand-400">{secret.name}</code></p>
        <div>
          <label className="label">New value</label>
          <input {...register('value')} type="password" placeholder="New secret value" className="input" />
          {errors.value && <p className="text-red-400 text-xs mt-1">{errors.value.message}</p>}
        </div>
        <input type="hidden" {...register('name')} />
        <div className="flex gap-2">
          <button type="submit" className="btn-primary text-sm">Update</button>
          <button type="button" onClick={onCancelEdit} className="btn-secondary text-sm">Cancel</button>
        </div>
      </form>
    )
  }

  return (
    <div className="flex items-center gap-3 p-3 rounded-xl hover:bg-white/[0.02] transition-colors">
      <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
        expired ? 'bg-red-400/10' : expiring ? 'bg-amber-400/10' : 'bg-green-400/10'
      }`}>
        <Shield className={`w-3.5 h-3.5 ${expired ? 'text-red-400' : expiring ? 'text-amber-400' : 'text-green-400'}`} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <p className="text-sm font-mono font-medium text-white">{secret.name}</p>
          {expired && <span className="text-[10px] font-bold text-red-400 bg-red-400/10 px-1.5 py-0.5 rounded">EXPIRED</span>}
          {expiring && !expired && <span className="text-[10px] font-bold text-amber-400 bg-amber-400/10 px-1.5 py-0.5 rounded">EXPIRING</span>}
        </div>
        <p className="text-xs text-slate-500 mt-0.5">
          {secret.description && <>{secret.description} · </>}
          Added {new Date(secret.created_at).toLocaleDateString()}
          {secret.expires_at && ` · Expires ${new Date(secret.expires_at).toLocaleDateString()}`}
        </p>
      </div>
      <div className="flex items-center gap-1 shrink-0">
        <button onClick={onEdit} className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors">
          <Pencil className="w-3.5 h-3.5" />
        </button>
        <button onClick={onDelete} className="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-red-400/10 transition-colors">
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  )
}
