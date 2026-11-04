'use client'
import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { Loader2, Save, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui'
import { LOCALES, errorMessage, storeApi, type Store } from '@/lib/storeApi'
import { TextArea, TextInput } from './fields'

export function SettingsTab({ store, onDeleted }: { store: Store; onDeleted: () => void }) {
  const qc = useQueryClient()
  const [name, setName] = useState(store.name)
  const [description, setDescription] = useState(store.description)
  const [active, setActive] = useState(store.active)
  const [confirmSlug, setConfirmSlug] = useState('')

  const refresh = () => qc.invalidateQueries({ queryKey: ['m2m-stores'] })
  const save = useMutation({
    mutationFn: () => storeApi.patchStore(store.id, { name: name.trim(), description: description.trim(), active }),
    onSuccess: () => { refresh(); toast.success('Saved') },
    onError: e => toast.error(errorMessage(e)),
  })
  const remove = useMutation({
    mutationFn: () => storeApi.deleteStore(store.id),
    onSuccess: () => { refresh(); toast.success('Store deleted'); onDeleted() },
    onError: e => toast.error(errorMessage(e)),
  })

  const dirty = name.trim() !== store.name || description.trim() !== store.description || active !== store.active
  return (
    <div className="space-y-6">
      <form
        onSubmit={e => { e.preventDefault(); if (name.trim()) save.mutate() }}
        className="space-y-4 rounded-xl border border-white/10 bg-dark-800 p-4 sm:p-6"
      >
        <TextInput label="Name" value={name} onChange={e => setName(e.target.value)} maxLength={120} required />
        <TextArea label="Description" value={description} onChange={e => setDescription(e.target.value)} maxLength={2000} />
        <label className="flex items-center gap-3 text-sm text-slate-300">
          <input type="checkbox" checked={active} onChange={e => setActive(e.target.checked)}
                 className="h-4 w-4 accent-sky-500" />
          Visible to buyers
        </label>
        <dl className="grid gap-3 text-xs text-slate-500 sm:grid-cols-3">
          <div><dt className="font-semibold text-slate-400">Address</dt><dd className="font-mono">/s/{store.slug}</dd></div>
          <div><dt className="font-semibold text-slate-400">Currencies</dt><dd>{store.currencies.join(', ')} (default {store.default_currency})</dd></div>
          <div><dt className="font-semibold text-slate-400">Languages</dt>
            <dd>{store.locales.map(l => LOCALES.find(x => x.code === l)?.label ?? l).join(', ')}</dd></div>
        </dl>
        <div className="flex justify-end">
          <Button type="submit" disabled={!dirty || !name.trim() || save.isPending}>
            {save.isPending ? <Loader2 className="animate-spin" /> : <Save />} Save
          </Button>
        </div>
      </form>

      <section className="space-y-3 rounded-xl border border-red-500/20 bg-red-500/[0.04] p-4 sm:p-6">
        <h3 className="text-sm font-bold text-red-300">Delete store</h3>
        <p className="text-sm text-slate-400">
          The store disappears from buyers. Its address stays reserved, so no one else can open a store under it.
          Type <span className="font-mono text-slate-200">{store.slug}</span> to confirm.
        </p>
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[200px] flex-1">
            <TextInput label="Store address" value={confirmSlug} onChange={e => setConfirmSlug(e.target.value)} spellCheck={false} />
          </div>
          <Button variant="destructive" disabled={confirmSlug !== store.slug || remove.isPending} onClick={() => remove.mutate()}>
            {remove.isPending ? <Loader2 className="animate-spin" /> : <Trash2 />} Delete store
          </Button>
        </div>
      </section>
    </div>
  )
}
