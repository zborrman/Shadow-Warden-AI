'use client'
import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { Loader2, Save, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui'
import { CopyField, Panel, PanelActions, Row, Switch } from '@/components/ui/settings'
import { LOCALES, errorMessage, storeApi, type Store } from '@/lib/storeApi'

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
    <div className="space-y-5">
      <form onSubmit={e => { e.preventDefault(); if (name.trim()) save.mutate() }}>
        <Panel title="General">
          <Row label="Name" help="Shown at the top of your storefront." htmlFor="store-name">
            <input id="store-name" className="input" value={name} onChange={e => setName(e.target.value)}
                   maxLength={120} required />
          </Row>
          <Row label="Description" help="A sentence or two about what you sell." htmlFor="store-desc">
            <textarea id="store-desc" className="input min-h-[88px]" value={description}
                      onChange={e => setDescription(e.target.value)} maxLength={2000} />
          </Row>
          <Row label="Visible to buyers" help="Off hides the storefront without deleting anything.">
            <Switch checked={active} onChange={setActive} label="Visible to buyers" />
          </Row>
          <PanelActions>
            <Button type="submit" disabled={!dirty || !name.trim() || save.isPending}>
              {save.isPending ? <Loader2 className="animate-spin" /> : <Save />} Save
            </Button>
          </PanelActions>
        </Panel>
      </form>

      <Panel title="Storefront">
        <Row label="Address" help="Share this link with buyers. It cannot be changed.">
          <CopyField value={`${window.location.origin}/s/${store.slug}`} label="Store address" />
        </Row>
        <Row label="Currencies" help="Prices you set per product. Nothing is converted.">
          <p className="text-sm text-slate-200">{store.currencies.join(', ')}
            <span className="text-slate-500"> · default {store.default_currency}</span></p>
        </Row>
        <Row label="Languages" help="Storefront languages buyers can switch between.">
          <p className="text-sm text-slate-200">
            {store.locales.map(l => LOCALES.find(x => x.code === l)?.label ?? l).join(', ')}
          </p>
        </Row>
      </Panel>

      <Panel title="Danger zone" tone="danger">
        <Row label="Delete store" htmlFor="confirm-slug"
             help={<>The store disappears from buyers. Its address stays reserved, so no one else can open a store
               under it. Type <span className="font-mono text-slate-200">{store.slug}</span> to confirm.</>}>
          <div className="flex flex-wrap gap-2">
            <input id="confirm-slug" className="input min-w-[160px] flex-1" value={confirmSlug} spellCheck={false}
                   onChange={e => setConfirmSlug(e.target.value)} placeholder={store.slug} />
            <Button variant="destructive" disabled={confirmSlug !== store.slug || remove.isPending}
                    onClick={() => remove.mutate()}>
              {remove.isPending ? <Loader2 className="animate-spin" /> : <Trash2 />} Delete
            </Button>
          </div>
        </Row>
      </Panel>
    </div>
  )
}
