'use client'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { ChevronRight, Loader2, Plus, Store as StoreIcon } from 'lucide-react'
import { TopBar } from '@/components/layout/TopBar'
import { Button } from '@/components/ui'
import {
  CURRENCIES, LOCALES, SETTLEMENT_CURRENCY, SLUG_RE, errorMessage, storeApi,
  type Store,
} from '@/lib/storeApi'
import { ChipSet, EmptyState, SelectInput, TextArea, TextInput } from './_components/fields'
import { StoreEditor } from './_components/StoreEditor'

export default function StoreManagePage() {
  const [selected, setSelected] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const stores = useQuery({ queryKey: ['m2m-stores'], queryFn: storeApi.listStores })

  const current = stores.data?.find(s => s.id === selected)
  if (current) {
    return (
      <>
        <TopBar title={`Store · ${current.name}`} />
        <StoreEditor store={current} onBack={() => setSelected(null)} />
      </>
    )
  }

  return (
    <>
      <TopBar title="Store Builder" />
      <div className="mx-auto w-full max-w-4xl p-4 sm:p-6 space-y-6">
        <header className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-slate-100">Your stores</h2>
            <p className="text-sm text-slate-500">
              A store has its own address, currencies, languages, categories and shipping zones.
            </p>
          </div>
          {!creating && (
            <Button onClick={() => setCreating(true)}><Plus /> New store</Button>
          )}
        </header>

        {creating && (
          <CreateStore
            onCancel={() => setCreating(false)}
            onCreated={s => { setCreating(false); setSelected(s.id) }}
          />
        )}

        {stores.isLoading && <p className="text-sm text-slate-500">Loading stores…</p>}
        {stores.isError && (
          <p className="text-sm text-red-400" role="alert">{errorMessage(stores.error)}</p>
        )}
        {stores.data && stores.data.length === 0 && !creating && (
          <EmptyState
            title="No stores yet"
            body="Create your first store to start adding products."
            action={<Button onClick={() => setCreating(true)}><Plus /> New store</Button>}
          />
        )}
        {stores.data && stores.data.length > 0 && (
          <ul className="divide-y divide-white/[0.06] rounded-xl border border-white/10 bg-dark-800">
            {stores.data.map(s => (
              <li key={s.id}>
                <button
                  onClick={() => setSelected(s.id)}
                  className="flex w-full items-center gap-4 px-4 py-3.5 text-left hover:bg-white/[0.03] transition-colors"
                >
                  <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-brand-500/10 text-brand-400">
                    <StoreIcon className="h-4 w-4" />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-semibold text-slate-100">{s.name}</span>
                    <span className="block truncate font-mono text-xs text-slate-500">/s/{s.slug}</span>
                  </span>
                  <span className={s.active ? 'text-xs text-emerald-400' : 'text-xs text-slate-500'}>
                    {s.active ? 'Active' : 'Hidden'}
                  </span>
                  <ChevronRight className="h-4 w-4 text-slate-600" />
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </>
  )
}

function CreateStore({ onCancel, onCreated }: { onCancel: () => void; onCreated: (s: Store) => void }) {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [slugTouched, setSlugTouched] = useState(false)
  const [description, setDescription] = useState('')
  const [currencies, setCurrencies] = useState<string[]>([SETTLEMENT_CURRENCY])
  const [defaultCurrency, setDefaultCurrency] = useState(SETTLEMENT_CURRENCY)
  const [locales, setLocales] = useState<string[]>(['en'])

  const suggested = name.toLowerCase().normalize('NFKD').replace(/[^\w\s-]/g, '')
    .trim().replace(/[\s_]+/g, '-').replace(/-+/g, '-').slice(0, 40).replace(/^-|-$/g, '')
  const effectiveSlug = slugTouched ? slug : suggested
  const slugError = effectiveSlug && !SLUG_RE.test(effectiveSlug)
    ? 'Lowercase letters, digits and hyphens; 1–40 characters, not starting or ending with a hyphen.'
    : undefined

  const create = useMutation({
    mutationFn: () => storeApi.createStore({
      name: name.trim(), slug: effectiveSlug, description: description.trim(),
      currencies, default_currency: currencies.includes(defaultCurrency) ? defaultCurrency : SETTLEMENT_CURRENCY,
      locales,
    }),
    onSuccess: s => {
      qc.invalidateQueries({ queryKey: ['m2m-stores'] })
      toast.success('Store created')
      onCreated(s)
    },
    onError: e => toast.error(errorMessage(e)),
  })

  const valid = name.trim() && effectiveSlug && !slugError && locales.length > 0
  return (
    <form
      onSubmit={e => { e.preventDefault(); if (valid) create.mutate() }}
      className="rounded-xl border border-white/10 bg-dark-800 p-4 sm:p-6 space-y-5"
    >
      <h3 className="text-sm font-bold text-slate-100">New store</h3>
      <div className="grid gap-4 sm:grid-cols-2">
        <TextInput label="Name" value={name} onChange={e => setName(e.target.value)} maxLength={120} required autoFocus />
        <TextInput
          label="Address"
          value={effectiveSlug}
          onChange={e => { setSlugTouched(true); setSlug(e.target.value.toLowerCase()) }}
          hint={`Storefront at /s/${effectiveSlug || 'your-store'}. It cannot be changed later.`}
          error={slugError}
          spellCheck={false}
          required
        />
      </div>
      <TextArea label="Description" value={description} onChange={e => setDescription(e.target.value)} maxLength={2000} />
      <ChipSet
        legend="Currencies"
        options={CURRENCIES.map(c => ({ value: c, label: c }))}
        value={currencies}
        onChange={setCurrencies}
        locked={[SETTLEMENT_CURRENCY]}
      />
      <p className="-mt-3 text-xs text-slate-500">
        USD is always on: agent orders settle in it. Each product gets its own price per currency; nothing is converted.
      </p>
      <div className="grid gap-4 sm:grid-cols-2">
        <SelectInput label="Default currency" value={defaultCurrency} onChange={e => setDefaultCurrency(e.target.value)}>
          {currencies.map(c => <option key={c} value={c}>{c}</option>)}
        </SelectInput>
      </div>
      <ChipSet
        legend="Storefront languages"
        options={LOCALES.map(l => ({ value: l.code, label: l.label }))}
        value={locales}
        onChange={setLocales}
      />
      <div className="flex justify-end gap-2 pt-1">
        <Button type="button" variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button type="submit" disabled={!valid || create.isPending}>
          {create.isPending && <Loader2 className="animate-spin" />} Create store
        </Button>
      </div>
    </form>
  )
}
