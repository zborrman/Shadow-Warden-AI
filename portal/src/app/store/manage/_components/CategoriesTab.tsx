'use client'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { Loader2, Plus, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui'
import { SLUG_RE, errorMessage, storeApi, type Category, type Store } from '@/lib/storeApi'
import { EmptyState, SelectInput, TextInput } from './fields'

export const MAX_DEPTH = 5

/** Depth-first list of [category, depth] — for indenting and for parent pickers. */
export function flatten(nodes: Category[], depth = 0): [Category, number][] {
  return nodes.flatMap(n => [[n, depth] as [Category, number], ...flatten(n.children, depth + 1)])
}

export function useCategories(storeId: string) {
  return useQuery({ queryKey: ['m2m-categories', storeId], queryFn: () => storeApi.categories(storeId) })
}

export function CategoriesTab({ store }: { store: Store }) {
  const qc = useQueryClient()
  const tree = useCategories(store.id)
  const flat = flatten(tree.data ?? [])
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [parent, setParent] = useState('')

  const refresh = () => qc.invalidateQueries({ queryKey: ['m2m-categories', store.id] })
  const create = useMutation({
    mutationFn: () => storeApi.createCategory(store.id, {
      name: name.trim(), slug, parent_id: parent, position: flat.length,
    }),
    onSuccess: () => { setName(''); setSlug(''); refresh(); toast.success('Category added') },
    onError: e => toast.error(errorMessage(e)),
  })
  const remove = useMutation({
    mutationFn: storeApi.deleteCategory,
    onSuccess: () => { refresh(); toast.success('Category deleted') },
    onError: e => toast.error(errorMessage(e)),
  })

  const slugError = slug && !SLUG_RE.test(slug) ? 'Lowercase letters, digits and hyphens.' : undefined
  // A parent at depth 4 would put the new category at depth 5, one past the limit.
  const parents = flat.filter(([, d]) => d < MAX_DEPTH - 1)

  return (
    <div className="space-y-6">
      <form
        onSubmit={e => { e.preventDefault(); if (name.trim() && slug && !slugError) create.mutate() }}
        className="grid gap-4 rounded-xl border border-white/10 bg-dark-800 p-4 sm:grid-cols-[1fr_1fr_1fr_auto] sm:items-end"
      >
        <TextInput
          label="Name"
          value={name}
          onChange={e => {
            setName(e.target.value)
            setSlug(e.target.value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40))
          }}
          maxLength={120}
          required
        />
        <TextInput label="Slug" value={slug} onChange={e => setSlug(e.target.value.toLowerCase())}
                   error={slugError} spellCheck={false} required />
        <SelectInput label="Parent" value={parent} onChange={e => setParent(e.target.value)}>
          <option value="">Top level</option>
          {parents.map(([c, d]) => <option key={c.id} value={c.id}>{'— '.repeat(d)}{c.name}</option>)}
        </SelectInput>
        <Button type="submit" disabled={!name.trim() || !slug || Boolean(slugError) || create.isPending}>
          {create.isPending ? <Loader2 className="animate-spin" /> : <Plus />} Add
        </Button>
      </form>

      {tree.isLoading && <p className="text-sm text-slate-500">Loading categories…</p>}
      {tree.isError && <p className="text-sm text-red-400" role="alert">{errorMessage(tree.error)}</p>}
      {tree.data && flat.length === 0 && (
        <EmptyState title="No categories" body={`Group products into a tree up to ${MAX_DEPTH} levels deep.`} />
      )}
      {flat.length > 0 && (
        <ul className="divide-y divide-white/[0.06] rounded-xl border border-white/10 bg-dark-800">
          {flat.map(([c, depth]) => (
            <li key={c.id} className="flex items-center gap-3 px-4 py-2.5" style={{ paddingLeft: 16 + depth * 20 }}>
              <span className="min-w-0 flex-1 truncate text-sm text-slate-200">{c.name}</span>
              <span className="font-mono text-xs text-slate-500">{c.slug}</span>
              <Button
                variant="ghost"
                size="icon-sm"
                aria-label={`Delete ${c.name}`}
                title={c.children.length ? 'Delete its subcategories first' : 'Delete'}
                disabled={c.children.length > 0 || remove.isPending}
                onClick={() => { if (confirm(`Delete category "${c.name}"?`)) remove.mutate(c.id) }}
              >
                <Trash2 />
              </Button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
