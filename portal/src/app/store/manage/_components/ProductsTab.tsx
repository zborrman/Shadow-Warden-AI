'use client'
import { useEffect, useRef, useState } from 'react'
import type { ChangeEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { ImagePlus, Languages, Loader2, Package, Plus, Save, Trash2, X } from 'lucide-react'
import { Button } from '@/components/ui'
import {
  LOCALES, MAX_IMAGE_BYTES, SETTLEMENT_CURRENCY, orderCurrencies, errorMessage, formatMoney, fromMinor, storeApi, toMinor,
  type ProductImage, type Store, type StoreProduct,
} from '@/lib/storeApi'
import { EmptyState, SelectInput, TextArea, TextInput } from './fields'
import { flatten, useCategories } from './CategoriesTab'

const ACCEPT = 'image/jpeg,image/png,image/webp'

export function ProductsTab({ store }: { store: Store }) {
  const products = useQuery({ queryKey: ['m2m-products', store.id], queryFn: () => storeApi.products(store.id) })
  const [editing, setEditing] = useState<StoreProduct | 'new' | null>(null)

  if (editing) {
    const current = editing === 'new' ? null
      : products.data?.find(p => p.id === editing.id) ?? editing
    return <ProductForm store={store} product={current} onDone={() => setEditing(null)}
                        onCreated={p => setEditing(p)} />
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button onClick={() => setEditing('new')}><Plus /> New product</Button>
      </div>
      {products.isLoading && <p className="text-sm text-slate-500">Loading products…</p>}
      {products.isError && <p className="text-sm text-red-400" role="alert">{errorMessage(products.error)}</p>}
      {products.data && products.data.length === 0 && (
        <EmptyState title="No products" body="Add a product with a USD price; other currencies are optional."
                    action={<Button onClick={() => setEditing('new')}><Plus /> New product</Button>} />
      )}
      {products.data && products.data.length > 0 && (
        <ul className="divide-y divide-white/[0.06] rounded-xl border border-white/10 bg-dark-800">
          {products.data.map(p => (
            <li key={p.id}>
              <button onClick={() => setEditing(p)}
                      className="flex w-full items-center gap-4 px-4 py-3 text-left hover:bg-white/[0.03] transition-colors">
                <Thumb image={p.images[0]} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-semibold text-slate-100">{p.name}</span>
                  <span className="block truncate text-xs text-slate-500">
                    {p.prices.map(pr => formatMoney(pr.amount_minor, pr.currency)).join(' · ')}
                  </span>
                </span>
                <span className="text-xs text-slate-400">{p.available} in stock</span>
                {!p.active && <span className="text-xs text-slate-500">Hidden</span>}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

/** A product photo, fetched with the session token (an <img src> cannot carry it). */
function Thumb({ image, size = 40 }: { image?: ProductImage; size?: number }) {
  const [src, setSrc] = useState<string | null>(null)
  useEffect(() => {
    if (!image) return
    let url: string | null = null
    let live = true
    storeApi.imageBlobUrl(image).then(u => { url = u; if (live) setSrc(u) }).catch(() => {})
    return () => { live = false; if (url) URL.revokeObjectURL(url) }
  }, [image])
  return (
    <span className="flex shrink-0 items-center justify-center overflow-hidden rounded-lg bg-dark-700 text-slate-600"
          style={{ width: size, height: size }}>
      {src ? <img src={src} alt="" className="h-full w-full object-cover" /> : <Package className="h-4 w-4" />}
    </span>
  )
}

function ProductForm({ store, product, onDone, onCreated }: {
  store: Store; product: StoreProduct | null; onDone: () => void; onCreated: (p: StoreProduct) => void
}) {
  const qc = useQueryClient()
  const categories = flatten(useCategories(store.id).data ?? [])
  const priceOf = (c: string) => product?.prices.find(p => p.currency === c)
  const [name, setName] = useState(product?.name ?? '')
  const [description, setDescription] = useState(product?.description ?? '')
  const [categoryId, setCategoryId] = useState(product?.category_id ?? '')
  const [unit, setUnit] = useState(product?.unit ?? 'unit')
  const [stock, setStock] = useState(String(product?.stock ?? 0))
  const [active, setActive] = useState(product?.active ?? true)
  const [prices, setPrices] = useState<Record<string, string>>(() => Object.fromEntries(
    store.currencies.map(c => { const p = priceOf(c); return [c, p ? fromMinor(p.amount_minor, c) : ''] }),
  ))
  const otherLocales = store.locales.filter(l => l !== 'en')
  const [i18n, setI18n] = useState<Record<string, { name: string; description: string }>>(() => Object.fromEntries(
    otherLocales.map(l => [l, product?.translations[l] ?? { name: '', description: '' }]),
  ))

  const minor = Object.fromEntries(store.currencies.map(c => [c, prices[c]?.trim() ? toMinor(prices[c], c) : null]))
  const badPrice = store.currencies.filter(c => prices[c]?.trim() && minor[c] === null)
  const stockN = Number(stock)
  const valid = name.trim() && minor[SETTLEMENT_CURRENCY] !== null && badPrice.length === 0
    && Number.isInteger(stockN) && stockN >= 0

  const save = useMutation({
    mutationFn: async () => {
      const saved = await storeApi.saveProduct({
        id: product?.id, store_id: store.id, category_id: categoryId,
        name: name.trim(), description: description.trim(), unit: unit.trim() || 'unit',
        stock: stockN, active, price_minor: minor[SETTLEMENT_CURRENCY] as number,
      })
      await storeApi.setPrices(saved.id, store.currencies
        .filter(c => minor[c] !== null)
        .map(c => ({ currency: c, amount_minor: minor[c] as number })))
      for (const l of otherLocales) {
        const t = i18n[l]
        if (t?.name.trim()) {
          await storeApi.setTranslation(saved.id, l, { name: t.name.trim(), description: t.description.trim() })
        }
      }
      return saved.id
    },
    onSuccess: async id => {
      await qc.invalidateQueries({ queryKey: ['m2m-products', store.id] })
      toast.success('Product saved')
      if (!product) {
        const fresh = qc.getQueryData<StoreProduct[]>(['m2m-products', store.id])?.find(p => p.id === id)
        if (fresh) onCreated(fresh)
      }
    },
    onError: e => toast.error(errorMessage(e)),
  })
  const remove = useMutation({
    mutationFn: () => storeApi.deleteProduct(product!.id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['m2m-products', store.id] }); toast.success('Product deleted'); onDone() },
    onError: e => toast.error(errorMessage(e)),
  })

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-bold text-slate-100">{product ? 'Edit product' : 'New product'}</h3>
        <Button variant="ghost" size="sm" onClick={onDone}><X /> Close</Button>
      </div>

      <form onSubmit={e => { e.preventDefault(); if (valid) save.mutate() }}
            className="space-y-5 rounded-xl border border-white/10 bg-dark-800 p-4 sm:p-6">
        <div className="grid gap-4 sm:grid-cols-2">
          <TextInput label="Name" value={name} onChange={e => setName(e.target.value)} maxLength={200} required />
          <SelectInput label="Category" value={categoryId} onChange={e => setCategoryId(e.target.value)}>
            <option value="">None</option>
            {categories.map(([c, d]) => <option key={c.id} value={c.id}>{'— '.repeat(d)}{c.name}</option>)}
          </SelectInput>
        </div>
        <TextArea label="Description" value={description} onChange={e => setDescription(e.target.value)} maxLength={4000} />
        <div className="grid gap-4 sm:grid-cols-3">
          <TextInput label="Stock" type="number" min={0} step={1} value={stock} onChange={e => setStock(e.target.value)}
                     error={Number.isInteger(stockN) && stockN >= 0 ? undefined : 'A whole number, 0 or more'} />
          <TextInput label="Unit" value={unit} onChange={e => setUnit(e.target.value)} maxLength={40} hint='e.g. "unit", "kg", "pack"' />
          <label className="flex items-center gap-3 self-end pb-2 text-sm text-slate-300">
            <input type="checkbox" checked={active} onChange={e => setActive(e.target.checked)} className="h-4 w-4 accent-sky-500" />
            Visible to buyers
          </label>
        </div>

        <fieldset className="space-y-3">
          <legend className="text-xs font-semibold text-slate-400">Prices</legend>
          <div className="grid gap-4 sm:grid-cols-4">
            {orderCurrencies(store.currencies).map(c => (
              <TextInput key={c} label={c === SETTLEMENT_CURRENCY ? `${c} (required)` : c} inputMode="decimal"
                         value={prices[c] ?? ''} onChange={e => setPrices(p => ({ ...p, [c]: e.target.value }))}
                         placeholder={c === 'JPY' ? '0' : '0.00'}
                         error={badPrice.includes(c) ? 'Not an amount' : undefined}
                         required={c === SETTLEMENT_CURRENCY} />
            ))}
          </div>
          <p className="text-xs text-slate-500">Each currency is the price you set. Nothing is converted between them.</p>
        </fieldset>

        {otherLocales.length > 0 && (
          <fieldset className="space-y-3">
            <legend className="flex items-center gap-2 text-xs font-semibold text-slate-400">
              <Languages className="h-3.5 w-3.5" /> Translations
            </legend>
            <p className="text-xs text-slate-500">Name and description above are the English text. Leave a language empty to show English.</p>
            {otherLocales.map(l => (
              <div key={l} className="grid gap-3 rounded-lg border border-white/[0.06] p-3 sm:grid-cols-2">
                <TextInput label={`${LOCALES.find(x => x.code === l)?.label ?? l} name`} value={i18n[l]?.name ?? ''}
                           onChange={e => setI18n(t => ({ ...t, [l]: { ...t[l], name: e.target.value } }))} maxLength={200} />
                <TextInput label="Description" value={i18n[l]?.description ?? ''}
                           onChange={e => setI18n(t => ({ ...t, [l]: { ...t[l], description: e.target.value } }))} maxLength={4000} />
              </div>
            ))}
          </fieldset>
        )}

        <div className="flex flex-wrap justify-end gap-2">
          <Button type="submit" disabled={!valid || save.isPending}>
            {save.isPending ? <Loader2 className="animate-spin" /> : <Save />} {product ? 'Save' : 'Create product'}
          </Button>
        </div>
      </form>

      {product
        ? <ImagesPanel store={store} product={product} />
        : <p className="text-sm text-slate-500">Photos can be added once the product is created.</p>}

      {product && (
        <div className="flex justify-end">
          <Button variant="destructive" size="sm" disabled={remove.isPending}
                  onClick={() => { if (confirm(`Delete "${product.name}"? This cannot be undone.`)) remove.mutate() }}>
            <Trash2 /> Delete product
          </Button>
        </div>
      )}
    </div>
  )
}

function ImagesPanel({ store, product }: { store: Store; product: StoreProduct }) {
  const qc = useQueryClient()
  const input = useRef<HTMLInputElement>(null)
  const refresh = () => qc.invalidateQueries({ queryKey: ['m2m-products', store.id] })

  const upload = useMutation({
    mutationFn: (file: File) => storeApi.uploadImage(product.id, file),
    onSuccess: () => { refresh(); toast.success('Photo added') },
    onError: e => toast.error(errorMessage(e)),
  })
  const remove = useMutation({
    mutationFn: storeApi.deleteImage,
    onSuccess: () => { refresh(); toast.success('Photo removed') },
    onError: e => toast.error(errorMessage(e)),
  })

  const onPick = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    if (!ACCEPT.split(',').includes(file.type)) { toast.error('A photo is JPEG, PNG or WebP'); return }
    if (file.size > MAX_IMAGE_BYTES) { toast.error('A photo is at most 2 MB'); return }
    upload.mutate(file)
  }

  return (
    <section className="space-y-3 rounded-xl border border-white/10 bg-dark-800 p-4 sm:p-6">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold text-slate-400">Photos ({product.images.length}/8)</h4>
        <input ref={input} type="file" accept={ACCEPT} className="hidden" onChange={onPick} />
        <Button variant="secondary" size="sm" disabled={upload.isPending || product.images.length >= 8}
                onClick={() => input.current?.click()}>
          {upload.isPending ? <Loader2 className="animate-spin" /> : <ImagePlus />} Add photo
        </Button>
      </div>
      <p className="text-xs text-slate-500">JPEG, PNG or WebP, up to 2 MB. Location and camera data are removed on upload.</p>
      {product.images.length > 0 && (
        <ul className="flex flex-wrap gap-3">
          {product.images.map(img => (
            <li key={img.id} className="relative">
              <Thumb image={img} size={96} />
              <button
                aria-label="Remove photo"
                disabled={remove.isPending}
                onClick={() => remove.mutate(img.id)}
                className="absolute -right-2 -top-2 flex h-6 w-6 items-center justify-center rounded-full border border-white/10 bg-dark-700 text-slate-300 hover:text-red-400 transition-colors"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
