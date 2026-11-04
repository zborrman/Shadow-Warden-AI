'use client'
import { useState } from 'react'
import { ArrowLeft, FolderTree, Package, Settings2, Truck } from 'lucide-react'
import clsx from 'clsx'
import type { Store } from '@/lib/storeApi'
import { ProductsTab } from './ProductsTab'
import { CategoriesTab } from './CategoriesTab'
import { ShippingTab } from './ShippingTab'
import { SettingsTab } from './SettingsTab'

const TABS = [
  { id: 'products',   label: 'Products',   icon: Package    },
  { id: 'categories', label: 'Categories', icon: FolderTree },
  { id: 'shipping',   label: 'Shipping',   icon: Truck      },
  { id: 'settings',   label: 'Settings',   icon: Settings2  },
] as const
type TabId = typeof TABS[number]['id']

export function StoreEditor({ store, onBack }: { store: Store; onBack: () => void }) {
  const [tab, setTab] = useState<TabId>('products')

  return (
    <div className="mx-auto w-full max-w-5xl p-4 sm:p-6 space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <button
          onClick={onBack}
          className="inline-flex items-center gap-1.5 text-sm text-slate-400 hover:text-slate-200 transition-colors"
        >
          <ArrowLeft className="h-4 w-4" /> All stores
        </button>
        <span className="font-mono text-xs text-slate-500">/s/{store.slug}</span>
        {!store.active && (
          <span className="rounded-md border border-amber-400/30 bg-amber-400/10 px-2 py-0.5 text-xs text-amber-300">
            Hidden from buyers
          </span>
        )}
      </div>

      <div role="tablist" aria-label="Store sections" className="flex gap-1 overflow-x-auto border-b border-white/10">
        {TABS.map(t => (
          <button
            key={t.id}
            role="tab"
            id={`tab-${t.id}`}
            aria-selected={tab === t.id}
            aria-controls={`panel-${t.id}`}
            onClick={() => setTab(t.id)}
            className={clsx(
              '-mb-px inline-flex items-center gap-2 whitespace-nowrap border-b-2 px-3 py-2.5 text-sm font-medium transition-colors',
              tab === t.id ? 'border-brand-500 text-slate-100' : 'border-transparent text-slate-500 hover:text-slate-300',
            )}
          >
            <t.icon className="h-4 w-4" /> {t.label}
          </button>
        ))}
      </div>

      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {tab === 'products'   && <ProductsTab store={store} />}
        {tab === 'categories' && <CategoriesTab store={store} />}
        {tab === 'shipping'   && <ShippingTab store={store} />}
        {tab === 'settings'   && <SettingsTab store={store} onDeleted={onBack} />}
      </div>
    </div>
  )
}
