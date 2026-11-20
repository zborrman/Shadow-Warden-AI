'use client'
import { useState } from 'react'
import { ArrowLeft, FolderTree, Inbox, Package, Settings2, Truck, Users } from 'lucide-react'
import type { Store } from '@/lib/storeApi'
import { SectionNav } from '@/components/ui/settings'
import { ProductsTab } from './ProductsTab'
import { CategoriesTab } from './CategoriesTab'
import { ShippingTab } from './ShippingTab'
import { SettingsTab } from './SettingsTab'
import { OrdersTab } from './OrdersTab'
import { CustomersTab } from './CustomersTab'

type TabId = 'products' | 'categories' | 'orders' | 'customers' | 'shipping' | 'settings'

const GROUPS: { group: string; items: { id: TabId; label: string; icon: React.ElementType }[] }[] = [
  { group: 'Catalog', items: [
    { id: 'products',   label: 'Products',   icon: Package },
    { id: 'categories', label: 'Categories', icon: FolderTree },
  ] },
  { group: 'Sales', items: [
    { id: 'orders',    label: 'Orders',    icon: Inbox },
    { id: 'customers', label: 'Customers', icon: Users },
  ] },
  { group: 'Store', items: [
    { id: 'shipping', label: 'Shipping', icon: Truck },
    { id: 'settings', label: 'Settings', icon: Settings2 },
  ] },
]

export function StoreEditor({ store, onBack }: { store: Store; onBack: () => void }) {
  const [tab, setTab] = useState<TabId>('products')
  const title = GROUPS.flatMap(g => g.items).find(i => i.id === tab)?.label

  return (
    <div className="mx-auto w-full max-w-6xl space-y-5 p-4 sm:p-6">
      <div className="flex flex-wrap items-center gap-3">
        <button
          onClick={onBack}
          className="inline-flex items-center gap-1.5 text-sm text-slate-400 transition-colors hover:text-slate-200"
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

      <div className="flex flex-col gap-6 md:flex-row">
        <SectionNav label="Store sections" groups={GROUPS} current={tab} onSelect={setTab} />
        <div className="min-w-0 flex-1 space-y-4">
          <h2 className="text-lg font-semibold text-slate-100">{title}</h2>
          {tab === 'products'   && <ProductsTab store={store} />}
          {tab === 'orders'     && <OrdersTab store={store} />}
          {tab === 'customers'  && <CustomersTab store={store} />}
          {tab === 'categories' && <CategoriesTab store={store} />}
          {tab === 'shipping'   && <ShippingTab store={store} />}
          {tab === 'settings'   && <SettingsTab store={store} onDeleted={onBack} />}
        </div>
      </div>
    </div>
  )
}
