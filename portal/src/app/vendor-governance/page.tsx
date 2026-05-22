'use client'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Building2, Plus, FileText, AlertTriangle, CheckCircle2, Clock, Shield } from 'lucide-react'
import clsx from 'clsx'
import { TopBar } from '@/components/layout/TopBar'
import { vendorApi, type Vendor } from '@/lib/smbApi'

const RISK_COLOR: Record<string, string> = {
  LOW:      'bg-green-500/15 text-green-400',
  MEDIUM:   'bg-yellow-500/15 text-yellow-400',
  HIGH:     'bg-orange-500/15 text-orange-400',
  CRITICAL: 'bg-red-500/15 text-red-400',
}

export default function VendorGovernancePage() {
  const qc       = useQueryClient()
  const [tenant, setTenant] = useState('default')
  const [showAdd, setShowAdd] = useState(false)
  const [form, setForm] = useState({ display_name: '', website: '', provider_type: 'LLM' })
  const [err, setErr] = useState<string | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['vendors', tenant],
    queryFn:  () => vendorApi.list(tenant),
  })

  const { data: expiring } = useQuery({
    queryKey: ['expiring-dpas', tenant],
    queryFn:  () => vendorApi.expiring(tenant),
  })

  const create = useMutation({
    mutationFn: () => vendorApi.create({ tenant_id: tenant, ...form }),
    onSuccess:  () => {
      qc.invalidateQueries({ queryKey: ['vendors', tenant] })
      setShowAdd(false)
      setForm({ display_name: '', website: '', provider_type: 'LLM' })
      setErr(null)
    },
    onError: (e: Error) => setErr(e.message),
  })

  const vendors = data?.vendors ?? []
  const expiringDpas = expiring?.dpas ?? []

  return (
    <div className="flex flex-col h-screen">
      <TopBar title="Vendor Governance" />
      <div className="flex-1 overflow-y-auto p-6 space-y-6">

        {/* Tenant selector */}
        <div className="flex items-center gap-3 flex-wrap">
          <label className="text-xs text-slate-400">Tenant</label>
          <input
            className="input w-44 text-sm"
            value={tenant}
            onChange={e => setTenant(e.target.value)}
            placeholder="Tenant ID"
          />
          <button onClick={() => setShowAdd(v => !v)} className="btn-primary text-sm px-4 py-2 ml-auto">
            <Plus className="w-4 h-4" /> Add Vendor
          </button>
        </div>

        {/* Expiry warnings */}
        {expiringDpas.length > 0 && (
          <div className="flex items-start gap-3 p-4 rounded-xl bg-yellow-500/10 border border-yellow-500/20 text-yellow-300 text-sm">
            <Clock className="w-4 h-4 mt-0.5 shrink-0" />
            <span>{expiringDpas.length} DPA{expiringDpas.length > 1 ? 's' : ''} expiring within 30 days — review and renew.</span>
          </div>
        )}

        {/* Add form */}
        {showAdd && (
          <div className="card p-5 space-y-3">
            <h3 className="text-sm font-semibold text-white">Register AI Vendor</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <input className="input" placeholder="Vendor name" value={form.display_name}
                onChange={e => setForm(f => ({ ...f, display_name: e.target.value }))} />
              <input className="input" placeholder="Website" value={form.website}
                onChange={e => setForm(f => ({ ...f, website: e.target.value }))} />
            </div>
            <select className="input" value={form.provider_type}
              onChange={e => setForm(f => ({ ...f, provider_type: e.target.value }))}>
              {['LLM', 'EMBEDDING', 'TOOL', 'OTHER'].map(t => <option key={t} value={t}>{t}</option>)}
            </select>
            {err && <p className="text-xs text-red-400">{err}</p>}
            <div className="flex gap-2 justify-end">
              <button onClick={() => setShowAdd(false)} className="btn-secondary text-sm px-3 py-1.5">Cancel</button>
              <button onClick={() => create.mutate()} disabled={!form.display_name || create.isPending}
                className="btn-primary text-sm px-4 py-1.5">
                {create.isPending ? 'Adding…' : 'Register'}
              </button>
            </div>
          </div>
        )}

        {/* Vendor table */}
        <div className="card overflow-hidden">
          <div className="px-4 py-3 border-b border-white/[0.06] flex items-center gap-2">
            <Building2 className="w-4 h-4 text-blue-400" />
            <span className="text-sm font-medium text-white">{vendors.length} AI Vendors</span>
          </div>
          {isLoading ? (
            <p className="text-center py-12 text-slate-500 text-sm">Loading…</p>
          ) : vendors.length === 0 ? (
            <div className="text-center py-12">
              <Shield className="w-8 h-8 text-slate-600 mx-auto mb-3" />
              <p className="text-sm text-slate-500">No vendors registered yet.</p>
            </div>
          ) : (
            <div className="divide-y divide-white/[0.04]">
              {vendors.map((v: Vendor) => (
                <div key={v.vendor_id} className="flex items-center gap-4 px-4 py-3 hover:bg-white/[0.02]">
                  <div className="w-9 h-9 rounded-xl bg-dark-700 flex items-center justify-center text-sm font-bold text-blue-400 shrink-0">
                    {v.display_name[0]?.toUpperCase()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-white truncate">{v.display_name}</p>
                    <p className="text-xs text-slate-500 truncate">{v.website || v.provider_type}</p>
                  </div>
                  <span className={clsx('text-[11px] font-medium px-2 py-0.5 rounded-full', RISK_COLOR[v.risk_tier] ?? 'bg-slate-500/15 text-slate-400')}>
                    {v.risk_tier}
                  </span>
                  <span className={clsx('text-[11px] px-2 py-0.5 rounded-full',
                    v.status === 'active' ? 'bg-green-500/15 text-green-400' : 'bg-slate-500/15 text-slate-400')}>
                    {v.status}
                  </span>
                  <span className="text-[11px] text-slate-500 font-mono shrink-0">{v.provider_type}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* DPA expiry banner */}
        {expiringDpas.length > 0 && (
          <div className="card p-4 space-y-2">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <FileText className="w-4 h-4 text-yellow-400" /> Expiring DPAs
            </h3>
            {expiringDpas.map(d => (
              <div key={d.dpa_id} className="flex items-center justify-between px-3 py-2 rounded-lg bg-yellow-500/5 border border-yellow-500/15">
                <div>
                  <p className="text-xs text-white">{d.dpa_type}</p>
                  <p className="text-[11px] text-slate-400">Vendor: {d.vendor_id.slice(0, 8)}…</p>
                </div>
                <div className="flex items-center gap-2 text-xs">
                  <Clock className="w-3 h-3 text-yellow-400" />
                  <span className="text-yellow-400">{d.expires_at?.slice(0, 10) ?? '—'}</span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Compliance tip */}
        <div className="flex items-start gap-3 p-4 rounded-xl bg-green-500/10 border border-green-500/20 text-green-300 text-sm">
          <CheckCircle2 className="w-4 h-4 mt-0.5 shrink-0" />
          <span>All DPAs processed by Shadow Warden are GDPR Art. 28 compliant and logged in the STIX audit chain.</span>
        </div>

      </div>
    </div>
  )
}
