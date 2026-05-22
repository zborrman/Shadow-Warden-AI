'use client'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { DollarSign, Plus, TrendingUp, Building2, BarChart3 } from 'lucide-react'
import clsx from 'clsx'
import { TopBar } from '@/components/layout/TopBar'
import { costApi } from '@/lib/smbApi'

const COST_TYPES = ['api_usage', 'audit', 'compliance', 'incident'] as const
const DEPARTMENTS = ['engineering', 'finance', 'hr', 'marketing', 'operations', 'default']

function currentMonth() {
  return new Date().toISOString().slice(0, 7)
}

export default function CostAllocationPage() {
  const qc = useQueryClient()
  const [tenant, setTenant] = useState('default')
  const [month, setMonth] = useState(currentMonth())
  const [showAdd, setShowAdd] = useState(false)
  const [form, setForm] = useState({
    department: 'default',
    project: '',
    cost_type: 'api_usage',
    amount_usd: '',
    vendor_id: '',
    notes: '',
  })

  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ['cost-summary', tenant, month],
    queryFn:  () => costApi.summary(tenant, month),
  })

  const { data: depts, isLoading: deptsLoading } = useQuery({
    queryKey: ['cost-departments', tenant],
    queryFn:  () => costApi.departments(tenant),
  })

  const record = useMutation({
    mutationFn: () => costApi.record({
      tenant_id:   tenant,
      department:  form.department,
      project:     form.project,
      cost_type:   form.cost_type,
      amount_usd:  parseFloat(form.amount_usd || '0'),
      vendor_id:   form.vendor_id,
      notes:       form.notes,
      period_month: month,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cost-summary', tenant, month] })
      qc.invalidateQueries({ queryKey: ['cost-departments', tenant] })
      setShowAdd(false)
      setForm({ department: 'default', project: '', cost_type: 'api_usage', amount_usd: '', vendor_id: '', notes: '' })
    },
  })

  const sum = summary as Record<string, unknown> | undefined
  const totalUsd = (sum?.total_usd as number | undefined) ?? 0
  const byDept   = (sum?.by_department as Record<string, number> | undefined) ?? {}
  const byVendor = (sum?.by_vendor as Record<string, number> | undefined) ?? {}

  const deptList = depts?.departments ?? []
  const maxSpend = Math.max(...deptList.map((d: { total_usd: number }) => d.total_usd), 1)

  return (
    <div className="flex flex-col h-screen">
      <TopBar title="AI Cost Allocation" />
      <div className="flex-1 overflow-y-auto p-6 space-y-5">

        {/* Controls */}
        <div className="flex items-center gap-3 flex-wrap">
          <label className="text-xs text-slate-400">Tenant</label>
          <input className="input w-40 text-sm" value={tenant} onChange={e => setTenant(e.target.value)} />
          <label className="text-xs text-slate-400">Month</label>
          <input className="input w-36 text-sm" type="month" value={month} onChange={e => setMonth(e.target.value)} />
          <button onClick={() => setShowAdd(v => !v)} className="btn-primary text-sm px-4 py-2 ml-auto">
            <Plus className="w-4 h-4" /> Record Cost
          </button>
        </div>

        {/* Summary cards */}
        {!summaryLoading && sum && (
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
            <div className="card p-4 flex items-start gap-3 md:col-span-1">
              <DollarSign className="w-5 h-5 mt-0.5 text-green-400 shrink-0" />
              <div>
                <p className="text-xs text-slate-400">Total Spend</p>
                <p className="text-2xl font-bold mt-1 text-green-400">${totalUsd.toFixed(2)}</p>
                <p className="text-[11px] text-slate-500 mt-0.5">{month}</p>
              </div>
            </div>
            <div className="card p-4 flex items-start gap-3">
              <Building2 className="w-5 h-5 mt-0.5 text-blue-400 shrink-0" />
              <div>
                <p className="text-xs text-slate-400">Departments</p>
                <p className="text-2xl font-bold mt-1 text-blue-400">{Object.keys(byDept).length}</p>
              </div>
            </div>
            <div className="card p-4 flex items-start gap-3">
              <BarChart3 className="w-5 h-5 mt-0.5 text-purple-400 shrink-0" />
              <div>
                <p className="text-xs text-slate-400">Vendors</p>
                <p className="text-2xl font-bold mt-1 text-purple-400">{Object.keys(byVendor).length}</p>
              </div>
            </div>
          </div>
        )}

        {/* Add form */}
        {showAdd && (
          <div className="card p-5 space-y-3">
            <h3 className="text-sm font-semibold text-white">Record AI Cost</h3>
            <div className="grid grid-cols-2 gap-3">
              <select className="input" value={form.department}
                onChange={e => setForm(f => ({ ...f, department: e.target.value }))}>
                {DEPARTMENTS.map(d => <option key={d} value={d}>{d}</option>)}
              </select>
              <select className="input" value={form.cost_type}
                onChange={e => setForm(f => ({ ...f, cost_type: e.target.value }))}>
                {COST_TYPES.map(t => <option key={t} value={t}>{t.replace('_', ' ')}</option>)}
              </select>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-slate-400 mb-1 block">Amount (USD)</label>
                <input className="input" type="number" step="0.01" min="0" placeholder="0.00"
                  value={form.amount_usd} onChange={e => setForm(f => ({ ...f, amount_usd: e.target.value }))} />
              </div>
              <input className="input self-end" placeholder="Project (optional)"
                value={form.project} onChange={e => setForm(f => ({ ...f, project: e.target.value }))} />
            </div>
            <input className="input" placeholder="Vendor ID (optional)"
              value={form.vendor_id} onChange={e => setForm(f => ({ ...f, vendor_id: e.target.value }))} />
            <input className="input" placeholder="Notes (optional)"
              value={form.notes} onChange={e => setForm(f => ({ ...f, notes: e.target.value }))} />
            <div className="flex gap-2 justify-end">
              <button onClick={() => setShowAdd(false)} className="btn-secondary text-sm px-3 py-1.5">Cancel</button>
              <button onClick={() => record.mutate()} disabled={!form.amount_usd || record.isPending}
                className="btn-primary text-sm px-4 py-1.5">
                {record.isPending ? 'Saving…' : 'Record'}
              </button>
            </div>
          </div>
        )}

        {/* Department breakdown bar chart */}
        <div className="card overflow-hidden">
          <div className="px-4 py-3 border-b border-white/[0.06] flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-blue-400" />
            <span className="text-sm font-medium text-white">Department Spend (rolling 3 months)</span>
          </div>
          {deptsLoading ? (
            <p className="text-center py-12 text-slate-500 text-sm">Loading…</p>
          ) : deptList.length === 0 ? (
            <div className="text-center py-12">
              <DollarSign className="w-8 h-8 text-slate-600 mx-auto mb-3" />
              <p className="text-sm text-slate-500">No cost data recorded yet.</p>
            </div>
          ) : (
            <div className="p-4 space-y-3">
              {deptList.map((d: { department: string; total_usd: number }) => (
                <div key={d.department}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-slate-300 capitalize">{d.department}</span>
                    <span className="text-slate-400 font-mono">${d.total_usd.toFixed(2)}</span>
                  </div>
                  <div className="h-2 rounded-full bg-dark-700">
                    <div
                      className="h-2 rounded-full bg-blue-500 transition-all"
                      style={{ width: `${(d.total_usd / maxSpend) * 100}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* By-vendor breakdown */}
        {Object.keys(byVendor).length > 0 && (
          <div className="card p-4 space-y-2">
            <p className="text-sm font-medium text-white mb-3">Vendor Breakdown — {month}</p>
            {Object.entries(byVendor).map(([vid, amt]) => (
              <div key={vid} className="flex items-center justify-between py-1.5 border-b border-white/[0.04] last:border-0">
                <span className="text-xs text-slate-400 font-mono truncate max-w-[60%]">{vid || '(unassigned)'}</span>
                <span className="text-xs text-white font-medium">${(amt as number).toFixed(2)}</span>
              </div>
            ))}
          </div>
        )}

        <p className="text-[11px] text-slate-600">
          Cost allocations are indexed by UECIID and linked to the SEP audit trail for compliance reporting.
        </p>
      </div>
    </div>
  )
}
