'use client'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { Loader2, Plus, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui'
import { errorMessage, formatMoney, orderCurrencies, storeApi, toMinor, type Store } from '@/lib/storeApi'
import { EmptyState, SelectInput, TextInput } from './fields'

export function ShippingTab({ store }: { store: Store }) {
  const qc = useQueryClient()
  const zones = useQuery({ queryKey: ['m2m-zones', store.id], queryFn: () => storeApi.zones(store.id) })
  const [name, setName] = useState('')
  const [countries, setCountries] = useState('')
  const [currency, setCurrency] = useState(store.default_currency)
  const [rate, setRate] = useState('')
  const [freeOver, setFreeOver] = useState('')
  const [duty, setDuty] = useState('0')
  const [minDays, setMinDays] = useState('2')
  const [maxDays, setMaxDays] = useState('7')

  const codes = countries.split(/[\s,]+/).map(c => c.trim().toUpperCase()).filter(Boolean)
  const badCodes = codes.filter(c => c !== '*' && !/^[A-Z]{2}$/.test(c))
  const rateMinor = toMinor(rate, currency)
  const freeMinor = freeOver.trim() ? toMinor(freeOver, currency) : null
  const dutyPct = Number(duty.replace(',', '.'))
  const dutyOk = Number.isFinite(dutyPct) && dutyPct >= 0 && dutyPct <= 100
  const daysOk = Number(minDays) >= 0 && Number(maxDays) >= Number(minDays) && Number(maxDays) <= 365
  const valid = name.trim() && codes.length > 0 && badCodes.length === 0 && rateMinor !== null
    && (!freeOver.trim() || freeMinor !== null) && dutyOk && daysOk

  const refresh = () => qc.invalidateQueries({ queryKey: ['m2m-zones', store.id] })
  const create = useMutation({
    mutationFn: () => storeApi.createZone(store.id, {
      name: name.trim(), countries: codes, currency,
      rate_minor: rateMinor ?? 0, free_over_minor: freeMinor,
      duty_estimate_bps: Math.round(dutyPct * 100),
      min_days: Number(minDays), max_days: Number(maxDays),
    }),
    onSuccess: () => {
      setName(''); setCountries(''); setRate(''); setFreeOver(''); setDuty('0')
      refresh(); toast.success('Shipping zone added')
    },
    onError: e => toast.error(errorMessage(e)),
  })
  const remove = useMutation({
    mutationFn: storeApi.deleteZone,
    onSuccess: () => { refresh(); toast.success('Shipping zone deleted') },
    onError: e => toast.error(errorMessage(e)),
  })

  return (
    <div className="space-y-6">
      <form
        onSubmit={e => { e.preventDefault(); if (valid) create.mutate() }}
        className="space-y-4 rounded-xl border border-white/10 bg-dark-800 p-4 sm:p-6"
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <TextInput label="Zone name" value={name} onChange={e => setName(e.target.value)} maxLength={120} required />
          <TextInput
            label="Countries"
            value={countries}
            onChange={e => setCountries(e.target.value)}
            hint='Two-letter codes, e.g. "DE, AT, CH". Use * for the rest of the world.'
            error={badCodes.length ? `Not a country code: ${badCodes.join(', ')}` : undefined}
            spellCheck={false}
            required
          />
        </div>
        <div className="grid gap-4 sm:grid-cols-4">
          <SelectInput label="Currency" value={currency} onChange={e => setCurrency(e.target.value)}>
            {orderCurrencies(store.currencies).map(c => <option key={c} value={c}>{c}</option>)}
          </SelectInput>
          <TextInput label="Rate" inputMode="decimal" value={rate} onChange={e => setRate(e.target.value)}
                     error={rate && rateMinor === null ? 'Not an amount' : undefined} required />
          <TextInput label="Free over" inputMode="decimal" value={freeOver} onChange={e => setFreeOver(e.target.value)}
                     hint="Optional" error={freeOver && freeMinor === null ? 'Not an amount' : undefined} />
          <TextInput label="Duty estimate, %" inputMode="decimal" value={duty} onChange={e => setDuty(e.target.value)}
                     hint="Your own rate; buyers see it as an estimate."
                     error={dutyOk ? undefined : 'Between 0 and 100'} />
        </div>
        <div className="grid gap-4 sm:grid-cols-4">
          <TextInput label="Delivery from, days" type="number" min={0} max={365} value={minDays}
                     onChange={e => setMinDays(e.target.value)} />
          <TextInput label="Delivery to, days" type="number" min={0} max={365} value={maxDays}
                     onChange={e => setMaxDays(e.target.value)} error={daysOk ? undefined : 'Must not be before "from"'} />
        </div>
        <div className="flex justify-end">
          <Button type="submit" disabled={!valid || create.isPending}>
            {create.isPending ? <Loader2 className="animate-spin" /> : <Plus />} Add zone
          </Button>
        </div>
      </form>

      {zones.isError && <p className="text-sm text-red-400" role="alert">{errorMessage(zones.error)}</p>}
      {zones.data && zones.data.length === 0 && (
        <EmptyState title="No shipping zones"
                    body="Buyers outside every zone cannot get a shipping quote. Add a * zone to cover everywhere else." />
      )}
      {zones.data && zones.data.length > 0 && (
        <ul className="divide-y divide-white/[0.06] rounded-xl border border-white/10 bg-dark-800">
          {zones.data.map(z => (
            <li key={z.id} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-3">
              <span className="min-w-0 flex-1">
                <span className="block text-sm font-semibold text-slate-100">{z.name}</span>
                <span className="block font-mono text-xs text-slate-500">{z.countries.join(' ')}</span>
              </span>
              <span className="text-sm text-slate-300">{formatMoney(z.rate_minor, z.currency)}</span>
              {z.free_over_minor !== null && (
                <span className="text-xs text-slate-500">free over {formatMoney(z.free_over_minor, z.currency)}</span>
              )}
              <span className="text-xs text-slate-500">{z.min_days}–{z.max_days} days</span>
              {z.duty_estimate_bps > 0 && (
                <span className="text-xs text-slate-500">duty ≈ {(z.duty_estimate_bps / 100).toFixed(2)}%</span>
              )}
              <Button variant="ghost" size="icon-sm" aria-label={`Delete ${z.name}`} disabled={remove.isPending}
                      onClick={() => { if (confirm(`Delete zone "${z.name}"?`)) remove.mutate(z.id) }}>
                <Trash2 />
              </Button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
