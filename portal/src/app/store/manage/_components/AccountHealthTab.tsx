'use client'
// R8.5b: Amazon account-health arithmetic on the seller's own numbers. Nothing is
// fetched from Amazon (no Seller Central access, no SP-API yet): the seller copies
// two figures from the Account Health page and gets the exact volume of on-time,
// defect-free orders that brings each rate back inside Amazon's published target.
import { useState } from 'react'
import { Panel, Row } from '@/components/ui/settings'

type Metric = {
  id: string; name: string; window: string; target: number; higherIsBetter?: boolean
  countLabel: string; badLabel: string
}

const METRICS: Metric[] = [
  { id: 'odr', name: 'Order Defect Rate', window: '60 days', target: 0.01,
    countLabel: 'Orders in the window', badLabel: 'Orders with a defect' },
  { id: 'lsr', name: 'Late Shipment Rate', window: '10 or 30 days', target: 0.04,
    countLabel: 'Seller-fulfilled orders', badLabel: 'Shipped late' },
  { id: 'cr', name: 'Pre-fulfilment Cancel Rate', window: '7 days', target: 0.025,
    countLabel: 'Seller-fulfilled orders', badLabel: 'Cancelled by you' },
  { id: 'vtr', name: 'Valid Tracking Rate', window: '30 days', target: 0.95, higherIsBetter: true,
    countLabel: 'Seller-fulfilled shipments', badLabel: 'With valid tracking' },
]

/** Clean orders still needed so the rate is strictly inside the target; 0 when it already is. */
export function ordersNeeded(m: Metric, total: number, count: number): number {
  if (total <= 0) return 0
  // Snap to 1e-6 first: 0.95 * 100 is 94.999... in binary floating point, which
  // would answer one order short exactly on the boundary.
  const snap = (v: number) => Math.round(v * 1e6) / 1e6
  const x = m.higherIsBetter
    // (good + x) / (total + x) > target  ->  x > (target*total - good) / (1 - target)
    ? snap((m.target * total - count) / (1 - m.target))
    // bad / (total + x) < target  ->  x > bad/target - total
    : snap(count / m.target - total)
  return x < 0 ? 0 : Math.floor(x) + 1
}

const pct = (v: number) => `${(v * 100).toFixed(2)}%`

function MetricRow({ m }: { m: Metric }) {
  const [total, setTotal] = useState('')
  const [count, setCount] = useState('')
  const t = Number(total), c = Number(count)
  const valid = total !== '' && count !== '' && Number.isInteger(t) && Number.isInteger(c) && t > 0 && c >= 0 && c <= t
  const rate = valid ? c / t : 0
  const ok = valid && (m.higherIsBetter ? rate > m.target : rate < m.target)
  const need = valid ? ordersNeeded(m, t, c) : 0
  const field = 'input w-full'

  return (
    <Row label={m.name}
         help={`Amazon's target: ${m.higherIsBetter ? 'above' : 'under'} ${pct(m.target)}, measured over ${m.window}.`}>
      <div className="space-y-2">
        <div className="grid grid-cols-2 gap-2">
          <label className="text-xs text-slate-400">{m.countLabel}
            <input className={field} inputMode="numeric" value={total} onChange={e => setTotal(e.target.value.replace(/\D/g, ''))} />
          </label>
          <label className="text-xs text-slate-400">{m.badLabel}
            <input className={field} inputMode="numeric" value={count} onChange={e => setCount(e.target.value.replace(/\D/g, ''))} />
          </label>
        </div>
        {valid && (
          <p className={`text-sm ${ok ? 'text-emerald-300' : 'text-amber-200'}`} role="status">
            Now {pct(rate)} — {ok ? 'inside the target.'
              : `${need.toLocaleString('en-US')} more ${m.higherIsBetter ? 'shipments with valid tracking' : 'on-time, defect-free orders'} in the window bring it to ${pct(m.higherIsBetter ? (c + need) / (t + need) : c / (t + need))}.`}
          </p>
        )}
        {total !== '' && count !== '' && !valid && (
          <p className="text-xs text-red-400" role="alert">Whole numbers, and the second cannot be larger than the first.</p>
        )}
      </div>
    </Row>
  )
}

export function AccountHealthTab() {
  return (
    <div className="space-y-5">
      <Panel title="Amazon account health">
        <p className="px-5 py-4 text-sm text-slate-300">
          Copy the figures from Seller Central → Performance → Account Health. We do the arithmetic here, in your
          browser; nothing is sent to us or read from Amazon.
        </p>
        {METRICS.map(m => <MetricRow key={m.id} m={m} />)}
      </Panel>
      <p className="text-xs text-slate-500">
        This is arithmetic on your numbers, not a prediction of Amazon&apos;s decisions. Old defects also leave the
        window as it rolls forward, and Amazon may treat a defect differently from how it is counted here. The targets
        are those Amazon publishes for professional sellers.
      </p>
    </div>
  )
}
