/**
 * portal/src/lib/storefront/units.ts
 * Metric/imperial display. The seller's own unit is always what is sold and
 * priced; the other system is shown beside it, marked approximate.
 */

export type UnitSystem = 'metric' | 'imperial'

// How many metric units make one imperial unit.
const PAIRS: { metric: string; imperial: string; metricPerImperial: number }[] = [
  { metric: 'kg', imperial: 'lb', metricPerImperial: 0.45359237 },
  { metric: 'g', imperial: 'oz', metricPerImperial: 28.349523125 },
  { metric: 'l', imperial: 'gal', metricPerImperial: 3.785411784 },
  { metric: 'ml', imperial: 'fl oz', metricPerImperial: 29.5735295625 },
  { metric: 'km', imperial: 'mi', metricPerImperial: 1.609344 },
  { metric: 'm', imperial: 'ft', metricPerImperial: 0.3048 },
  { metric: 'cm', imperial: 'in', metricPerImperial: 2.54 },
  { metric: 'm2', imperial: 'sq ft', metricPerImperial: 0.09290304 },
]

/**
 * The price per unit in the buyer's other system, or null when the seller's
 * unit is already in that system or has no counterpart (e.g. "piece").
 * Display only: the result is rounded and must be shown as approximate.
 */
export function convertUnitPrice(
  amountMinor: number, unit: string, system: UnitSystem,
): { amountMinor: number; unit: string } | null {
  const u = unit.trim().toLowerCase()
  for (const p of PAIRS) {
    if (system === 'imperial' && u === p.metric) {
      return { amountMinor: Math.round(amountMinor * p.metricPerImperial), unit: p.imperial }
    }
    if (system === 'metric' && u === p.imperial) {
      return { amountMinor: Math.round(amountMinor / p.metricPerImperial), unit: p.metric }
    }
  }
  return null
}
