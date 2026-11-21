'use client'
import { useEffect, useState } from 'react'
import { ShieldAlert, ShieldCheck } from 'lucide-react'
import { storeApi } from '@/lib/storeApi'

const LABEL: Record<string, string> = {
  pesticide_claim: 'Pesticide claim',
  disease_claim: 'Medical claim',
  environmental_claim: 'Green claim',
  absolute_claim: 'Absolute claim',
}

type Finding = Awaited<ReturnType<typeof storeApi.lintListing>>[number]

/** Live check of the product's own text, before it reaches a marketplace. Advice only: nothing is blocked. */
export function ListingCheck({ name, description }: { name: string; description: string }) {
  const [found, setFound] = useState<Finding[] | null>(null)
  useEffect(() => {
    if (!name.trim() && !description.trim()) { setFound(null); return }
    const t = setTimeout(() => {
      storeApi.lintListing({ name, description }).then(setFound).catch(() => setFound(null))
    }, 450)
    return () => clearTimeout(t)
  }, [name, description])

  if (found === null) return null
  if (found.length === 0) {
    return (
      <p className="flex items-center gap-2 text-xs text-emerald-300">
        <ShieldCheck className="h-4 w-4" aria-hidden /> Listing check: no claims that need proof or a registration.
      </p>
    )
  }
  return (
    <div className="rounded-lg border border-amber-400/30 bg-amber-400/[0.06] p-3" role="status">
      <p className="mb-2 flex items-center gap-2 text-sm font-semibold text-amber-200">
        <ShieldAlert className="h-4 w-4" aria-hidden /> Listing check: {found.length} {found.length === 1 ? 'claim' : 'claims'} to review
      </p>
      <ul className="space-y-1.5 text-xs text-slate-300">
        {found.map(f => (
          <li key={`${f.field}-${f.term}`}>
            <span className="font-semibold text-amber-100">“{f.term}”</span>
            <span className="text-slate-400"> · {LABEL[f.category] ?? f.category} in the {f.field}</span>
            {f.suggestion && <span> — try “{f.suggestion}”</span>}
            <span className="block text-slate-500">{f.basis}</span>
          </li>
        ))}
      </ul>
      <p className="mt-2 text-[11px] text-slate-500">
        Based on public rules (EPA, FDA, FTC, EU), not on any marketplace’s private filter. Advice only: your listing is saved as written.
      </p>
    </div>
  )
}
