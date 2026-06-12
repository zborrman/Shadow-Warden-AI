'use client'
/**
 * /community-hub/agentic-commerce — M2M Agentic Commerce Hub
 * 5 tabs: Agents · Assets · Trading Floor · Escrow · Imported
 */

import { useState, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Bot, Package, TrendingUp, Lock, Download,
  Plus, X, ChevronRight, RefreshCw,
  CheckCircle2, Clock, AlertTriangle, XCircle,
  DollarSign, Tag, ArrowLeftRight, Shield,
  Zap, Star,
} from 'lucide-react'
import clsx from 'clsx'
import toast from 'react-hot-toast'
import {
  agenticCommerceApi,
  type MktAgent, type MktAsset, type MktListing,
  type MktEscrow, type MktPurchase, type MktNegotiation,
} from '@/lib/agenticCommerceApi'

// ── Helpers ───────────────────────────────────────────────────────────────────

function shortDid(did: string) {
  return did.length > 22 ? `${did.slice(0, 14)}…${did.slice(-6)}` : did
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: '2-digit' })
}

function fmtUsd(n: number) {
  return `$${n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
}

const ASSET_COLOR: Record<string, string> = {
  rule:    'bg-violet-500/20 text-violet-300 border-violet-500/30',
  model:   'bg-blue-500/20 text-blue-300 border-blue-500/30',
  signals: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
}

const ESCROW_COLOR: Record<string, string> = {
  pending_deposit: 'text-slate-400',
  funded:          'text-blue-400',
  delivered:       'text-amber-400',
  confirmed:       'text-emerald-400',
  disputed:        'text-red-400',
  resolved_buyer:  'text-emerald-300',
  resolved_seller: 'text-blue-300',
  cancelled:       'text-slate-500',
}

const ESCROW_ICON: Record<string, React.ElementType> = {
  pending_deposit: Clock,
  funded:          DollarSign,
  delivered:       Package,
  confirmed:       CheckCircle2,
  disputed:        AlertTriangle,
  resolved_buyer:  CheckCircle2,
  resolved_seller: CheckCircle2,
  cancelled:       XCircle,
}

// ── Tab definitions ───────────────────────────────────────────────────────────

type TabId = 'agents' | 'assets' | 'trading' | 'escrow' | 'imported'

const TABS: { id: TabId; label: string; icon: React.ElementType }[] = [
  { id: 'agents',   label: 'Agents',        icon: Bot          },
  { id: 'assets',   label: 'Assets',        icon: Package      },
  { id: 'trading',  label: 'Trading Floor', icon: TrendingUp   },
  { id: 'escrow',   label: 'Escrow',        icon: Lock         },
  { id: 'imported', label: 'Imported',      icon: Download     },
]

// ── Modal wrapper ─────────────────────────────────────────────────────────────

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="relative w-full max-w-lg rounded-2xl border border-white/10 bg-[#0d1220] shadow-2xl">
        <div className="flex items-center justify-between border-b border-white/8 px-6 py-4">
          <h3 className="text-sm font-semibold text-white">{title}</h3>
          <button onClick={onClose} className="rounded-lg p-1 text-slate-400 hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="px-6 py-5">{children}</div>
      </div>
    </div>
  )
}

// ── Field helper ──────────────────────────────────────────────────────────────

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <label className="block text-xs font-medium text-slate-400">{label}</label>
      {children}
    </div>
  )
}

const inputCls = 'w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-white placeholder:text-slate-600 focus:border-indigo-500/60 focus:outline-none'
const btnPrimary = 'flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-500 transition-colors disabled:opacity-50'
const btnSecondary = 'flex items-center gap-2 rounded-lg border border-white/10 px-3 py-1.5 text-xs text-slate-300 hover:border-white/20 hover:text-white transition-colors'

// ── Agents Tab ────────────────────────────────────────────────────────────────

function AgentsTab({ onAgentCreated }: { onAgentCreated?: (agent: MktAgent) => void }) {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const [form, setForm] = useState({ tenant_id: 'default', community_id: '', public_key: '', capabilities: [] as string[] })

  const { data: agents = [], isLoading } = useQuery({
    queryKey: ['mkt-agents'],
    queryFn:  () => agenticCommerceApi.listAgents().catch(() => [] as MktAgent[]),
  })

  const registerMut = useMutation({
    mutationFn: () => agenticCommerceApi.registerAgent(form),
    onSuccess: (agent) => {
      toast.success('Agent registered')
      qc.invalidateQueries({ queryKey: ['mkt-agents'] })
      qc.invalidateQueries({ queryKey: ['mkt-stats'] })
      setShowModal(false)
      onAgentCreated?.(agent)
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const revokeMut = useMutation({
    mutationFn: (agentId: string) =>
      agenticCommerceApi.updateCapabilities(agentId, { tenant_id: 'default', capabilities: [] }),
    onSuccess: () => { toast.success('Agent capabilities cleared'); qc.invalidateQueries({ queryKey: ['mkt-agents'] }) },
    onError:   (e: Error) => toast.error(e.message),
  })

  const toggleCap = (cap: string) =>
    setForm(f => ({
      ...f,
      capabilities: f.capabilities.includes(cap) ? f.capabilities.filter(c => c !== cap) : [...f.capabilities, cap],
    }))

  const CAPS = ['marketplace_buy', 'marketplace_sell', 'marketplace_negotiate']

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-slate-500">{agents.length} agent{agents.length !== 1 ? 's' : ''} registered</p>
        <button onClick={() => setShowModal(true)} className={btnPrimary}>
          <Plus className="w-3.5 h-3.5" /> Register Agent
        </button>
      </div>

      {isLoading ? (
        <div className="py-12 text-center text-slate-500 text-sm">Loading agents…</div>
      ) : agents.length === 0 ? (
        <div className="py-12 text-center">
          <Bot className="w-8 h-8 text-slate-700 mx-auto mb-3" />
          <p className="text-sm text-slate-500">No agents yet. Register one to start trading.</p>
        </div>
      ) : (
        <div className="grid gap-3">
          {agents.map(a => (
            <div key={a.agent_id} className="rounded-xl border border-white/8 bg-white/[0.03] p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={clsx('w-2 h-2 rounded-full shrink-0', a.status === 'active' ? 'bg-emerald-400' : 'bg-slate-600')} />
                    <code className="text-xs text-indigo-300 font-mono truncate">{shortDid(a.agent_id)}</code>
                  </div>
                  <p className="text-xs text-slate-500 mb-2">Community: {a.community_id || '—'}</p>
                  <div className="flex flex-wrap gap-1">
                    {a.capabilities.map(c => (
                      <span key={c} className="rounded-md border border-indigo-500/30 bg-indigo-500/10 px-2 py-0.5 text-[10px] text-indigo-300">
                        {c.replace('marketplace_', '')}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-[10px] text-slate-600">{fmtDate(a.created_at)}</span>
                  <button
                    onClick={() => revokeMut.mutate(a.agent_id)}
                    disabled={revokeMut.isPending}
                    className="rounded-md border border-red-500/20 px-2 py-1 text-[10px] text-red-400 hover:border-red-500/40 transition-colors"
                  >
                    Revoke
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {showModal && (
        <Modal title="Register New Agent" onClose={() => setShowModal(false)}>
          <div className="space-y-4">
            <Field label="Tenant ID">
              <input className={inputCls} value={form.tenant_id}
                onChange={e => setForm(f => ({ ...f, tenant_id: e.target.value }))} />
            </Field>
            <Field label="Community ID">
              <input className={inputCls} placeholder="community-uuid" value={form.community_id}
                onChange={e => setForm(f => ({ ...f, community_id: e.target.value }))} />
            </Field>
            <Field label="Ed25519 Public Key (base64)">
              <textarea className={inputCls} rows={2} placeholder="AAAAC3Nz…"
                value={form.public_key} onChange={e => setForm(f => ({ ...f, public_key: e.target.value }))} />
            </Field>
            <Field label="Capabilities">
              <div className="flex flex-wrap gap-2 pt-1">
                {CAPS.map(c => (
                  <button key={c} onClick={() => toggleCap(c)}
                    className={clsx('rounded-lg border px-3 py-1.5 text-xs transition-colors',
                      form.capabilities.includes(c)
                        ? 'border-indigo-500 bg-indigo-500/20 text-indigo-300'
                        : 'border-white/10 text-slate-400 hover:border-white/20')}>
                    {c.replace('marketplace_', '')}
                  </button>
                ))}
              </div>
            </Field>
            <div className="flex justify-end gap-2 pt-1">
              <button onClick={() => setShowModal(false)} className={btnSecondary}>Cancel</button>
              <button onClick={() => registerMut.mutate()} disabled={registerMut.isPending || !form.public_key || form.capabilities.length === 0} className={btnPrimary}>
                {registerMut.isPending ? 'Registering…' : 'Register'}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}

// ── Assets Tab ────────────────────────────────────────────────────────────────

function AssetsTab({ onPublish }: { onPublish?: (asset: { asset_id: string; asset_type: string; seller_agent_id: string }) => void }) {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const [showPublish, setShowPublish] = useState<{ asset_id: string; asset_type: string; seller_agent_id: string } | null>(null)
  const [form, setForm] = useState({ tenant_id: 'default', seller_agent_id: '', asset_type: 'rule', raw_data: '' })
  const [listingForm, setListingForm] = useState({ community_id: '', price_usd: '10', pricing_strategy: 'fixed' })

  const { data: assets = [], isLoading } = useQuery({
    queryKey: ['mkt-assets'],
    queryFn:  () => agenticCommerceApi.listAssets().catch(() => [] as MktAsset[]),
  })

  const tokenizeMut = useMutation({
    mutationFn: () => agenticCommerceApi.registerAsset({
      tenant_id:       form.tenant_id,
      seller_agent_id: form.seller_agent_id,
      asset_type:      form.asset_type,
      raw_data:        (() => { try { return JSON.parse(form.raw_data) } catch { return { content: form.raw_data } } })(),
    }),
    onSuccess: (res) => {
      toast.success(`Asset tokenized: ${res.asset_id}`)
      qc.invalidateQueries({ queryKey: ['mkt-assets'] })
      setShowModal(false)
      setShowPublish(res)
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const publishMut = useMutation({
    mutationFn: () => agenticCommerceApi.createListing({
      asset_id:         showPublish!.asset_id,
      seller_agent_id:  showPublish!.seller_agent_id,
      community_id:     listingForm.community_id,
      tenant_id:        form.tenant_id,
      asset_type:       showPublish!.asset_type,
      price_usd:        parseFloat(listingForm.price_usd),
      pricing_strategy: listingForm.pricing_strategy,
    }),
    onSuccess: () => {
      toast.success('Asset published to Trading Floor')
      qc.invalidateQueries({ queryKey: ['mkt-listings'] })
      setShowPublish(null)
      onPublish?.(showPublish!)
    },
    onError: (e: Error) => toast.error(e.message),
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-slate-500">{assets.length} asset{assets.length !== 1 ? 's' : ''} tokenized</p>
        <button onClick={() => setShowModal(true)} className={btnPrimary}>
          <Plus className="w-3.5 h-3.5" /> Tokenize Asset
        </button>
      </div>

      {isLoading ? (
        <div className="py-12 text-center text-slate-500 text-sm">Loading assets…</div>
      ) : assets.length === 0 ? (
        <div className="py-12 text-center">
          <Package className="w-8 h-8 text-slate-700 mx-auto mb-3" />
          <p className="text-sm text-slate-500">No assets tokenized yet.</p>
        </div>
      ) : (
        <div className="grid gap-3">
          {assets.map(a => (
            <div key={a.asset_id} className="rounded-xl border border-white/8 bg-white/[0.03] p-4">
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={clsx('rounded-md border px-2 py-0.5 text-[10px] font-mono', ASSET_COLOR[a.asset_type] ?? 'bg-slate-500/20 text-slate-300')}>
                      {a.asset_type.toUpperCase()}
                    </span>
                    <code className="text-xs text-slate-300 font-mono truncate">{a.asset_id}</code>
                  </div>
                  <p className="text-xs text-slate-500">Seller: {shortDid(a.seller_agent_id)}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-[10px] text-slate-600">{fmtDate(a.created_at)}</span>
                  <button
                    onClick={() => setShowPublish({ asset_id: a.asset_id, asset_type: a.asset_type, seller_agent_id: a.seller_agent_id })}
                    className={btnSecondary}
                  >
                    <Tag className="w-3 h-3" /> Publish
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {showModal && (
        <Modal title="Tokenize New Asset" onClose={() => setShowModal(false)}>
          <div className="space-y-4">
            <Field label="Seller Agent DID">
              <input className={inputCls} placeholder="did:shadow:…" value={form.seller_agent_id}
                onChange={e => setForm(f => ({ ...f, seller_agent_id: e.target.value }))} />
            </Field>
            <Field label="Asset Type">
              <select className={inputCls} value={form.asset_type}
                onChange={e => setForm(f => ({ ...f, asset_type: e.target.value }))}>
                <option value="rule">Detection Rule</option>
                <option value="model">Semantic Model</option>
                <option value="signals">Signal Bundle</option>
              </select>
            </Field>
            <Field label="Asset Data (JSON)">
              <textarea className={inputCls} rows={4}
                placeholder='{"name":"jailbreak-v2","pattern":"(ignore|bypass).*instructions"}'
                value={form.raw_data} onChange={e => setForm(f => ({ ...f, raw_data: e.target.value }))} />
            </Field>
            <div className="flex justify-end gap-2 pt-1">
              <button onClick={() => setShowModal(false)} className={btnSecondary}>Cancel</button>
              <button onClick={() => tokenizeMut.mutate()} disabled={tokenizeMut.isPending || !form.seller_agent_id} className={btnPrimary}>
                {tokenizeMut.isPending ? 'Tokenizing…' : 'Tokenize & Sign'}
              </button>
            </div>
          </div>
        </Modal>
      )}

      {showPublish && (
        <Modal title="Publish to Trading Floor" onClose={() => setShowPublish(null)}>
          <div className="space-y-4">
            <div className="rounded-lg border border-white/8 bg-white/[0.03] p-3 text-xs text-slate-400">
              <span className="text-slate-500">Asset: </span><code className="text-indigo-300">{showPublish.asset_id}</code>
            </div>
            <Field label="Community ID">
              <input className={inputCls} placeholder="community-uuid" value={listingForm.community_id}
                onChange={e => setListingForm(f => ({ ...f, community_id: e.target.value }))} />
            </Field>
            <Field label="Price (USD)">
              <input className={inputCls} type="number" min="0.01" step="0.01" value={listingForm.price_usd}
                onChange={e => setListingForm(f => ({ ...f, price_usd: e.target.value }))} />
            </Field>
            <Field label="Pricing Strategy">
              <select className={inputCls} value={listingForm.pricing_strategy}
                onChange={e => setListingForm(f => ({ ...f, pricing_strategy: e.target.value }))}>
                <option value="fixed">Fixed</option>
                <option value="negotiable">Negotiable</option>
                <option value="auction">Auction</option>
              </select>
            </Field>
            <div className="flex justify-end gap-2 pt-1">
              <button onClick={() => setShowPublish(null)} className={btnSecondary}>Cancel</button>
              <button onClick={() => publishMut.mutate()} disabled={publishMut.isPending || !listingForm.community_id} className={btnPrimary}>
                {publishMut.isPending ? 'Publishing…' : 'List Asset'}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}

// ── Trading Floor Tab ──────────────────────────────────────────────────────────

function TradingTab({ onPurchased }: { onPurchased?: (escrowId: string) => void }) {
  const qc = useQueryClient()
  const [negotiating, setNegotiating] = useState<MktListing | null>(null)
  const [negState, setNegState] = useState<MktNegotiation | null>(null)
  const [offerPrice, setOfferPrice] = useState('')
  const [buyerAgentId, setBuyerAgentId] = useState('')
  const [buyModal, setBuyModal] = useState<MktListing | null>(null)
  const [filterType, setFilterType] = useState('')

  const { data: listings = [], isLoading, refetch } = useQuery({
    queryKey: ['mkt-listings', filterType],
    queryFn:  () => agenticCommerceApi.listListings(filterType ? { asset_type: filterType } : undefined).catch(() => [] as MktListing[]),
  })

  const buyMut = useMutation({
    mutationFn: () => agenticCommerceApi.buyListing(buyModal!.listing_id, buyerAgentId),
    onSuccess: (res) => {
      toast.success('Purchase initiated — check Escrow tab')
      qc.invalidateQueries({ queryKey: ['mkt-listings'] })
      qc.invalidateQueries({ queryKey: ['mkt-escrows'] })
      qc.invalidateQueries({ queryKey: ['mkt-stats'] })
      setBuyModal(null)
      onPurchased?.(res.escrow_id)
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const startNegMut = useMutation({
    mutationFn: () => agenticCommerceApi.startNegotiation({
      buyer_agent_id:  buyerAgentId,
      seller_agent_id: negotiating!.seller_agent,
      listing_id:      negotiating!.listing_id,
      initial_price:   parseFloat(offerPrice) || negotiating!.price_usd * 0.9,
    }),
    onSuccess: (neg) => { setNegState(neg); toast.success('Negotiation started') },
    onError:   (e: Error) => toast.error(e.message),
  })

  const sendOfferMut = useMutation({
    mutationFn: () => agenticCommerceApi.sendOffer(negState!.negotiation_id, {
      from_agent_id: buyerAgentId,
      price:         parseFloat(offerPrice),
    }),
    onSuccess: () => {
      toast.success('Offer sent')
      agenticCommerceApi.getNegotiation(negState!.negotiation_id).then(setNegState)
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const acceptOfferMut = useMutation({
    mutationFn: () => agenticCommerceApi.acceptOffer(negState!.negotiation_id, buyerAgentId),
    onSuccess: () => { toast.success('Offer accepted'); setNegotiating(null); setNegState(null) },
    onError:   (e: Error) => toast.error(e.message),
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <select className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-xs text-slate-300 focus:outline-none"
            value={filterType} onChange={e => setFilterType(e.target.value)}>
            <option value="">All types</option>
            <option value="rule">Rules</option>
            <option value="model">Models</option>
            <option value="signals">Signals</option>
          </select>
          <p className="text-xs text-slate-500">{listings.length} listing{listings.length !== 1 ? 's' : ''}</p>
        </div>
        <button onClick={() => refetch()} className={btnSecondary}>
          <RefreshCw className="w-3 h-3" /> Refresh
        </button>
      </div>

      {isLoading ? (
        <div className="py-12 text-center text-slate-500 text-sm">Loading listings…</div>
      ) : listings.length === 0 ? (
        <div className="py-12 text-center">
          <TrendingUp className="w-8 h-8 text-slate-700 mx-auto mb-3" />
          <p className="text-sm text-slate-500">No active listings. Publish an asset to start trading.</p>
        </div>
      ) : (
        <div className="grid gap-3">
          {listings.map(l => (
            <div key={l.listing_id} className="rounded-xl border border-white/8 bg-white/[0.03] p-4">
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={clsx('rounded-md border px-2 py-0.5 text-[10px] font-mono', ASSET_COLOR[l.asset_type] ?? '')}>
                      {l.asset_type.toUpperCase()}
                    </span>
                    <span className="text-sm font-semibold text-white">{fmtUsd(l.price_usd)}</span>
                    <span className="text-[10px] text-slate-600 capitalize">{l.pricing_strategy}</span>
                  </div>
                  <p className="text-xs text-slate-500 truncate">Seller: {shortDid(l.seller_agent)}</p>
                  <div className="flex items-center gap-1 mt-1">
                    {[1,2,3,4,5].map(i => (
                      <Star key={i} className={clsx('w-2.5 h-2.5', i <= Math.round(l.demand_score * 5) ? 'text-amber-400 fill-amber-400' : 'text-slate-700')} />
                    ))}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {l.pricing_strategy === 'negotiable' && (
                    <button onClick={() => { setNegotiating(l); setBuyerAgentId(''); setOfferPrice((l.price_usd * 0.9).toFixed(2)) }} className={btnSecondary}>
                      <ArrowLeftRight className="w-3 h-3" /> Negotiate
                    </button>
                  )}
                  <button onClick={() => { setBuyModal(l); setBuyerAgentId('') }} className={btnPrimary}>
                    <DollarSign className="w-3.5 h-3.5" /> Buy
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Buy modal */}
      {buyModal && (
        <Modal title={`Buy — ${fmtUsd(buyModal.price_usd)}`} onClose={() => setBuyModal(null)}>
          <div className="space-y-4">
            <div className="rounded-lg border border-white/8 bg-white/[0.03] p-3 space-y-1 text-xs">
              <div className="flex justify-between"><span className="text-slate-500">Asset type</span><span className="text-white capitalize">{buyModal.asset_type}</span></div>
              <div className="flex justify-between"><span className="text-slate-500">Price</span><span className="text-emerald-400 font-semibold">{fmtUsd(buyModal.price_usd)}</span></div>
              <div className="flex justify-between"><span className="text-slate-500">Seller</span><code className="text-indigo-300">{shortDid(buyModal.seller_agent)}</code></div>
            </div>
            <Field label="Your Buyer Agent DID">
              <input className={inputCls} placeholder="did:shadow:…" value={buyerAgentId} onChange={e => setBuyerAgentId(e.target.value)} />
            </Field>
            <div className="flex justify-end gap-2 pt-1">
              <button onClick={() => setBuyModal(null)} className={btnSecondary}>Cancel</button>
              <button onClick={() => buyMut.mutate()} disabled={buyMut.isPending || !buyerAgentId} className={btnPrimary}>
                {buyMut.isPending ? 'Processing…' : 'Confirm Purchase'}
              </button>
            </div>
          </div>
        </Modal>
      )}

      {/* Negotiate panel */}
      {negotiating && (
        <Modal title={`Negotiate — ${negotiating.listing_id}`} onClose={() => { setNegotiating(null); setNegState(null) }}>
          <div className="space-y-4">
            {!negState ? (
              <>
                <Field label="Your Buyer Agent DID">
                  <input className={inputCls} placeholder="did:shadow:…" value={buyerAgentId} onChange={e => setBuyerAgentId(e.target.value)} />
                </Field>
                <Field label="Initial Offer (USD)">
                  <input className={inputCls} type="number" value={offerPrice} onChange={e => setOfferPrice(e.target.value)} />
                </Field>
                <div className="flex justify-end gap-2">
                  <button onClick={() => setNegotiating(null)} className={btnSecondary}>Cancel</button>
                  <button onClick={() => startNegMut.mutate()} disabled={startNegMut.isPending || !buyerAgentId} className={btnPrimary}>
                    {startNegMut.isPending ? 'Starting…' : 'Start Negotiation'}
                  </button>
                </div>
              </>
            ) : (
              <>
                <div className="space-y-1 max-h-48 overflow-y-auto">
                  {(negState.offers ?? []).map(o => (
                    <div key={o.offer_id} className={clsx('rounded-lg px-3 py-2 text-xs', o.from_agent_id === buyerAgentId ? 'bg-indigo-500/15 text-indigo-300 ml-8' : 'bg-white/5 text-slate-300 mr-8')}>
                      <span className="font-semibold">{fmtUsd(o.price)}</span>
                      {o.message && <span className="ml-2 text-slate-500">{o.message}</span>}
                    </div>
                  ))}
                </div>
                <Field label="Counter-offer (USD)">
                  <input className={inputCls} type="number" value={offerPrice} onChange={e => setOfferPrice(e.target.value)} />
                </Field>
                <div className="flex gap-2 justify-end">
                  <button onClick={() => acceptOfferMut.mutate()} disabled={acceptOfferMut.isPending} className="flex items-center gap-2 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-500 transition-colors">
                    Accept
                  </button>
                  <button onClick={() => sendOfferMut.mutate()} disabled={sendOfferMut.isPending || !offerPrice} className={btnPrimary}>
                    {sendOfferMut.isPending ? 'Sending…' : 'Send Offer'}
                  </button>
                </div>
              </>
            )}
          </div>
        </Modal>
      )}
    </div>
  )
}

// ── Escrow Tab ────────────────────────────────────────────────────────────────

function EscrowTab({ highlightId }: { highlightId?: string }) {
  const qc = useQueryClient()
  const [filterStatus, setFilterStatus] = useState('')
  const [deliverModal, setDeliverModal] = useState<string | null>(null)
  const [assetHash, setAssetHash] = useState('')
  const [disputeModal, setDisputeModal] = useState<string | null>(null)
  const [disputeReason, setDisputeReason] = useState('')

  const { data: escrows = [], isLoading, refetch } = useQuery({
    queryKey: ['mkt-escrows', filterStatus],
    queryFn:  () => agenticCommerceApi.listEscrows(filterStatus ? { status: filterStatus } : undefined).catch(() => [] as MktEscrow[]),
  })

  const mut = (fn: () => Promise<unknown>, msg: string) => useMutation({  // eslint-disable-line react-hooks/rules-of-hooks
    mutationFn: fn,
    onSuccess:  () => { toast.success(msg); qc.invalidateQueries({ queryKey: ['mkt-escrows'] }) },
    onError:    (e: Error) => toast.error(e.message),
  })

  const fundMut    = mut(() => Promise.resolve(), 'Funded')
  const confirmMut = mut(() => Promise.resolve(), 'Confirmed')
  const resolveMut = mut(() => Promise.resolve(), 'Resolved')

  async function handleFund(id: string) {
    try { await agenticCommerceApi.fundEscrow(id); toast.success('Escrow funded'); qc.invalidateQueries({ queryKey: ['mkt-escrows'] }) }
    catch (e: unknown) { toast.error((e as Error).message) }
  }

  async function handleConfirm(id: string) {
    try { await agenticCommerceApi.confirmReceipt(id); toast.success('Receipt confirmed'); qc.invalidateQueries({ queryKey: ['mkt-escrows'] }); qc.invalidateQueries({ queryKey: ['mkt-purchases'] }) }
    catch (e: unknown) { toast.error((e as Error).message) }
  }

  async function handleDeliver() {
    if (!deliverModal) return
    try { await agenticCommerceApi.deliverAsset(deliverModal, assetHash); toast.success('Asset delivered'); qc.invalidateQueries({ queryKey: ['mkt-escrows'] }); setDeliverModal(null); setAssetHash('') }
    catch (e: unknown) { toast.error((e as Error).message) }
  }

  async function handleDispute() {
    if (!disputeModal) return
    try { await agenticCommerceApi.raiseDispute(disputeModal, disputeReason); toast.success('Dispute raised'); qc.invalidateQueries({ queryKey: ['mkt-escrows'] }); setDisputeModal(null); setDisputeReason('') }
    catch (e: unknown) { toast.error((e as Error).message) }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <select className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-xs text-slate-300 focus:outline-none"
          value={filterStatus} onChange={e => setFilterStatus(e.target.value)}>
          <option value="">All statuses</option>
          <option value="pending_deposit">Pending Deposit</option>
          <option value="funded">Funded</option>
          <option value="delivered">Delivered</option>
          <option value="confirmed">Confirmed</option>
          <option value="disputed">Disputed</option>
        </select>
        <button onClick={() => refetch()} className={btnSecondary}>
          <RefreshCw className="w-3 h-3" /> Refresh
        </button>
      </div>

      {isLoading ? (
        <div className="py-12 text-center text-slate-500 text-sm">Loading escrows…</div>
      ) : escrows.length === 0 ? (
        <div className="py-12 text-center">
          <Lock className="w-8 h-8 text-slate-700 mx-auto mb-3" />
          <p className="text-sm text-slate-500">No escrow contracts yet.</p>
        </div>
      ) : (
        <div className="grid gap-3">
          {escrows.map(e => {
            const Icon   = ESCROW_ICON[e.status] ?? Clock
            const colour = ESCROW_COLOR[e.status] ?? 'text-slate-400'
            const isNew  = highlightId && e.escrow_id === highlightId
            return (
              <div key={e.escrow_id} className={clsx('rounded-xl border p-4 transition-colors', isNew ? 'border-indigo-500/40 bg-indigo-500/5' : 'border-white/8 bg-white/[0.03]')}>
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <Icon className={clsx('w-4 h-4 shrink-0', colour)} />
                      <code className="text-xs text-slate-300 font-mono truncate">{e.escrow_id}</code>
                    </div>
                    <div className="grid grid-cols-2 gap-x-4 text-xs text-slate-500 mt-1">
                      <span>Buyer: {shortDid(e.buyer_agent)}</span>
                      <span>Seller: {shortDid(e.seller_agent)}</span>
                      <span>Amount: <span className="text-white">{fmtUsd(e.amount_usd)}</span></span>
                      <span>Status: <span className={colour}>{e.status.replace(/_/g, ' ')}</span></span>
                    </div>
                  </div>
                  <div className="flex flex-col gap-1.5 shrink-0">
                    {e.status === 'pending_deposit' && (
                      <button onClick={() => handleFund(e.escrow_id)} className={btnPrimary}>Fund</button>
                    )}
                    {e.status === 'funded' && (
                      <button onClick={() => { setDeliverModal(e.escrow_id); setAssetHash('') }} className={btnPrimary}>
                        Deliver Asset
                      </button>
                    )}
                    {e.status === 'delivered' && (
                      <button onClick={() => handleConfirm(e.escrow_id)} className={btnPrimary}>
                        Confirm Receipt
                      </button>
                    )}
                    {(e.status === 'funded' || e.status === 'delivered') && (
                      <button onClick={() => { setDisputeModal(e.escrow_id); setDisputeReason('') }} className="flex items-center gap-1 rounded-lg border border-red-500/20 px-2 py-1 text-[10px] text-red-400 hover:border-red-500/40 transition-colors">
                        Raise Dispute
                      </button>
                    )}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {deliverModal && (
        <Modal title="Deliver Asset" onClose={() => setDeliverModal(null)}>
          <div className="space-y-4">
            <Field label="Asset Hash (SHA-256)">
              <input className={inputCls} placeholder="sha256:…" value={assetHash} onChange={e => setAssetHash(e.target.value)} />
            </Field>
            <div className="flex justify-end gap-2">
              <button onClick={() => setDeliverModal(null)} className={btnSecondary}>Cancel</button>
              <button onClick={handleDeliver} disabled={!assetHash} className={btnPrimary}>Deliver</button>
            </div>
          </div>
        </Modal>
      )}

      {disputeModal && (
        <Modal title="Raise Dispute" onClose={() => setDisputeModal(null)}>
          <div className="space-y-4">
            <Field label="Reason">
              <textarea className={inputCls} rows={3} placeholder="Describe the issue…"
                value={disputeReason} onChange={e => setDisputeReason(e.target.value)} />
            </Field>
            <div className="flex justify-end gap-2">
              <button onClick={() => setDisputeModal(null)} className={btnSecondary}>Cancel</button>
              <button onClick={handleDispute} disabled={!disputeReason} className="flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-xs font-semibold text-white hover:bg-red-500 transition-colors">
                Raise Dispute
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}

// ── Imported Tab ──────────────────────────────────────────────────────────────

function ImportedTab() {
  const { data: purchases = [], isLoading } = useQuery({
    queryKey: ['mkt-purchases'],
    queryFn:  () => agenticCommerceApi.listPurchases().catch(() => [] as MktPurchase[]),
  })

  const MODULE_LINK: Record<string, string> = {
    rule:    '/dashboard/?tab=evolution',
    model:   '/dashboard/?tab=semantic',
    signals: '/dashboard/?tab=intel',
  }

  return (
    <div className="space-y-4">
      <p className="text-xs text-slate-500">{purchases.length} purchase record{purchases.length !== 1 ? 's' : ''}</p>

      {isLoading ? (
        <div className="py-12 text-center text-slate-500 text-sm">Loading purchases…</div>
      ) : purchases.length === 0 ? (
        <div className="py-12 text-center">
          <Download className="w-8 h-8 text-slate-700 mx-auto mb-3" />
          <p className="text-sm text-slate-500">No purchased assets yet.</p>
        </div>
      ) : (
        <div className="grid gap-3">
          {purchases.map(p => (
            <div key={p.purchase_id} className="rounded-xl border border-white/8 bg-white/[0.03] p-4">
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={clsx('w-2 h-2 rounded-full shrink-0', p.status === 'completed' ? 'bg-emerald-400' : p.status === 'pending' ? 'bg-amber-400' : 'bg-slate-600')} />
                    <code className="text-xs text-slate-300 font-mono truncate">{p.asset_id}</code>
                  </div>
                  <div className="grid grid-cols-2 gap-x-4 text-xs text-slate-500 mt-1">
                    <span>Paid: <span className="text-white">{fmtUsd(p.price_paid)}</span></span>
                    <span>Status: <span className={p.status === 'completed' ? 'text-emerald-400' : 'text-amber-400'}>{p.status}</span></span>
                    <span>Buyer: {shortDid(p.buyer_agent)}</span>
                    <span>Date: {fmtDate(p.purchased_at)}</span>
                  </div>
                </div>
                {p.status === 'completed' && (
                  <a href={MODULE_LINK['rule'] ?? '/dashboard/'} className="flex items-center gap-1.5 rounded-lg border border-emerald-500/20 px-3 py-1.5 text-[10px] text-emerald-400 hover:border-emerald-500/40 transition-colors shrink-0">
                    <Zap className="w-3 h-3" /> View in Module <ChevronRight className="w-3 h-3" />
                  </a>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Stats bar ─────────────────────────────────────────────────────────────────

function StatsBar() {
  const { data: stats } = useQuery({
    queryKey: ['mkt-stats'],
    queryFn:  () => agenticCommerceApi.getStats().catch(() => null),
    refetchInterval: 30_000,
  })

  if (!stats) return null

  const items = [
    { label: 'Agents',          value: stats.agents,           color: 'text-indigo-400' },
    { label: 'Active Listings', value: stats.active_listings,  color: 'text-blue-400'   },
    { label: 'Completed Trades',value: stats.completed_trades, color: 'text-emerald-400'},
    { label: 'Volume',          value: fmtUsd(stats.total_volume_usd), color: 'text-amber-400' },
  ]

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
      {items.map(it => (
        <div key={it.label} className="rounded-xl border border-white/8 bg-white/[0.03] px-4 py-3">
          <p className="text-xs text-slate-500 mb-1">{it.label}</p>
          <p className={clsx('text-lg font-bold', it.color)}>{it.value}</p>
        </div>
      ))}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AgenticCommercePage() {
  const [tab, setTab] = useState<TabId>('agents')
  const [highlightEscrow, setHighlightEscrow] = useState<string | undefined>()

  const handlePurchased = useCallback((escrowId: string) => {
    setHighlightEscrow(escrowId)
    setTab('escrow')
  }, [])

  return (
    <div className="min-h-screen bg-[#080c14] text-white">
      {/* Header */}
      <div className="border-b border-white/8 bg-[#0a0f1e] px-6 py-5">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl flex items-center justify-center bg-gradient-to-br from-indigo-600 to-violet-600 shrink-0">
            <ArrowLeftRight className="w-4 h-4 text-white" />
          </div>
          <div>
            <h1 className="text-base font-bold text-white">Agentic Commerce Hub</h1>
            <p className="text-xs text-slate-500">M2M marketplace — agents, assets, trading, escrow</p>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <Shield className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-[10px] text-emerald-400 font-semibold">DID-secured · AP2 mandates</span>
          </div>
        </div>
      </div>

      <div className="px-6 py-6">
        <StatsBar />

        {/* Tab bar */}
        <div className="flex gap-1 border-b border-white/8 mb-6">
          {TABS.map(t => {
            const Icon = t.icon
            return (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={clsx(
                  'flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium border-b-2 -mb-px transition-colors',
                  tab === t.id
                    ? 'border-indigo-500 text-white'
                    : 'border-transparent text-slate-500 hover:text-slate-300',
                )}
              >
                <Icon className="w-3.5 h-3.5" />
                {t.label}
              </button>
            )
          })}
        </div>

        {/* Tab content */}
        <div className="max-w-4xl">
          {tab === 'agents'   && <AgentsTab />}
          {tab === 'assets'   && <AssetsTab />}
          {tab === 'trading'  && <TradingTab onPurchased={handlePurchased} />}
          {tab === 'escrow'   && <EscrowTab  highlightId={highlightEscrow} />}
          {tab === 'imported' && <ImportedTab />}
        </div>
      </div>
    </div>
  )
}
