'use client'
/**
 * /community-hub/create — 6-step community creation wizard.
 * Step 1: Identity  · Step 2: Security  · Step 3: Members
 * Step 4: Peering   · Step 5: Compliance · Step 6: Integrations
 */

import React, { useState, useCallback, useEffect, Suspense } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import Link from 'next/link'
import toast from 'react-hot-toast'
import {
  Building2, Shield, Users, Network, BookOpen, Settings2,
  ChevronRight, ChevronLeft, Check, Plus, X, Globe, Lock,
  Zap, Info, ArrowLeft, Loader2, Bell, LockKeyhole,
  ShoppingCart, Bot, CheckCircle2,
} from 'lucide-react'
import {
  createCommunity,
  getCommunity,
  patchCommunity,
  addMember,
  upgradeToPQC,
  uploadCharter,
  updateSettings,
} from '@/lib/communityHubApi'

// ── Types ───────────────────────────────────────────────────────────────────

interface Invitation { tenantId: string; role: 'admin' | 'member' | 'observer' }

interface WizardData {
  // Step 1
  name:        string
  description: string
  visibility:  'private' | 'public'
  joinPolicy:  'invite' | 'approval' | 'open'
  // Step 2
  cryptoMode:  'classical' | 'hybrid_pqc'
  // Step 3
  invitations: Invitation[]
  // Step 4
  peeringEnabled: boolean
  peeringPolicy:  'MIRROR_ONLY' | 'REWRAP_ALLOWED' | 'FULL_SYNC'
  tunnelRegions:  string[]
  // Step 5
  charterEnabled:       boolean
  charterText:          string
  stixAudit:            boolean
  docIntel:             boolean
  complianceFrameworks: string[]
  // Step 5.5
  createDefaultAgent: boolean
  // Step 6
  evolutionEnabled: boolean
  slackWebhook:     string
  teamsWebhook:     string
}

const INIT: WizardData = {
  name: '', description: '', visibility: 'private', joinPolicy: 'invite',
  cryptoMode: 'classical',
  invitations: [],
  peeringEnabled: false, peeringPolicy: 'MIRROR_ONLY', tunnelRegions: [],
  charterEnabled: false, charterText: '', stixAudit: true, docIntel: true,
  complianceFrameworks: [],
  createDefaultAgent: true,
  evolutionEnabled: false, slackWebhook: '', teamsWebhook: '',
}

const TUNNEL_REGIONS  = ['EU', 'US', 'UK', 'CA', 'SG', 'AU', 'JP', 'CH']
const COMPLIANCE_FW   = ['GDPR', 'SOC 2', 'ISO 27001', 'HIPAA']

const STEPS = [
  { label: 'Identity',          icon: Building2,   subtitle: 'Name and access policy'    },
  { label: 'Security',          icon: Shield,       subtitle: 'Cryptographic keys'         },
  { label: 'Members',           icon: Users,        subtitle: 'Invite participants'         },
  { label: 'Peering',           icon: Network,      subtitle: 'Federation and tunnels'      },
  { label: 'Compliance',        icon: BookOpen,     subtitle: 'Audit and frameworks'        },
  { label: 'Marketplace Setup', icon: ShoppingCart, subtitle: 'Register default agent'      },
  { label: 'Integrations',      icon: Settings2,    subtitle: 'Finish and activate'         },
]

// ── Reusable primitives ─────────────────────────────────────────────────────

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <label className="block text-sm font-medium text-slate-300">{label}</label>
      {children}
    </div>
  )
}

function Inp(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={[
        'w-full bg-slate-800/60 border border-slate-700 rounded-lg px-3 py-2.5',
        'text-sm text-white placeholder-slate-600',
        'focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400/30 transition',
        props.className ?? '',
      ].join(' ')}
    />
  )
}

function TA(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      {...props}
      className={[
        'w-full bg-slate-800/60 border border-slate-700 rounded-lg px-3 py-2.5',
        'text-sm text-white placeholder-slate-600 resize-none',
        'focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400/30 transition',
        props.className ?? '',
      ].join(' ')}
    />
  )
}

function InfoBox({ icon: Icon = Info, children, color = 'blue' }: {
  icon?: React.ElementType; children: React.ReactNode; color?: 'blue' | 'amber'
}) {
  const cls = color === 'amber'
    ? 'bg-amber-500/10 border-amber-500/25 text-amber-300'
    : 'bg-blue-500/10 border-blue-500/20 text-blue-300'
  return (
    <div className={`flex gap-2 p-3 rounded-lg border text-xs ${cls}`}>
      <Icon size={13} className="shrink-0 mt-0.5" />
      <span className="leading-relaxed">{children}</span>
    </div>
  )
}

function OptionCard({
  active, onClick, icon: Icon, title, desc, badge,
}: {
  active: boolean; onClick: () => void; icon?: React.ElementType;
  title: string; desc: string; badge?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        'flex items-start gap-3 p-3.5 rounded-xl border text-left w-full transition-all',
        active
          ? 'border-brand-400 bg-brand-400/10 ring-1 ring-brand-400/20'
          : 'border-slate-700 bg-slate-800/30 hover:border-slate-600 hover:bg-slate-800/50',
      ].join(' ')}
    >
      {Icon && (
        <div className={`p-1.5 rounded-lg shrink-0 ${active ? 'bg-brand-400/20' : 'bg-slate-700'}`}>
          <Icon size={14} className={active ? 'text-brand-300' : 'text-slate-400'} />
        </div>
      )}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className={`text-sm font-medium ${active ? 'text-brand-200' : 'text-white'}`}>
            {title}
          </span>
          {badge && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-violet-500/20 text-violet-300 border border-violet-500/20 leading-none">
              {badge}
            </span>
          )}
        </div>
        <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">{desc}</p>
      </div>
      {active && <Check size={13} className="shrink-0 mt-1 text-brand-400" />}
    </button>
  )
}

function SwToggle({ checked, onChange, label, desc }: {
  checked: boolean; onChange: (v: boolean) => void; label: string; desc?: string
}) {
  return (
    <div className="flex items-start gap-3 cursor-pointer" onClick={() => onChange(!checked)}>
      <div className={`relative mt-0.5 w-8 h-4.5 rounded-full shrink-0 transition-colors ${checked ? 'bg-brand-400' : 'bg-slate-700'}`}>
        <span className={`absolute top-0.5 left-0.5 w-3.5 h-3.5 rounded-full bg-white shadow transition-transform ${checked ? 'translate-x-3.5' : ''}`} />
      </div>
      <div>
        <div className="text-sm font-medium text-white leading-tight">{label}</div>
        {desc && <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">{desc}</p>}
      </div>
    </div>
  )
}

function PillChip({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        'px-3 py-1.5 rounded-full text-xs font-medium border transition-all',
        active
          ? 'border-brand-400 bg-brand-400/15 text-brand-300'
          : 'border-slate-700 bg-slate-800/40 text-slate-400 hover:border-slate-600',
      ].join(' ')}
    >
      {label}
    </button>
  )
}

function CheckRow({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        'flex items-center gap-2.5 px-3 py-2.5 rounded-lg border text-sm text-left transition-all w-full',
        active
          ? 'border-emerald-500 bg-emerald-500/10 text-emerald-300'
          : 'border-slate-700 bg-slate-800/30 text-slate-400 hover:border-slate-600',
      ].join(' ')}
    >
      <div className={`w-4 h-4 rounded border flex items-center justify-center shrink-0 transition-colors ${active ? 'border-emerald-400 bg-emerald-500' : 'border-slate-600'}`}>
        {active && <Check size={10} className="text-white" />}
      </div>
      {label}
    </button>
  )
}

// ── Step 1: Identity ────────────────────────────────────────────────────────

function Step1({ d, set }: { d: WizardData; set: (k: keyof WizardData, v: unknown) => void }) {
  return (
    <div className="space-y-5">
      <Field label="Community Name *">
        <Inp
          value={d.name}
          onChange={e => set('name', e.target.value)}
          placeholder="e.g. APAC Security Alliance"
          maxLength={80}
        />
        <p className="text-xs text-slate-600">{d.name.length} / 80</p>
      </Field>

      <Field label="Description">
        <TA
          value={d.description}
          onChange={e => set('description', e.target.value)}
          placeholder="What is this community for? Who should join?"
          rows={3}
          maxLength={500}
        />
        <p className="text-xs text-slate-600">{d.description.length} / 500</p>
      </Field>

      <Field label="Visibility">
        <div className="grid grid-cols-2 gap-2">
          <OptionCard
            active={d.visibility === 'private'}
            onClick={() => set('visibility', 'private')}
            icon={Lock}
            title="Private"
            desc="Only visible to members and invited tenants"
          />
          <OptionCard
            active={d.visibility === 'public'}
            onClick={() => set('visibility', 'public')}
            icon={Globe}
            title="Public"
            desc="Listed in community directory, discoverable by all"
          />
        </div>
      </Field>

      <Field label="Join Policy">
        <div className="grid grid-cols-3 gap-2">
          {[
            { v: 'invite',   title: 'Invite Only', desc: 'Admin adds members manually' },
            { v: 'approval', title: 'Approval',     desc: 'Requests reviewed by admin' },
            { v: 'open',     title: 'Open',         desc: 'Anyone can join freely' },
          ].map(({ v, title, desc }) => (
            <OptionCard
              key={v}
              active={d.joinPolicy === v}
              onClick={() => set('joinPolicy', v)}
              title={title}
              desc={desc}
            />
          ))}
        </div>
      </Field>
    </div>
  )
}

// ── Step 2: Security ────────────────────────────────────────────────────────

function Step2({
  d, set, locked = false,
}: {
  d: WizardData; set: (k: keyof WizardData, v: unknown) => void; locked?: boolean
}) {
  if (locked) {
    const label = d.cryptoMode === 'classical' ? 'Classical Ed25519' : 'Hybrid PQC — Ed25519 + ML-DSA-65'
    return (
      <div className="space-y-4">
        <div className="flex gap-2 p-3 rounded-lg bg-amber-500/10 border border-amber-500/25 text-xs text-amber-300">
          <LockKeyhole size={13} className="shrink-0 mt-0.5" />
          <span>
            Cryptographic mode cannot be changed after community creation. The keypair is
            permanently bound to the community identity.
          </span>
        </div>
        <div className="rounded-xl border border-slate-700 bg-slate-800/20 p-4 space-y-1">
          <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-2">Current Mode</p>
          <p className="text-sm font-medium text-white">{label}</p>
          <p className="text-xs text-slate-500 mt-1">
            Key ID: <span className="font-mono text-slate-400">
              {d.cryptoMode === 'classical' ? 'v1' : 'v1-hybrid'}
            </span>
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-5">
      <InfoBox>
        A cryptographic keypair is generated automatically at creation. Ed25519 is recommended
        for most deployments. Hybrid PQC adds ML-DSA-65 (FIPS 204) post-quantum protection
        and requires Enterprise tier.
      </InfoBox>

      <Field label="Cryptographic Mode">
        <div className="space-y-2">
          <OptionCard
            active={d.cryptoMode === 'classical'}
            onClick={() => set('cryptoMode', 'classical')}
            icon={Shield}
            title="Classical — Ed25519"
            desc="Battle-tested 256-bit elliptic curve signatures. NIST-recommended for most use cases. Fast key operations."
          />
          <OptionCard
            active={d.cryptoMode === 'hybrid_pqc'}
            onClick={() => set('cryptoMode', 'hybrid_pqc')}
            icon={Zap}
            title="Hybrid PQC — Ed25519 + ML-DSA-65"
            desc="Classical and post-quantum signatures combined. Protects against future quantum adversaries. FIPS 204 compliant."
            badge="Enterprise"
          />
        </div>
      </Field>

      {d.cryptoMode === 'hybrid_pqc' && (
        <InfoBox icon={Zap} color="amber">
          Hybrid PQC key upgrade is applied after community creation via{' '}
          <code className="font-mono bg-white/10 px-1 rounded">POST /communities/{'{id}'}/upgrade-pqc</code>.
          The hybrid signature is 3,373 bytes — Ed25519 (64 B) + ML-DSA-65 (3,309 B).
          Requires Enterprise tier with liboqs installed.
        </InfoBox>
      )}

      <div className="rounded-xl border border-slate-700 bg-slate-800/20 p-4 space-y-2">
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">Key Details</p>
        <div className="grid grid-cols-2 gap-y-2 text-xs">
          {[
            ['Algorithm',    d.cryptoMode === 'classical' ? 'Ed25519' : 'Ed25519 + ML-DSA-65'],
            ['Key ID',       'Assigned at creation (e.g. "v1")'],
            ['Storage',      'Fernet-encrypted, VAULT_MASTER_KEY'],
            ['PQC Standard', d.cryptoMode === 'classical' ? 'N/A' : 'FIPS 204 (ML-DSA)'],
            ['KEM',          d.cryptoMode === 'classical' ? 'X25519' : 'X25519 + ML-KEM-768'],
            ['Hybrid kid',   d.cryptoMode === 'classical' ? 'v1'     : 'v1-hybrid'],
          ].map(([k, v]) => (
            <div key={k}>
              <span className="text-slate-500">{k}: </span>
              <span className="text-slate-300">{v}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Step 3: Members ─────────────────────────────────────────────────────────

function Step3({ d, set }: { d: WizardData; set: (k: keyof WizardData, v: unknown) => void }) {
  const [inp, setInp]   = useState('')
  const [role, setRole] = useState<'admin' | 'member' | 'observer'>('member')

  const addInv = () => {
    const tid = inp.trim()
    if (!tid) return
    if (d.invitations.find(i => i.tenantId === tid)) {
      toast.error('Already in invitation list'); return
    }
    set('invitations', [...d.invitations, { tenantId: tid, role }])
    setInp('')
  }

  const removeInv = (tid: string) =>
    set('invitations', d.invitations.filter(i => i.tenantId !== tid))

  return (
    <div className="space-y-5">
      <InfoBox>
        Invite members by Tenant ID. You can also add members after creation from the community
        settings page. All invited members will receive a Knock-and-Verify token (72-hour TTL).
      </InfoBox>

      <Field label="Add Member">
        <div className="flex gap-2">
          <Inp
            value={inp}
            onChange={e => setInp(e.target.value)}
            placeholder="tenant_id"
            onKeyDown={e => e.key === 'Enter' && addInv()}
            className="flex-1"
          />
          <select
            value={role}
            onChange={e => setRole(e.target.value as 'admin' | 'member' | 'observer')}
            className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-brand-400 transition"
          >
            <option value="admin">Admin</option>
            <option value="member">Member</option>
            <option value="observer">Observer</option>
          </select>
          <button
            type="button"
            onClick={addInv}
            className="flex items-center gap-1.5 px-3 py-2 bg-brand-400 hover:bg-brand-300 text-dark-900 text-sm font-semibold rounded-lg transition"
          >
            <Plus size={14} /> Add
          </button>
        </div>
      </Field>

      {d.invitations.length > 0 ? (
        <div className="space-y-1.5">
          <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold">
            Pending ({d.invitations.length})
          </p>
          {d.invitations.map(inv => (
            <div
              key={inv.tenantId}
              className="flex items-center justify-between px-3 py-2.5 rounded-lg bg-slate-800/50 border border-slate-700"
            >
              <div className="flex items-center gap-2.5">
                <Users size={13} className="text-slate-500" />
                <span className="text-sm text-white font-mono">{inv.tenantId}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs px-2 py-0.5 rounded bg-slate-700 text-slate-400">
                  {inv.role}
                </span>
                <button
                  type="button"
                  onClick={() => removeInv(inv.tenantId)}
                  className="text-slate-600 hover:text-red-400 transition"
                >
                  <X size={13} />
                </button>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-center py-8 text-sm text-slate-600">
          No invitations yet — you can skip this step.
        </div>
      )}
    </div>
  )
}

// ── Step 4: Peering ─────────────────────────────────────────────────────────

function Step4({ d, set }: { d: WizardData; set: (k: keyof WizardData, v: unknown) => void }) {
  const toggleRegion = (r: string) => {
    const next = d.tunnelRegions.includes(r)
      ? d.tunnelRegions.filter(x => x !== r)
      : [...d.tunnelRegions, r]
    set('tunnelRegions', next)
  }

  return (
    <div className="space-y-5">
      <SwToggle
        checked={d.peeringEnabled}
        onChange={v => set('peeringEnabled', v)}
        label="Enable Federation (Community Peering)"
        desc="Allow this community to peer with other Shadow Warden communities for rule sharing and data transfers."
      />

      {d.peeringEnabled && (
        <>
          <Field label="Data Transfer Policy">
            <div className="space-y-2">
              {[
                {
                  v: 'MIRROR_ONLY',
                  title: 'Mirror Only',
                  desc:  'Read-only replication. Peers can receive rules but cannot write back.',
                },
                {
                  v: 'REWRAP_ALLOWED',
                  title: 'Rewrap Allowed',
                  desc:  'Peers can re-encrypt and redistribute shared content with their own keys.',
                },
                {
                  v: 'FULL_SYNC',
                  title: 'Full Sync',
                  desc:  'Bidirectional synchronization. Highest trust level — use with verified peers only.',
                },
              ].map(({ v, title, desc }) => (
                <OptionCard
                  key={v}
                  active={d.peeringPolicy === v}
                  onClick={() => set('peeringPolicy', v)}
                  title={title}
                  desc={desc}
                />
              ))}
            </div>
          </Field>

          <Field label="MASQUE Tunnel Regions">
            <div className="flex flex-wrap gap-2">
              {TUNNEL_REGIONS.map(r => (
                <PillChip
                  key={r}
                  label={r}
                  active={d.tunnelRegions.includes(r)}
                  onClick={() => toggleRegion(r)}
                />
              ))}
            </div>
            <p className="text-xs text-slate-600 mt-1.5">
              Traffic is routed through selected jurisdictions. Leave empty to use default policy.
            </p>
          </Field>

          <InfoBox>
            MASQUE tunnels support MASQUE_H3, MASQUE_H2, and CONNECT_TCP protocols with TOFU TLS
            pinning. Cross-border transfers are validated against your Sovereign AI Cloud policy.
            The Causal Transfer Guard blocks exfiltration risk ≥ 0.70 in &lt;20 ms.
          </InfoBox>
        </>
      )}

      {!d.peeringEnabled && (
        <div className="text-center py-6 text-sm text-slate-600">
          Federation is off. This community operates in isolation — no cross-community transfers.
        </div>
      )}
    </div>
  )
}

// ── Step 5: Compliance ──────────────────────────────────────────────────────

function Step5({ d, set }: { d: WizardData; set: (k: keyof WizardData, v: unknown) => void }) {
  const toggleFw = (fw: string) => {
    const next = d.complianceFrameworks.includes(fw)
      ? d.complianceFrameworks.filter(f => f !== fw)
      : [...d.complianceFrameworks, fw]
    set('complianceFrameworks', next)
  }

  return (
    <div className="space-y-5">
      <div className="space-y-3.5">
        {/* STIX audit is mandatory — always on */}
        <div className="flex items-start gap-3 rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-3">
          <CheckCircle2 size={16} className="text-emerald-400 mt-0.5 shrink-0" />
          <div>
            <div className="text-sm font-medium text-white flex items-center gap-2">
              STIX 2.1 Tamper-Evident Audit Chain
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-normal">Required</span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Every transfer is appended to a SHA-256 prev_hash blockchain-style audit trail.
              Mandatory for all communities — cannot be disabled.
            </p>
          </div>
        </div>
        <SwToggle
          checked={d.docIntel}
          onChange={v => set('docIntel', v)}
          label="Document Intelligence Auto-scan"
          desc="All uploaded documents are converted via MarkItDown and screened through the full security filter pipeline."
        />
        <SwToggle
          checked={d.charterEnabled}
          onChange={v => set('charterEnabled', v)}
          label="Community Charter"
          desc="Define governance rules that members must accept before joining."
        />
      </div>

      {d.charterEnabled && (
        <Field label="Charter Text">
          <TA
            value={d.charterText}
            onChange={e => set('charterText', e.target.value)}
            placeholder="Define the community's purpose, acceptable use policy, and member responsibilities..."
            rows={5}
          />
        </Field>
      )}

      <Field label="Compliance Frameworks">
        <div className="grid grid-cols-2 gap-2">
          {COMPLIANCE_FW.map(fw => (
            <CheckRow
              key={fw}
              label={fw}
              active={d.complianceFrameworks.includes(fw)}
              onClick={() => toggleFw(fw)}
            />
          ))}
        </div>
        <p className="text-xs text-slate-600 mt-1.5">
          Selected frameworks are continuously monitored via the compliance scoring engine (Pro+).
        </p>
      </Field>
    </div>
  )
}

// ── Step 5.5: Marketplace Setup ─────────────────────────────────────────────

function Step5_5({ d, set }: { d: WizardData; set: (k: keyof WizardData, v: unknown) => void }) {
  return (
    <div className="space-y-5">
      <InfoBox icon={ShoppingCart} color="blue">
        A marketplace agent gives your community a DID identity to buy and sell detection assets.
        The agent is registered automatically when you create the community.
      </InfoBox>

      <div
        onClick={() => set('createDefaultAgent', !d.createDefaultAgent)}
        className={[
          'flex items-start gap-4 p-4 rounded-xl border cursor-pointer transition-all',
          d.createDefaultAgent
            ? 'border-violet-500/40 bg-violet-500/8'
            : 'border-white/8 bg-white/3 hover:border-white/15',
        ].join(' ')}
      >
        <div className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0 bg-violet-500/15 border border-violet-500/25 mt-0.5">
          <Bot size={16} className="text-violet-400" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2">
            <div className="text-sm font-semibold text-white">Register default marketplace agent</div>
            <div className={[
              'w-4 h-4 rounded border flex items-center justify-center shrink-0',
              d.createDefaultAgent ? 'bg-violet-500 border-violet-500' : 'border-slate-600 bg-slate-800',
            ].join(' ')}>
              {d.createDefaultAgent && <Check size={10} className="text-white" />}
            </div>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Capabilities: <code className="text-slate-300">marketplace_sell</code> + <code className="text-slate-300">marketplace_buy</code>
            <br />Spending limit: $100/mo · DID derived from ephemeral Ed25519 keypair
          </p>
        </div>
      </div>

      {!d.createDefaultAgent && (
        <p className="text-xs text-slate-500">
          You can register agents later from the Marketplace tab in the Community Hub.
        </p>
      )}
    </div>
  )
}

// ── Step 6: Integrations ────────────────────────────────────────────────────

function Step6({ d, set }: { d: WizardData; set: (k: keyof WizardData, v: unknown) => void }) {
  const fmtJoin = (v: string) => ({ invite: 'Invite Only', approval: 'Approval', open: 'Open' }[v] ?? v)
  const fmtCrypto = (v: string) => v === 'classical' ? 'Ed25519' : 'Hybrid PQC (Ed25519 + ML-DSA-65)'

  const summaryRows: [string, string][] = [
    ['Name',       d.name || '—'],
    ['Visibility', d.visibility],
    ['Join Policy', fmtJoin(d.joinPolicy)],
    ['Crypto',     fmtCrypto(d.cryptoMode)],
    ['Members',    `${d.invitations.length} invited`],
    ['Peering',    d.peeringEnabled ? d.peeringPolicy : 'Disabled'],
    ['Regions',    d.tunnelRegions.length > 0 ? d.tunnelRegions.join(', ') : 'Default routing'],
    ['Frameworks', d.complianceFrameworks.length > 0 ? d.complianceFrameworks.join(', ') : 'None'],
  ]

  return (
    <div className="space-y-5">
      {/* Summary card */}
      <div className="rounded-xl border border-slate-700 bg-slate-800/20 p-4">
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">
          Configuration Summary
        </p>
        <div className="grid grid-cols-2 gap-y-2 gap-x-4 text-xs">
          {summaryRows.map(([k, v]) => (
            <div key={k}>
              <span className="text-slate-500">{k}: </span>
              <span className="text-slate-200 capitalize">{v}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Evolution Engine */}
      <SwToggle
        checked={d.evolutionEnabled}
        onChange={v => set('evolutionEnabled', v)}
        label="Enable Evolution Engine"
        desc="Share anonymized jailbreak-detection rule bundles with federated communities. Each bundle requires admin approval before import."
      />

      {d.evolutionEnabled && (
        <InfoBox icon={Zap} color="amber">
          Rule bundles are screened through the security filter before sharing. No rules are
          distributed without explicit reviewer approval. The Evolution Engine operates in
          fail-open mode when no ANTHROPIC_API_KEY is configured.
        </InfoBox>
      )}

      {/* Notification channels */}
      <div className="space-y-3">
        <div className="flex items-center gap-2 text-sm font-medium text-slate-300">
          <Bell size={14} className="text-slate-400" />
          Notification Channels (optional)
        </div>
        <Field label="Slack Webhook URL">
          <Inp
            value={d.slackWebhook}
            onChange={e => set('slackWebhook', e.target.value)}
            placeholder="https://hooks.slack.com/services/..."
            type="url"
          />
        </Field>
        <Field label="Microsoft Teams Webhook URL">
          <Inp
            value={d.teamsWebhook}
            onChange={e => set('teamsWebhook', e.target.value)}
            placeholder="https://outlook.office.com/webhook/..."
            type="url"
          />
        </Field>
      </div>
    </div>
  )
}

// ── Success state ───────────────────────────────────────────────────────────

function SuccessScreen({ name, communityId, onView, onList }: {
  name: string; communityId: string; onView: () => void; onList: () => void
}) {
  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="text-center space-y-5 max-w-sm mx-auto">
        <div className="w-16 h-16 rounded-full bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center mx-auto">
          <Check size={28} className="text-emerald-400" />
        </div>
        <div>
          <h2 className="text-xl font-semibold text-white">Community Created</h2>
          <p className="text-sm text-slate-400 mt-1">
            <strong className="text-white">{name}</strong> is ready. A UECIID and Ed25519 keypair
            have been generated automatically.
          </p>
        </div>
        <div className="rounded-xl border border-slate-700 bg-slate-800/30 p-3 text-left">
          <p className="text-xs text-slate-500 mb-1">Community ID</p>
          <p className="text-xs font-mono text-slate-300 break-all">{communityId}</p>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row sm:justify-center">
          <button
            onClick={onView}
            className="px-5 py-2.5 bg-brand-400 hover:bg-brand-300 text-dark-900 text-sm font-semibold rounded-lg transition"
          >
            View Community →
          </button>
          <button
            onClick={onList}
            className="px-5 py-2.5 bg-slate-800 hover:bg-slate-700 text-white text-sm font-medium rounded-lg border border-slate-700 transition"
          >
            Back to List
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main wizard page ────────────────────────────────────────────────────────

function CreateCommunityWizard() {
  const router  = useRouter()
  const params  = useSearchParams()
  const isEdit  = params.get('edit') === 'true'
  const editId  = params.get('id') ?? ''

  const [step,        setStep]        = useState(0)
  const [data,        setData]        = useState<WizardData>(INIT)
  const [loading,     setLoading]     = useState(false)
  const [loadingData, setLoadingData] = useState(isEdit && !!editId)
  const [createdId,   setCreatedId]   = useState('')

  // Pre-fill state when editing an existing community
  useEffect(() => {
    if (!isEdit || !editId) return
    getCommunity(editId)
      .then(c => {
        const s = (c.settings ?? {}) as Record<string, unknown>
        setData(prev => ({
          ...prev,
          name:        c.name,
          description: c.description,
          visibility:  (c.visibility as WizardData['visibility']) ?? 'private',
          joinPolicy:  (c.join_policy as WizardData['joinPolicy']) ?? 'invite',
          cryptoMode:  (s.crypto_mode as WizardData['cryptoMode']) ?? 'classical',
          peeringEnabled:       Boolean(s.peering_enabled),
          peeringPolicy:        (s.peering_policy as WizardData['peeringPolicy']) ?? 'MIRROR_ONLY',
          tunnelRegions:        Array.isArray(s.tunnel_regions) ? (s.tunnel_regions as string[]) : [],
          stixAudit:            s.stix_audit !== false,
          docIntel:             s.doc_intel !== false,
          complianceFrameworks: Array.isArray(s.compliance_frameworks)
            ? (s.compliance_frameworks as string[]) : [],
          evolutionEnabled: Boolean(s.evolution_enabled),
          slackWebhook:     String(s.slack_webhook ?? ''),
          teamsWebhook:     String(s.teams_webhook ?? ''),
        }))
      })
      .catch(() => {/* community might not have settings yet — use defaults */})
      .finally(() => setLoadingData(false))
  }, [isEdit, editId])

  const set = useCallback((k: keyof WizardData, v: unknown) => {
    setData(prev => ({ ...prev, [k]: v }))
  }, [])

  const validate = (): string | null => {
    if (step === 0 && !data.name.trim()) return 'Community name is required'
    return null
  }

  const next = () => {
    const err = validate()
    if (err) { toast.error(err); return }
    setStep(s => Math.min(s + 1, STEPS.length - 1))
  }

  const back = () => setStep(s => Math.max(s - 1, 0))

  const submit = async () => {
    const err = validate()
    if (err) { toast.error(err); return }
    setLoading(true)

    try {
      if (isEdit && editId) {
        // ── Edit mode ───────────────────────────────────────────
        await patchCommunity(editId, {
          name:        data.name.trim(),
          description: data.description.trim(),
        }).catch(() => {/* fail-open */})

        for (const inv of data.invitations) {
          await addMember(editId, inv.tenantId, inv.role).catch(() =>
            toast(`Could not add ${inv.tenantId}`, { icon: '⚠️' })
          )
        }

        const settings: Record<string, unknown> = {
          peering_enabled:       data.peeringEnabled,
          peering_policy:        data.peeringPolicy,
          tunnel_regions:        data.tunnelRegions,
          stix_audit:            data.stixAudit,
          doc_intel:             data.docIntel,
          compliance_frameworks: data.complianceFrameworks,
          evolution_enabled:     data.evolutionEnabled,
        }
        if (data.slackWebhook) settings.slack_webhook = data.slackWebhook
        if (data.teamsWebhook) settings.teams_webhook = data.teamsWebhook
        await updateSettings(editId, settings).catch(() => {/* fail-open */})

        if (data.charterEnabled && data.charterText.trim()) {
          await uploadCharter(editId, data.charterText.trim()).catch(() => {/* fail-open */})
        }

        toast.success('Settings saved.')
        router.push(`/community-hub/${editId}`)
        return
      }

      // ── Create mode ─────────────────────────────────────────
      const community = await createCommunity(
        data.name.trim(),
        data.description.trim(),
        data.visibility,
        data.joinPolicy,
      )
      const cid = community.community_id

      if (data.cryptoMode === 'hybrid_pqc') {
        await upgradeToPQC(cid).catch(() =>
          toast('PQC upgrade skipped — requires Enterprise tier', { icon: '⚠️' })
        )
      }

      for (const inv of data.invitations) {
        await addMember(cid, inv.tenantId, inv.role).catch(() =>
          toast(`Could not invite ${inv.tenantId}`, { icon: '⚠️' })
        )
      }

      const settings: Record<string, unknown> = {
        peering_enabled:       data.peeringEnabled,
        peering_policy:        data.peeringPolicy,
        tunnel_regions:        data.tunnelRegions,
        stix_audit:            data.stixAudit,
        doc_intel:             data.docIntel,
        compliance_frameworks: data.complianceFrameworks,
        evolution_enabled:     data.evolutionEnabled,
      }
      if (data.slackWebhook) settings.slack_webhook = data.slackWebhook
      if (data.teamsWebhook) settings.teams_webhook = data.teamsWebhook
      await updateSettings(cid, settings).catch(() => {/* fail-open */})

      if (data.charterEnabled && data.charterText.trim()) {
        await uploadCharter(cid, data.charterText.trim()).catch(() => {/* fail-open */})
      }

      if (data.createDefaultAgent) {
        try {
          const WARDEN = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8001'
          const pub = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
          await fetch(`${WARDEN}/marketplace/agents/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              tenant_id:    community.creator_tenant_id ?? 'portal',
              community_id: cid,
              public_key:   pub,
              capabilities: ['marketplace_sell', 'marketplace_buy'],
            }),
          })
        } catch {
          /* fail-open — agent can be registered later from hub */
        }
      }

      setCreatedId(cid)
      toast.success('Community created successfully!')
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })
        .response?.data?.detail ?? (isEdit ? 'Failed to save changes' : 'Failed to create community')
      toast.error(msg)
    } finally {
      setLoading(false)
    }
  }

  if (createdId) {
    return (
      <SuccessScreen
        name={data.name}
        communityId={createdId}
        onView={() => router.push(`/community-hub/hub/${createdId}`)}
        onList={() => router.push('/community-hub')}
      />
    )
  }

  if (loadingData) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 size={24} className="animate-spin text-brand-400" />
      </div>
    )
  }

  const StepIcon = STEPS[step].icon
  const pct      = ((step + 1) / STEPS.length) * 100

  return (
    <div className="min-h-screen">
      <div className="max-w-2xl mx-auto px-4 py-8">
        {/* Back link */}
        <Link
          href={isEdit ? `/community-hub/${editId}` : '/community-hub'}
          className="inline-flex items-center gap-1.5 text-sm text-slate-500 hover:text-white transition mb-6"
        >
          <ArrowLeft size={15} /> {isEdit ? 'Back to Community' : 'Community Hub'}
        </Link>

        {/* Title */}
        <div className="mb-6">
          <h1 className="text-xl font-semibold text-white">
            {isEdit ? 'Edit Community Settings' : 'Create Community'}
          </h1>
          <p className="text-sm text-slate-500 mt-0.5">
            Step {step + 1} of {STEPS.length} — {STEPS[step].subtitle}
          </p>
        </div>

        {/* Progress bar */}
        <div className="h-1 bg-slate-800 rounded-full mb-6 overflow-hidden">
          <div
            className="h-full bg-brand-400 rounded-full transition-all duration-300"
            style={{ width: `${pct}%` }}
          />
        </div>

        {/* Step pills */}
        <div className="flex items-center gap-1 mb-8 overflow-x-auto pb-1">
          {STEPS.map((s, i) => {
            const Icon = s.icon
            const done = i < step
            const cur  = i === step
            return (
              <React.Fragment key={s.label}>
                <div className={[
                  'flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs whitespace-nowrap shrink-0 transition-all',
                  cur  ? 'bg-brand-400/15 text-brand-300 border border-brand-400/30 font-medium' :
                  done ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                         'bg-slate-800 text-slate-600 border border-slate-700',
                ].join(' ')}>
                  {done ? <Check size={10} /> : <Icon size={10} />}
                  <span className="hidden sm:inline">{s.label}</span>
                </div>
                {i < STEPS.length - 1 && (
                  <div className={`h-px w-4 shrink-0 ${i < step ? 'bg-emerald-500/30' : 'bg-slate-700'}`} />
                )}
              </React.Fragment>
            )
          })}
        </div>

        {/* Step card */}
        <div className="card mb-6">
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2.5 rounded-xl bg-brand-400/10 border border-brand-400/20 shrink-0">
              <StepIcon size={18} className="text-brand-400" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-white">{STEPS[step].label}</h2>
              <p className="text-xs text-slate-500">{STEPS[step].subtitle}</p>
            </div>
          </div>

          {step === 0 && <Step1 d={data} set={set} />}
          {step === 1 && <Step2 d={data} set={set} locked={isEdit} />}
          {step === 2 && <Step3 d={data} set={set} />}
          {step === 3 && <Step4 d={data} set={set} />}
          {step === 4 && <Step5 d={data} set={set} />}
          {step === 5 && <Step5_5 d={data} set={set} />}
          {step === 6 && <Step6 d={data} set={set} />}
        </div>

        {/* Navigation */}
        <div className="flex items-center justify-between">
          <button
            type="button"
            onClick={back}
            disabled={step === 0}
            className="flex items-center gap-1.5 px-4 py-2.5 text-sm text-slate-400 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed transition"
          >
            <ChevronLeft size={15} /> Back
          </button>

          {step < STEPS.length - 1 ? (
            <button
              type="button"
              onClick={next}
              className="flex items-center gap-1.5 px-5 py-2.5 btn-primary"
            >
              Continue <ChevronRight size={15} />
            </button>
          ) : (
            <button
              type="button"
              onClick={submit}
              disabled={loading}
              className="flex items-center gap-2 px-5 py-2.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-60 disabled:cursor-not-allowed text-white text-sm font-semibold rounded-lg transition"
            >
              {loading ? (
                <><Loader2 size={15} className="animate-spin" /> {isEdit ? 'Saving…' : 'Creating…'}</>
              ) : (
                <><Check size={15} /> {isEdit ? 'Save Changes' : 'Create Community'}</>
              )}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

export default function CreateCommunityPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 size={24} className="animate-spin text-brand-400" />
      </div>
    }>
      <CreateCommunityWizard />
    </Suspense>
  )
}
