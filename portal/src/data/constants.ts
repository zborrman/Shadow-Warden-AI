/**
 * portal/src/data/constants.ts
 * ────────────────────────────
 * Single source of truth for all static data used across the portal:
 * industries, risk levels, flag types, OWASP LLM Top 10, plan configs.
 */

// ── Industries (Dollar Impact Calculator) ─────────────────────────────────────

export interface Industry {
  id:         string
  label:      string
  multiplier: number
  description: string
}

export const INDUSTRIES: Industry[] = [
  { id: 'generic',    label: 'Generic',               multiplier: 1.0, description: 'Baseline IBM 2024 breach cost' },
  { id: 'finance',    label: 'Finance / Banking',      multiplier: 2.4, description: 'PCI-DSS, SOX exposure' },
  { id: 'healthcare', label: 'Healthcare',             multiplier: 3.2, description: 'HIPAA + patient data liability' },
  { id: 'tech',       label: 'Technology',             multiplier: 1.8, description: 'IP theft, customer data' },
  { id: 'retail',     label: 'Retail / E-Commerce',   multiplier: 1.5, description: 'PCI-DSS, customer PII' },
  { id: 'government', label: 'Government',             multiplier: 1.9, description: 'National security, FISMA' },
  { id: 'legal',      label: 'Legal / Professional',   multiplier: 2.1, description: 'Attorney-client privilege, GDPR' },
]

export const INDUSTRY_MAP = Object.fromEntries(INDUSTRIES.map(i => [i.id, i]))

// ── Risk levels ────────────────────────────────────────────────────────────────

export type RiskLevel = 'low' | 'medium' | 'high' | 'block'

export const RISK_LEVELS: Record<RiskLevel, { label: string; color: string; bg: string; border: string }> = {
  low:    { label: 'Low',    color: 'text-green-400',  bg: 'bg-green-400/10',  border: 'border-green-400/20' },
  medium: { label: 'Medium', color: 'text-amber-400',  bg: 'bg-amber-400/10',  border: 'border-amber-400/20' },
  high:   { label: 'High',   color: 'text-orange-400', bg: 'bg-orange-400/10', border: 'border-orange-400/20' },
  block:  { label: 'Block',  color: 'text-red-400',    bg: 'bg-red-400/10',    border: 'border-red-400/20' },
}

// ── Flag types ─────────────────────────────────────────────────────────────────

export interface FlagType {
  id:          string
  label:       string
  description: string
  owasp?:      string
}

export const FLAG_TYPES: FlagType[] = [
  { id: 'prompt_injection',    label: 'Prompt Injection',    description: 'Direct instruction override attempt',         owasp: 'LLM01' },
  { id: 'jailbreak',          label: 'Jailbreak',           description: 'Safety/alignment bypass attempt',             owasp: 'LLM01' },
  { id: 'indirect_injection', label: 'Indirect Injection',  description: 'Tool/document-mediated injection',            owasp: 'LLM02' },
  { id: 'injection_chain',    label: 'Injection Chain',     description: 'Multi-step injection sequence detected',      owasp: 'LLM01' },
  { id: 'tool_abuse',         label: 'Tool Abuse',          description: 'Malicious use of agent tool capabilities',    owasp: 'LLM06' },
  { id: 'data_exfiltration',  label: 'Data Exfiltration',   description: 'Attempt to extract sensitive data',           owasp: 'LLM02' },
  { id: 'pii_leakage',        label: 'PII Leakage',         description: 'Personal data in prompt or response',         owasp: 'LLM06' },
  { id: 'api_abuse',          label: 'API Abuse',           description: 'Rate/quota/billing abuse pattern',            owasp: 'LLM04' },
  { id: 'topological_noise',  label: 'Topological Noise',   description: 'High structural entropy — TDA gatekeeper',   owasp: 'LLM01' },
  { id: 'causal_high_risk',   label: 'Causal High Risk',    description: 'Bayesian DAG escalation in gray zone',       owasp: 'LLM01' },
  { id: 'policy_violation',   label: 'Policy Violation',    description: 'Custom content policy breach',                owasp: 'LLM09' },
  { id: 'service_denial',     label: 'Service Denial',      description: 'DoS / resource exhaustion pattern',           owasp: 'LLM04' },
  { id: 'compliance',         label: 'Compliance',          description: 'Regulatory / legal content restriction',      owasp: 'LLM09' },
]

// ── OWASP LLM Top 10 ──────────────────────────────────────────────────────────

export const OWASP_LLM: Record<string, { label: string; color: string }> = {
  LLM01: { label: 'Prompt Injection',             color: 'text-red-400' },
  LLM02: { label: 'Insecure Output Handling',     color: 'text-orange-400' },
  LLM03: { label: 'Training Data Poisoning',      color: 'text-violet-400' },
  LLM04: { label: 'Model Denial of Service',      color: 'text-blue-400' },
  LLM05: { label: 'Supply Chain Vulnerabilities', color: 'text-orange-400' },
  LLM06: { label: 'Sensitive Info Disclosure',    color: 'text-amber-400' },
  LLM07: { label: 'Insecure Plugin Design',       color: 'text-orange-400' },
  LLM08: { label: 'Excessive Agency',             color: 'text-violet-400' },
  LLM09: { label: 'Overreliance',                 color: 'text-slate-400' },
  LLM10: { label: 'Model Theft',                  color: 'text-blue-400' },
}

// ── Plans ─────────────────────────────────────────────────────────────────────

export interface Plan {
  id:            string
  label:         string
  requestsQuota: number
  priceUsd:      number
  features:      string[]
}

export const PLANS: Plan[] = [
  {
    id: 'starter', label: 'Starter', requestsQuota: 10_000, priceUsd: 0,
    features: ['10k requests/mo', 'Core detection pipeline', 'Email support'],
  },
  {
    id: 'pro', label: 'Pro', requestsQuota: 250_000, priceUsd: 99,
    features: ['250k requests/mo', 'Evolution Engine', 'Slack alerts', 'Priority support'],
  },
  {
    id: 'msp', label: 'MSP', requestsQuota: -1, priceUsd: 499,
    features: ['Unlimited requests', 'Multi-tenant', 'SIEM integration', 'Dedicated SLA'],
  },
]

// ── Shadow ban strategies ──────────────────────────────────────────────────────

export const SHADOW_BAN_STRATEGIES = [
  {
    id:          'gaslight',
    label:       'Gaslight',
    description: 'Returns convincing fake "allowed" response — attacker believes they succeeded',
    triggers:    ['prompt_injection', 'jailbreak', 'injection_chain'],
    color:       'text-violet-400',
  },
  {
    id:          'delay',
    label:       'Delay',
    description: 'Adds async delay (default 3s) before block — increases cost for automation',
    triggers:    ['api_abuse', 'topological_noise', 'service_denial'],
    color:       'text-amber-400',
  },
  {
    id:          'standard',
    label:       'Standard',
    description: 'Immediate block response for all other threat types',
    triggers:    ['*'],
    color:       'text-slate-400',
  },
]

// ── IBM 2024 breach cost constants (Dollar Impact Calculator) ──────────────────

export const IBM_2024 = {
  avgBreachCostUsd:  4_880_000,
  incidentBaseRate:  0.012,       // per month per 100k requests
  avgCostPerRequest: 0.0008,      // LLM token cost
  shadowBanRate:     0.015,       // fraction of requests shadow-banned
  socHourlyRate:     85,          // USD / hour
  triageHoursPerInc: 2.5,
}

// ── Navigation items ───────────────────────────────────────────────────────────

export const NAV_ITEMS = [
  { href: '/dashboard/', label: 'Dashboard',  icon: 'LayoutDashboard' },
  { href: '/api-keys/',  label: 'API Keys',   icon: 'Key' },
  { href: '/settings/',  label: 'Settings',   icon: 'Settings' },
] as const
