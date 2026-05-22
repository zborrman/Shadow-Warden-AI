'use client'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { BookOpen, Plus, Search, Tag, TrendingUp, Copy, Check } from 'lucide-react'
import clsx from 'clsx'
import { TopBar } from '@/components/layout/TopBar'
import { promptApi, type PromptEntry } from '@/lib/smbApi'

const CAT_COLOR: Record<string, string> = {
  general:    'bg-slate-500/15 text-slate-300',
  security:   'bg-red-500/15 text-red-300',
  compliance: 'bg-blue-500/15 text-blue-300',
  finance:    'bg-green-500/15 text-green-300',
  hr:         'bg-purple-500/15 text-purple-300',
  marketing:  'bg-yellow-500/15 text-yellow-300',
}

export default function PromptsPage() {
  const qc = useQueryClient()
  const [community, setCommunity] = useState('default')
  const [search, setSearch]       = useState('')
  const [showAdd, setShowAdd]     = useState(false)
  const [copied, setCopied]       = useState<string | null>(null)
  const [form, setForm]           = useState({ title: '', prompt_text: '', category: 'general', created_by: 'portal-user' })

  const { data, isLoading } = useQuery({
    queryKey: ['prompts', community],
    queryFn:  () => promptApi.list(community),
  })

  const create = useMutation({
    mutationFn: () => promptApi.create({ community_id: community, ...form }),
    onSuccess:  () => {
      qc.invalidateQueries({ queryKey: ['prompts', community] })
      setShowAdd(false)
      setForm({ title: '', prompt_text: '', category: 'general', created_by: 'portal-user' })
    },
  })

  const use = useMutation({
    mutationFn: (id: string) => promptApi.use(id),
    onSuccess:  () => qc.invalidateQueries({ queryKey: ['prompts', community] }),
  })

  async function copyPrompt(p: PromptEntry) {
    await navigator.clipboard.writeText(p.prompt_text ?? p.title)
    setCopied(p.prompt_id)
    use.mutate(p.prompt_id)
    setTimeout(() => setCopied(null), 2000)
  }

  const prompts: PromptEntry[] = data?.prompts ?? []
  const filtered = prompts.filter(p =>
    !search || p.title.toLowerCase().includes(search.toLowerCase()) ||
    p.category.toLowerCase().includes(search.toLowerCase()))

  return (
    <div className="flex flex-col h-screen">
      <TopBar title="Prompt Library" />
      <div className="flex-1 overflow-y-auto p-6 space-y-5">

        {/* Controls */}
        <div className="flex items-center gap-3 flex-wrap">
          <label className="text-xs text-slate-400">Community</label>
          <input className="input w-40 text-sm" value={community} onChange={e => setCommunity(e.target.value)} />
          <div className="relative flex-1 max-w-xs">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
            <input className="input pl-8 text-sm" placeholder="Search prompts…" value={search}
              onChange={e => setSearch(e.target.value)} />
          </div>
          <button onClick={() => setShowAdd(v => !v)} className="btn-primary text-sm px-4 py-2 ml-auto">
            <Plus className="w-4 h-4" /> Add Prompt
          </button>
        </div>

        {/* Add form */}
        {showAdd && (
          <div className="card p-5 space-y-3">
            <h3 className="text-sm font-semibold text-white">Add Prompt to Library</h3>
            <input className="input" placeholder="Prompt title" value={form.title}
              onChange={e => setForm(f => ({ ...f, title: e.target.value }))} />
            <div className="grid grid-cols-2 gap-3">
              <select className="input" value={form.category}
                onChange={e => setForm(f => ({ ...f, category: e.target.value }))}>
                {['general', 'security', 'compliance', 'finance', 'hr', 'marketing'].map(c =>
                  <option key={c} value={c}>{c}</option>)}
              </select>
              <input className="input" placeholder="Your name / ID" value={form.created_by}
                onChange={e => setForm(f => ({ ...f, created_by: e.target.value }))} />
            </div>
            <textarea className="input min-h-24 resize-none font-mono text-sm" placeholder="Prompt text…"
              value={form.prompt_text} onChange={e => setForm(f => ({ ...f, prompt_text: e.target.value }))} />
            <p className="text-[11px] text-slate-500">
              Prompts are screened by the 9-layer filter pipeline before saving.
            </p>
            <div className="flex gap-2 justify-end">
              <button onClick={() => setShowAdd(false)} className="btn-secondary text-sm px-3 py-1.5">Cancel</button>
              <button onClick={() => create.mutate()} disabled={!form.title || !form.prompt_text || create.isPending}
                className="btn-primary text-sm px-4 py-1.5">
                {create.isPending ? 'Screening…' : 'Save Prompt'}
              </button>
            </div>
            {create.isError && (
              <p className="text-xs text-red-400">{String((create.error as Error)?.message)}</p>
            )}
          </div>
        )}

        {/* Prompt grid */}
        {isLoading ? (
          <p className="text-center py-12 text-slate-500 text-sm">Loading…</p>
        ) : filtered.length === 0 ? (
          <div className="text-center py-12">
            <BookOpen className="w-8 h-8 text-slate-600 mx-auto mb-3" />
            <p className="text-sm text-slate-500">{search ? 'No prompts match your search.' : 'No prompts yet — add one above.'}</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {filtered.map((p: PromptEntry) => (
              <div key={p.prompt_id} className="card p-4 space-y-3 group hover:border-white/10 transition-all">
                <div className="flex items-start justify-between gap-2">
                  <h3 className="text-sm font-medium text-white leading-snug flex-1">{p.title}</h3>
                  <button
                    onClick={() => copyPrompt(p)}
                    className="opacity-0 group-hover:opacity-100 p-1.5 rounded-lg text-slate-400 hover:text-brand-400 hover:bg-brand-400/10 transition-all shrink-0"
                    title="Copy & record use"
                  >
                    {copied === p.prompt_id ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                {p.description && <p className="text-xs text-slate-500 line-clamp-2">{p.description}</p>}
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={clsx('text-[11px] px-2 py-0.5 rounded-full flex items-center gap-1',
                    CAT_COLOR[p.category] ?? 'bg-slate-500/15 text-slate-300')}>
                    <Tag className="w-2.5 h-2.5" /> {p.category}
                  </span>
                  <span className="text-[11px] text-slate-500 flex items-center gap-1 ml-auto">
                    <TrendingUp className="w-3 h-3" /> {p.use_count} uses
                  </span>
                </div>
                <div className="flex items-center justify-between text-[11px] text-slate-600">
                  <span>v{p.version}</span>
                  <span className={clsx('px-1.5 py-0.5 rounded',
                    p.visibility === 'community' ? 'text-blue-400' : 'text-slate-400')}>
                    {p.visibility}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
