'use client'
// R8.6b: the seller consultant. The conversation lives only in this component:
// nothing is stored on the server, and a reload starts a new conversation.
import { useRef, useState } from 'react'
import { Loader2, Send } from 'lucide-react'
import { Button } from '@/components/ui'
import { errorMessage, storeApi } from '@/lib/storeApi'

type Turn = { role: 'user' | 'assistant'; content: string }

const STARTERS = [
  'What changed for FBA labels in 2026?',
  'Which words in my title can get a listing removed?',
  'What does Amazon expect in a Plan of Action?',
  'What do EU buyers need to see on my product page?',
]

export function AssistantTab() {
  const [turns, setTurns] = useState<Turn[]>([])
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const end = useRef<HTMLDivElement>(null)

  async function ask(q: string) {
    const question = q.trim()
    if (!question || busy) return
    const next: Turn[] = [...turns, { role: 'user', content: question }].slice(-19) as Turn[]
    setTurns(next); setText(''); setBusy(true); setError('')
    try {
      const { reply } = await storeApi.assistantChat(next)
      setTurns(t => [...t, { role: 'assistant', content: reply }])
    } catch (e) {
      const r = (e as { response?: { status?: number; data?: { detail?: { error?: string } } } }).response
      setError(r?.status === 403 && r.data?.detail?.error === 'ai_budget'
        ? "This month's AI allowance on your plan is used up." : errorMessage(e))
    } finally {
      setBusy(false)
      setTimeout(() => end.current?.scrollIntoView({ behavior: 'smooth' }), 50)
    }
  }

  return (
    <div className="flex h-[70vh] flex-col rounded-xl border border-white/10 bg-dark-800">
      <div className="flex-1 space-y-3 overflow-y-auto p-4">
        {turns.length === 0 && (
          <div className="space-y-3">
            <p className="text-sm text-slate-300">
              Ask about Amazon rules, FBA labels, listing claims, EU product safety or an appeal. Answers come from a
              checked knowledge base; they are guidance, not legal advice.
            </p>
            <div className="flex flex-wrap gap-2">
              {STARTERS.map(s => (
                <button key={s} type="button" onClick={() => ask(s)}
                        className="rounded-full border border-white/10 px-3 py-1.5 text-xs text-slate-300 hover:border-white/25">
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}
        {turns.map((t, i) => (
          <div key={i} className={t.role === 'user' ? 'flex justify-end' : 'flex justify-start'}>
            <p className={`max-w-[85%] whitespace-pre-wrap rounded-2xl px-4 py-2.5 text-sm ${t.role === 'user'
              ? 'bg-brand-500/20 text-slate-100' : 'border border-white/10 bg-dark-900 text-slate-200'}`}>{t.content}</p>
          </div>
        ))}
        {busy && <p className="flex items-center gap-2 text-xs text-slate-400"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Thinking…</p>}
        {error && <p className="text-sm text-red-400" role="alert">{error}</p>}
        <div ref={end} />
      </div>
      <form className="flex gap-2 border-t border-white/10 p-3" onSubmit={e => { e.preventDefault(); ask(text) }}>
        <label htmlFor="assistant-q" className="sr-only">Your question</label>
        <textarea id="assistant-q" rows={2} maxLength={2000} value={text} onChange={e => setText(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); ask(text) } }}
                  placeholder="Ask in any language…"
                  className="flex-1 resize-none rounded-lg border border-white/10 bg-dark-900 px-3 py-2 text-sm text-slate-100 focus:border-brand-500/50 focus:outline-none" />
        <Button type="submit" disabled={busy || !text.trim()}><Send /> Ask</Button>
      </form>
      <p className="px-4 pb-3 text-[11px] text-slate-500">
        The conversation is kept only in this page. Do not paste buyers’ names or addresses.
      </p>
    </div>
  )
}
