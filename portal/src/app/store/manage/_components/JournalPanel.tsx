'use client'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { Check, Loader2, Mail, NotebookPen, Package, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui'
import { formatWhen } from '@/lib/prefs'
import { errorMessage, storeApi, type JournalEntry } from '@/lib/storeApi'

const when = (iso: string) => formatWhen(iso, true)

const field = 'w-full rounded-md border border-white/10 bg-dark-900 p-2 text-sm text-slate-100 focus:border-brand-500/50 focus:outline-none'

/** The customer's timeline. Messages are drafts: the seller sends them from its own mail client. */
export function JournalPanel({ storeId, customerId, email, panel }:
  { storeId: string; customerId: string; email: string; panel: string }) {
  const qc = useQueryClient()
  const key = ['m2m-journal', storeId, customerId]
  const entries = useQuery({ queryKey: key, queryFn: () => storeApi.journal(storeId, customerId) })
  const [kind, setKind] = useState<'note' | 'message'>('note')
  const [subject, setSubject] = useState('')
  const [body, setBody] = useState('')

  const refresh = () => qc.invalidateQueries({ queryKey: key })
  const add = useMutation({
    mutationFn: () => storeApi.addJournal(storeId, customerId,
      { kind, body, ...(kind === 'message' ? { subject } : {}) }),
    onSuccess: () => { setBody(''); setSubject(''); refresh() },
    onError: e => toast.error(errorMessage(e)),
  })

  return (
    <section className="space-y-3 border-t border-white/[0.06] p-4" aria-labelledby={`${panel}-journal`}>
      <h3 id={`${panel}-journal`} className="text-xs font-semibold uppercase tracking-wide text-slate-400">Journal</h3>

      <form className="space-y-2" onSubmit={e => { e.preventDefault(); if (body.trim()) add.mutate() }}>
        <div className="flex gap-2" role="radiogroup" aria-label="Entry type">
          {(['note', 'message'] as const).map(k => (
            <button key={k} type="button" role="radio" aria-checked={kind === k} onClick={() => setKind(k)}
                    className={`rounded-md border px-2.5 py-1 text-xs ${kind === k
                      ? 'border-brand-500/60 bg-brand-500/10 text-slate-100'
                      : 'border-white/10 text-slate-400 hover:text-slate-200'}`}>
              {k === 'note' ? 'Log a note' : 'Draft a message'}
            </button>
          ))}
        </div>
        {kind === 'message' && (
          <input aria-label="Subject" placeholder="Subject" maxLength={200} value={subject}
                 onChange={e => setSubject(e.target.value)} className={`h-9 ${field}`} />
        )}
        <textarea aria-label={kind === 'note' ? 'Note' : 'Message'} rows={3} maxLength={5000} value={body}
                  onChange={e => setBody(e.target.value)}
                  placeholder={kind === 'note' ? 'Called about sizes; will reorder in May'
                                               : 'Write the message, then send it from your own email'}
                  className={field} />
        <Button size="sm" type="submit" disabled={!body.trim() || add.isPending}>
          {add.isPending && <Loader2 className="animate-spin" />} {kind === 'note' ? 'Add note' : 'Save draft'}
        </Button>
      </form>

      {entries.isLoading ? (
        <div className="flex justify-center py-4"><Loader2 className="h-5 w-5 animate-spin text-slate-500" /></div>
      ) : entries.isError ? (
        <p className="text-sm text-red-400" role="alert">{errorMessage(entries.error)}</p>
      ) : (
        <ol className="space-y-2">
          {entries.data?.map(e => (
            <Entry key={e.id} entry={e} storeId={storeId} customerId={customerId} email={email}
                   onChange={refresh} />
          ))}
        </ol>
      )}
    </section>
  )
}

function Entry({ entry: e, storeId, customerId, email, onChange }: {
  entry: JournalEntry; storeId: string; customerId: string; email: string; onChange: () => void
}) {
  const [editing, setEditing] = useState<string | null>(null)
  const update = useMutation({
    mutationFn: (body: { body?: string; sent?: boolean }) =>
      storeApi.updateJournal(storeId, customerId, e.id, body),
    onSuccess: () => { setEditing(null); onChange() },
    onError: err => toast.error(errorMessage(err)),
  })
  const remove = useMutation({
    mutationFn: () => storeApi.deleteJournal(storeId, customerId, e.id),
    onSuccess: onChange,
    onError: err => toast.error(errorMessage(err)),
  })

  if (e.type === 'order') {
    return (
      <li className="flex items-center gap-2 text-xs text-slate-400">
        <Package className="h-3.5 w-3.5 shrink-0" aria-hidden />
        <span>Order request {e.status.replace('_', ' ').toLowerCase()}{e.by ? ` by ${e.by}` : ''}</span>
        <span className="ml-auto shrink-0">{when(e.at)}</span>
      </li>
    )
  }

  const draft = e.status === 'DRAFT'
  const mailto = `mailto:${email}?subject=${encodeURIComponent(e.subject)}&body=${encodeURIComponent(e.body)}`
  return (
    <li className="rounded-lg border border-white/10 p-3 text-sm">
      <div className="mb-1 flex items-center gap-2 text-xs text-slate-400">
        {e.type === 'note' ? <NotebookPen className="h-3.5 w-3.5" aria-hidden /> : <Mail className="h-3.5 w-3.5" aria-hidden />}
        <span>{e.type === 'note' ? 'Note' : draft ? 'Message draft' : 'Message sent'}</span>
        <span className="ml-auto">{when(e.at)}</span>
      </div>
      {e.subject && <p className="font-medium text-slate-100">{e.subject}</p>}
      {editing !== null ? (
        <textarea aria-label="Edit message" rows={4} maxLength={5000} value={editing}
                  onChange={ev => setEditing(ev.target.value)} className={field} />
      ) : (
        <p className="whitespace-pre-wrap text-slate-200">{e.body}</p>
      )}
      <div className="mt-2 flex flex-wrap gap-2">
        {draft && editing === null && <>
          <a href={mailto} className="inline-flex h-8 items-center gap-1 rounded-md border border-white/10 px-2.5 text-xs text-slate-200 hover:text-slate-50">
            <Mail className="h-3.5 w-3.5" aria-hidden /> Open in my email
          </a>
          <Button size="sm" variant="ghost" disabled={update.isPending} onClick={() => update.mutate({ sent: true })}>
            <Check /> Mark sent
          </Button>
          <Button size="sm" variant="ghost" onClick={() => setEditing(e.body)}>Edit</Button>
        </>}
        {draft && editing !== null && <>
          <Button size="sm" disabled={!editing.trim() || update.isPending} onClick={() => update.mutate({ body: editing })}>
            Save
          </Button>
          <Button size="sm" variant="ghost" onClick={() => setEditing(null)}>Cancel</Button>
        </>}
        <Button size="sm" variant="ghost" className="ml-auto text-red-300 hover:text-red-200" disabled={remove.isPending}
                onClick={() => { if (window.confirm('Delete this entry?')) remove.mutate() }}>
          <Trash2 /> Delete
        </Button>
      </div>
    </li>
  )
}
