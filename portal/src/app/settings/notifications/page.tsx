'use client'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Bell, Plus, Trash2, CheckCircle2, AlertCircle, Zap } from 'lucide-react'
import { settingsApi, type NotificationChannel } from '@/lib/settingsApi'
import { TopBar } from '@/components/layout/TopBar'
import { z } from 'zod'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'

function Toast({ msg, ok }: { msg: string; ok: boolean }) {
  return (
    <div className={`fixed bottom-6 right-6 flex items-center gap-2 px-4 py-3 rounded-xl border text-sm font-medium shadow-xl z-50 ${
      ok ? 'bg-green-500/10 border-green-500/20 text-green-400' : 'bg-red-500/10 border-red-500/20 text-red-400'
    }`}>
      {ok ? <CheckCircle2 className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
      {msg}
    </div>
  )
}

const CHANNEL_TYPES = [
  { value: 'slack',     label: 'Slack Webhook',   icon: '💬' },
  { value: 'teams',     label: 'Microsoft Teams',  icon: '💼' },
  { value: 'webhook',   label: 'Generic Webhook',  icon: '🔗' },
  { value: 'pagerduty', label: 'PagerDuty',        icon: '🚨' },
  { value: 'telegram',  label: 'Telegram Bot',     icon: '✈️' },
  { value: 'email',     label: 'Email',            icon: '📧' },
]

const channelSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('slack'),     label: z.string().min(1).max(80), url: z.string().url() }),
  z.object({ type: z.literal('teams'),     label: z.string().min(1).max(80), url: z.string().url() }),
  z.object({ type: z.literal('webhook'),   label: z.string().min(1).max(80), url: z.string().url() }),
  z.object({ type: z.literal('pagerduty'), label: z.string().min(1).max(80), routing_key: z.string().min(1) }),
  z.object({ type: z.literal('telegram'),  label: z.string().min(1).max(80), bot_token: z.string().min(1), chat_id: z.string().min(1) }),
  z.object({ type: z.literal('email'),     label: z.string().min(1).max(80), email: z.string().email() }),
])

type ChannelForm = z.infer<typeof channelSchema>

function buildConfig(data: ChannelForm): Record<string, string> {
  switch (data.type) {
    case 'slack':
    case 'teams':
    case 'webhook':   return { url: data.url }
    case 'pagerduty': return { routing_key: data.routing_key }
    case 'telegram':  return { bot_token: data.bot_token, chat_id: data.chat_id }
    case 'email':     return { email: data.email }
  }
}

export default function NotificationsPage() {
  const qc = useQueryClient()
  const [creating, setCreating] = useState(false)
  const [testingId, setTestingId] = useState<string | null>(null)
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null)

  const { data: channels = [] } = useQuery({
    queryKey: ['settings', 'channels'],
    queryFn: settingsApi.listChannels,
  })

  const { register, handleSubmit, watch, reset, formState: { errors, isSubmitting } } = useForm<ChannelForm>({
    resolver: zodResolver(channelSchema),
    defaultValues: { type: 'slack', label: '', url: '' },
  })
  const selectedType = watch('type') as string

  const addMut = useMutation({
    mutationFn: (d: ChannelForm) => settingsApi.addChannel({ type: d.type, label: d.label, config: buildConfig(d) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['settings', 'channels'] }); reset(); setCreating(false); showToast('Channel added', true) },
    onError: () => showToast('Failed to add channel', false),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => settingsApi.deleteChannel(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['settings', 'channels'] }); showToast('Channel deleted', true) },
    onError: () => showToast('Failed to delete channel', false),
  })

  async function testChannel(id: string) {
    setTestingId(id)
    try {
      const result = await settingsApi.testChannel(id)
      qc.invalidateQueries({ queryKey: ['settings', 'channels'] })
      showToast(result.ok ? `Test sent (${result.latency_ms}ms)` : result.message, result.ok)
    } catch {
      showToast('Test failed', false)
    } finally {
      setTestingId(null)
    }
  }

  function showToast(msg: string, ok: boolean) {
    setToast({ msg, ok })
    setTimeout(() => setToast(null), 3500)
  }

  const ct = CHANNEL_TYPES.find(c => c.value === selectedType)

  return (
    <>
      <TopBar title="Notification Channels" />
      <div className="flex-1 p-6 max-w-2xl">

        <div className="card p-6">
          <div className="flex items-center justify-between mb-5">
            <div>
              <h2 className="font-semibold text-white">Channels</h2>
              <p className="text-sm text-slate-400 mt-0.5">{channels.length} channel{channels.length !== 1 ? 's' : ''}</p>
            </div>
            <button onClick={() => setCreating(c => !c)} className="btn-primary flex items-center gap-2 text-sm">
              <Plus className="w-4 h-4" /> Add channel
            </button>
          </div>

          {creating && (
            <form onSubmit={handleSubmit(d => addMut.mutateAsync(d))}
                  className="p-4 rounded-xl bg-white/[0.03] border border-white/[0.06] mb-5 space-y-3">
              <div>
                <label className="label">Channel type</label>
                <select {...register('type')} className="input">
                  {CHANNEL_TYPES.map(c => <option key={c.value} value={c.value}>{c.icon} {c.label}</option>)}
                </select>
              </div>
              <div>
                <label className="label">Label</label>
                <input {...register('label')} placeholder="e.g. SOC Alerts, PagerDuty On-call" className="input" />
              </div>

              {['slack', 'teams', 'webhook'].includes(selectedType) && (
                <div>
                  <label className="label">Webhook URL</label>
                  <input {...register('url' as any)} type="url" placeholder="https://..." className="input" />
                  {(errors as any).url && <p className="text-red-400 text-xs mt-1">{(errors as any).url?.message}</p>}
                </div>
              )}
              {selectedType === 'pagerduty' && (
                <div>
                  <label className="label">Routing Key</label>
                  <input {...register('routing_key' as any)} placeholder="Events API v2 routing key" className="input font-mono text-sm" />
                </div>
              )}
              {selectedType === 'telegram' && (
                <>
                  <div>
                    <label className="label">Bot Token</label>
                    <input {...register('bot_token' as any)} placeholder="123456:ABCdef..." className="input font-mono text-sm" />
                  </div>
                  <div>
                    <label className="label">Chat ID</label>
                    <input {...register('chat_id' as any)} placeholder="-100..." className="input" />
                  </div>
                </>
              )}
              {selectedType === 'email' && (
                <div>
                  <label className="label">Email address</label>
                  <input {...register('email' as any)} type="email" placeholder="ops@example.com" className="input" />
                </div>
              )}

              <div className="flex gap-2 pt-1">
                <button type="submit" disabled={isSubmitting || addMut.isPending} className="btn-primary text-sm">
                  {(isSubmitting || addMut.isPending) ? <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : 'Add Channel'}
                </button>
                <button type="button" onClick={() => { setCreating(false); reset() }} className="btn-secondary text-sm">Cancel</button>
              </div>
            </form>
          )}

          {channels.length === 0 && !creating ? (
            <p className="text-sm text-slate-500 text-center py-6">No channels yet. Add Slack, Teams, PagerDuty, or any webhook.</p>
          ) : (
            <div className="space-y-1">
              {channels.map(ch => (
                <ChannelRow
                  key={ch.id}
                  channel={ch}
                  testing={testingId === ch.id}
                  onTest={() => testChannel(ch.id)}
                  onDelete={() => deleteMut.mutate(ch.id)}
                />
              ))}
            </div>
          )}
        </div>

        {toast && <Toast {...toast} />}
      </div>
    </>
  )
}

function ChannelRow({ channel, testing, onTest, onDelete }: {
  channel: NotificationChannel
  testing: boolean
  onTest: () => void
  onDelete: () => void
}) {
  const ct = CHANNEL_TYPES.find(c => c.value === channel.type)
  const configSummary = Object.entries(channel.config)
    .map(([k, v]) => `${k}: ${v}`)
    .join(' · ')

  return (
    <div className="flex items-center gap-3 p-3 rounded-xl hover:bg-white/[0.02] transition-colors">
      <div className="w-8 h-8 rounded-lg bg-brand-400/10 flex items-center justify-center shrink-0 text-base">
        {ct?.icon ?? <Bell className="w-4 h-4" />}
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <p className="text-sm font-medium text-white">{channel.label}</p>
          <span className="text-[10px] font-semibold text-slate-500 uppercase">{ct?.label ?? channel.type}</span>
          {channel.verified && (
            <span className="text-[10px] font-bold text-green-400 bg-green-400/10 px-1.5 py-0.5 rounded">Verified</span>
          )}
        </div>
        <p className="text-xs text-slate-600 mt-0.5 truncate">{configSummary}</p>
      </div>
      <div className="flex items-center gap-1 shrink-0">
        <button
          onClick={onTest}
          disabled={testing}
          className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
        >
          {testing
            ? <span className="w-3 h-3 border border-white/30 border-t-white rounded-full animate-spin" />
            : <Zap className="w-3.5 h-3.5" />}
          Test
        </button>
        <button onClick={onDelete} className="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-red-400/10 transition-colors">
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  )
}
