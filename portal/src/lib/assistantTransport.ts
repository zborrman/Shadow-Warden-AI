/**
 * portal/src/lib/assistantTransport.ts
 * The seller consultant's chat transport for AI SDK `useChat`.
 *
 * The browser holds no model key and calls no model: it posts the conversation
 * to the gateway (`POST /m2m-store/assistant/chat` with `Accept:
 * text/event-stream`), which checks the plan's AI allowance, screens the
 * question and streams the reply in the AI SDK UI message stream format.
 * The request goes with the user's portal session, like every store call.
 */
import { DefaultChatTransport, type UIMessage } from 'ai'
import { API_URL, getAccessToken, refreshAccessToken } from './api'

/** The gateway accepts at most this many turns per request (`assist.MAX_TURNS`). */
export const MAX_TURNS = 20

/** UI messages → the `{role, content}` turns the gateway's schema takes; text parts only. */
export function toTurns(messages: UIMessage[]): { role: 'user' | 'assistant'; content: string }[] {
  return messages
    .filter(m => m.role === 'user' || m.role === 'assistant')
    .map(m => ({
      role: m.role as 'user' | 'assistant',
      content: m.parts.map(p => (p.type === 'text' ? p.text : '')).join('').trim(),
    }))
    .filter(t => t.content)
    .slice(-MAX_TURNS)
}

/** fetch with the session token; one refresh and retry on a 401, as the axios client does. */
const sessionFetch: typeof fetch = async (input, init) => {
  const send = (token: string | null) => {
    const headers = new Headers(init?.headers)
    headers.set('Accept', 'text/event-stream')
    if (token) headers.set('Authorization', `Bearer ${token}`)
    return fetch(input, { ...init, headers })
  }
  const first = await send(getAccessToken())
  if (first.status !== 401) return first
  try {
    return await send(await refreshAccessToken())
  } catch {
    if (typeof window !== 'undefined') window.location.href = '/login/'
    return first
  }
}

export function assistantTransport() {
  return new DefaultChatTransport({
    api: `${API_URL}/m2m-store/assistant/chat`,
    fetch: sessionFetch,
    prepareSendMessagesRequest: ({ messages }) => ({ body: { messages: toTurns(messages) } }),
  })
}

/**
 * The transport throws the response body of a refused request as the error
 * message; turn the gateway's `{detail}` into a sentence for the seller.
 */
export function assistantError(err: Error | undefined): string {
  if (!err) return ''
  try {
    const detail = (JSON.parse(err.message) as { detail?: unknown }).detail
    if (detail && typeof detail === 'object' && (detail as { error?: string }).error === 'ai_budget') {
      return "This month's AI allowance on your plan is used up."
    }
    if (typeof detail === 'string') return detail
  } catch {
    // Not JSON: an error part from the stream, or a network failure.
  }
  return err.message || 'The assistant did not answer. Try again.'
}
