/**
 * portal/src/services/notifications.ts
 * ──────────────────────────────────────
 * Notification preference business logic — maps user settings to
 * display labels and manages update mutations cleanly.
 */
import { api } from '@/lib/api'

export interface NotificationPrefs {
  notify_high:  boolean
  notify_block: boolean
}

export const NOTIFICATION_OPTIONS = [
  {
    field:   'notify_high'  as const,
    label:   'High-risk alerts',
    desc:    'Notify when HIGH risk signals are detected in filter pipeline',
    default: true,
  },
  {
    field:   'notify_block' as const,
    label:   'Block-level alerts',
    desc:    'Notify when requests are fully blocked by the gateway',
    default: true,
  },
]

export async function updateNotificationPrefs(prefs: Partial<NotificationPrefs>) {
  const r = await api.patch('/me', prefs)
  return r.data
}
