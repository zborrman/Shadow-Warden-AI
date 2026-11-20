'use client'
// Display preferences, kept on this device (localStorage), like the theme.
// They change how dates read in the portal; nothing is sent to the server.
import { useCallback, useEffect, useState } from 'react'

export interface Prefs {
  /** IANA zone, e.g. "Asia/Jerusalem". Empty: the browser's own zone. */
  timeZone: string
  hour12: boolean
}

const KEY = 'sw_prefs'
const EVENT = 'sw-prefs'
const DEFAULTS: Prefs = { timeZone: '', hour12: false }

export function readPrefs(): Prefs {
  if (typeof window === 'undefined') return DEFAULTS
  try {
    return { ...DEFAULTS, ...JSON.parse(localStorage.getItem(KEY) || '{}') }
  } catch {
    return DEFAULTS
  }
}

export function usePrefs(): [Prefs, (p: Partial<Prefs>) => void] {
  const [prefs, setState] = useState<Prefs>(DEFAULTS)
  useEffect(() => {
    setState(readPrefs())
    const sync = () => setState(readPrefs())
    window.addEventListener(EVENT, sync)
    window.addEventListener('storage', sync)
    return () => { window.removeEventListener(EVENT, sync); window.removeEventListener('storage', sync) }
  }, [])
  const update = useCallback((p: Partial<Prefs>) => {
    const next = { ...readPrefs(), ...p }
    localStorage.setItem(KEY, JSON.stringify(next))
    window.dispatchEvent(new Event(EVENT))
  }, [])
  return [prefs, update]
}

/** A date (and optionally time) in the user's chosen zone and clock. */
export function formatWhen(iso: string, withTime = false, prefs: Prefs = readPrefs()): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return new Intl.DateTimeFormat('en-GB', {
    dateStyle: 'medium',
    ...(withTime ? { timeStyle: 'short', hour12: prefs.hour12 } : {}),
    ...(prefs.timeZone ? { timeZone: prefs.timeZone } : {}),
  }).format(d)
}

export function browserTimeZone(): string {
  return Intl.DateTimeFormat().resolvedOptions().timeZone
}
