/**
 * portal/src/lib/storefront/prefs.ts
 * Cookie names for the buyer's storefront choices. Shared by the server layout
 * (initial render) and the client provider (updates), so it must not be a
 * 'use client' module: a server import of one yields a reference, not the value.
 */
export const PREF_COOKIES = {
  locale: 'sf_lang', currency: 'sf_cur', units: 'sf_units', sidebar: 'sf_sidebar',
} as const
