// Shared Sentry options for the portal (browser + server).
//
// Errors only: no tracing, no profiling, no session replay. The storefront is
// where buyers type their name and address, so nothing a person typed or who
// they are may leave in an event:
// - dataCollection is off for every category (SDK 11 collects users, cookies,
//   headers, query strings and request/response bodies by default);
// - the URL loses its query and fragment - an order page carries the buyer's
//   token in "#t=", and that token opens the order;
// - request headers and console breadcrumbs are dropped.
// Unset NEXT_PUBLIC_SENTRY_DSN means the SDK stays off.
import type { Breadcrumb, ErrorEvent } from '@sentry/nextjs'

export const SENTRY_DSN = process.env.NEXT_PUBLIC_SENTRY_DSN || ''

const bareUrl = (u?: string) => (u ? u.split(/[?#]/)[0] : u)

export function scrubEvent(event: ErrorEvent): ErrorEvent {
  delete event.user
  if (event.request) {
    event.request.url = bareUrl(event.request.url)
    delete event.request.query_string
    delete event.request.cookies
    delete event.request.headers
    delete event.request.data
  }
  return event
}

export function scrubBreadcrumb(b: Breadcrumb): Breadcrumb | null {
  if (b.category === 'console') return null
  if (b.data && typeof b.data.url === 'string') b.data.url = bareUrl(b.data.url)
  if (b.data && typeof b.data.to === 'string') b.data.to = bareUrl(b.data.to)
  if (b.data && typeof b.data.from === 'string') b.data.from = bareUrl(b.data.from)
  return b
}

export const sentryOptions = {
  dsn: SENTRY_DSN,
  enabled: SENTRY_DSN !== '',
  environment: process.env.NODE_ENV,
  tracesSampleRate: 0,
  dataCollection: {
    userInfo: false,
    cookies: false,
    httpHeaders: false,
    httpBodies: [],
    urlQueryParams: false,
  },
  beforeSend: scrubEvent,
  beforeBreadcrumb: scrubBreadcrumb,
}
