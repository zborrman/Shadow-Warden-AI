import * as Sentry from '@sentry/nextjs'

// The portal has no middleware, so there is no edge runtime to configure.
export async function register() {
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    await import('./sentry.server.config')
  }
}

// Errors from Server Components and route handlers (storefront pages render on the server).
export const onRequestError = Sentry.captureRequestError
