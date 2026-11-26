import { api, setAccessToken } from './api'

export interface LoginResult {
  access_token: string
  expires_in: number
}

/** With two-factor on, the server answers with a short-lived session instead of a token. */
export interface TotpChallenge {
  requires_totp: true
  totp_session: string
}

/** No authenticator yet: two-step sign-in is required, so the password opens enrolment only. */
export interface TotpSetupRequired {
  requires_totp_setup: true
  setup_session: string
}

export type LoginAnswer = LoginResult | TotpChallenge | TotpSetupRequired

export async function login(email: string, password: string): Promise<LoginAnswer> {
  const { data } = await api.post<LoginAnswer>('/auth/login', { email, password })
  if ('requires_totp' in data || 'requires_totp_setup' in data) return data
  setAccessToken(data.access_token)
  return data
}

/** Required enrolment, step 1: a fresh key for the authenticator app. */
export async function enrollStart(setup_session: string): Promise<{ secret: string; otpauth_uri: string }> {
  const { data } = await api.post('/auth/totp/enroll/start', { setup_session })
  return data
}

/** Required enrolment, step 2: the first code turns 2FA on and opens the session. */
export async function enrollFinish(setup_session: string, code: string): Promise<LoginResult> {
  const { data } = await api.post<LoginResult>('/auth/totp/enroll/finish', { setup_session, code })
  setAccessToken(data.access_token)
  return data
}

/** Second step of a two-factor sign-in: the 6-digit code from the authenticator app. */
export async function completeTotp(totp_session: string, code: string): Promise<LoginResult> {
  const { data } = await api.post<LoginResult>('/auth/totp/complete', { totp_session, code })
  setAccessToken(data.access_token)
  return data
}

export async function register(email: string, password: string, display_name?: string) {
  const { data } = await api.post('/auth/register', { email, password, display_name })
  return data
}

export async function logout() {
  await api.post('/auth/logout').catch(() => {})
  setAccessToken(null)
}

export async function refreshSession(): Promise<boolean> {
  try {
    const { data } = await api.post<LoginResult>('/auth/refresh')
    setAccessToken(data.access_token)
    return true
  } catch {
    setAccessToken(null)
    return false
  }
}

export async function forgotPassword(email: string) {
  const { data } = await api.post('/auth/forgot-password', { email })
  return data
}

export async function resetPassword(token: string, new_password: string) {
  const { data } = await api.post('/auth/reset-password', { token, new_password })
  return data
}
