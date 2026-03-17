import { api, setAccessToken } from './api'

export interface LoginResult {
  access_token: string
  expires_in: number
}

export async function login(email: string, password: string): Promise<LoginResult> {
  const { data } = await api.post<LoginResult>('/auth/login', { email, password })
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
