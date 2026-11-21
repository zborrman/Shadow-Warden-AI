import axios from 'axios'

export const API_URL = process.env.NEXT_PUBLIC_API_URL || 'https://api.shadow-warden-ai.com'

// Token stored in memory — never localStorage (XSS protection)
let _accessToken: string | null = null

export function setAccessToken(token: string | null) { _accessToken = token }
export function getAccessToken() { return _accessToken }

export const api = axios.create({
  baseURL: `${API_URL}/portal`,
  withCredentials: true,   // sends the HttpOnly refresh cookie
})

// Attach access token to every request
api.interceptors.request.use(cfg => {
  if (_accessToken) cfg.headers['Authorization'] = `Bearer ${_accessToken}`
  return cfg
})

// Auto-refresh on 401
let _refreshing: Promise<string> | null = null

// On these a 401 is the answer (wrong password or code), not an expired
// session: refreshing and reloading /login/ would wipe the form and hide the
// message, and on change-password or close it would sign the person out.
const ANSWERS_401 = /\/auth\/(login|register|refresh|totp\/complete|forgot-password|reset-password)\/?$|\/me\/(change-password|close)\/?$/

api.interceptors.response.use(
  r => r,
  async err => {
    const original = err.config
    if (err.response?.status === 401 && !original._retry && !ANSWERS_401.test(original.url ?? '')) {
      original._retry = true
      try {
        if (!_refreshing) {
          _refreshing = axios
            .post(`${API_URL}/portal/auth/refresh`, {}, { withCredentials: true })
            .then(r => {
              const token = r.data.access_token as string
              setAccessToken(token)
              _refreshing = null
              return token
            })
            .catch(e => {
              _refreshing = null
              setAccessToken(null)
              throw e
            })
        }
        const newToken = await _refreshing
        original.headers['Authorization'] = `Bearer ${newToken}`
        return axios(original)
      } catch {
        // Refresh failed → redirect to login
        if (typeof window !== 'undefined') window.location.href = '/login/'
      }
    }
    return Promise.reject(err)
  }
)

/** Authorization header for the portal's own /api/* proxies, which check the session. */
export function sessionHeaders(): Record<string, string> {
  return _accessToken ? { Authorization: `Bearer ${_accessToken}` } : {}
}
