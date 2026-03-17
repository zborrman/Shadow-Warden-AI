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

api.interceptors.response.use(
  r => r,
  async err => {
    const original = err.config
    if (err.response?.status === 401 && !original._retry) {
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
