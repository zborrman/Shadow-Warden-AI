'use client'
/**
 * portal/src/context/AuthContext.tsx
 * ────────────────────────────────────
 * Provides the authenticated user and auth actions to the component tree.
 * Wraps React Query's useMe() so auth state is available without prop drilling.
 *
 * Usage:
 *   const { user, isLoading, logout } = useAuth()
 */
import { createContext, useContext, useCallback, type ReactNode } from 'react'
import { useRouter } from 'next/navigation'
import { useQueryClient } from '@tanstack/react-query'
import { useMe, type Me } from '@/hooks/useMe'
import { logout as authLogout } from '@/lib/auth'

interface AuthContextValue {
  user:      Me | undefined
  isLoading: boolean
  isAuthed:  boolean
  logout:    () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const { data: user, isLoading } = useMe()
  const router   = useRouter()
  const qc       = useQueryClient()

  const logout = useCallback(async () => {
    await authLogout()
    qc.clear()
    router.replace('/login/')
  }, [qc, router])

  return (
    <AuthContext.Provider value={{ user, isLoading, isAuthed: !!user, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within <AuthProvider>')
  return ctx
}
