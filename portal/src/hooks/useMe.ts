/**
 * portal/src/hooks/useMe.ts
 * ──────────────────────────
 * React Query hook for the current authenticated user.
 */
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'

export interface Me {
  id:           string
  email:        string
  display_name: string
  tenant_id:    string
  plan:         string
  notify_high:  boolean
  notify_block: boolean
  created_at:   string
}

export function useMe() {
  return useQuery<Me>({
    queryKey: ['me'],
    queryFn:  () => api.get<Me>('/me').then(r => r.data),
    staleTime: 5 * 60_000,
  })
}

export function useUpdateMe() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (patch: Partial<Me>) => api.patch<Me>('/me', patch).then(r => r.data),
    onSuccess:  () => qc.invalidateQueries({ queryKey: ['me'] }),
  })
}
