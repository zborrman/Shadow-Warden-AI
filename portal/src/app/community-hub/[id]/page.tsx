'use client'
/**
 * /community-hub/[id] — permanent redirect to new hub design at /community-hub/hub/[id]
 */
import { useEffect } from 'react'
import { useParams, useRouter } from 'next/navigation'

export default function CommunityHubLegacyRedirect() {
  const { id } = useParams<{ id: string }>()
  const router  = useRouter()

  useEffect(() => {
    router.replace(`/community-hub/hub/${id}`)
  }, [id, router])

  return null
}
