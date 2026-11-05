import type { Metadata } from 'next'
import { OrderView } from '../../_components/OrderView'

// A buyer's own order request: private to whoever holds the link.
export const metadata: Metadata = { robots: { index: false, follow: false }, referrer: 'no-referrer' }

export default function OrderRequestPage({ params }: { params: { id: string } }) {
  return <OrderView id={params.id} />
}
