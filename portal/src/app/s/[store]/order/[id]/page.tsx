import type { Metadata } from 'next'
import { OrderView } from '../../_components/OrderView'

// A buyer's own order request: private to whoever holds the link.
export const metadata: Metadata = { robots: { index: false, follow: false }, referrer: 'no-referrer' }

export default async function OrderRequestPage(props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  return <OrderView id={params.id} />
}
