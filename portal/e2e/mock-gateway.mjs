// A stand-in for the gateway's anonymous storefront routes, for the CI audit.
// It replays fixtures/storefront.json, recorded from the real router by
// scripts/storefront_fixture.py (a pytest test fails if the router's shapes
// drift from it). Owner routes are not served: the audit covers the public
// storefront only.
//
//   node e2e/mock-gateway.mjs            # listens on 127.0.0.1:18011
import { createServer } from 'node:http'
import { readFileSync } from 'node:fs'
import { deflateSync } from 'node:zlib'

const fx = JSON.parse(readFileSync(new URL('./fixtures/storefront.json', import.meta.url), 'utf8'))
const PORT = Number(process.env.MOCK_GATEWAY_PORT || 18011)
const BASE = `/m2m-store/storefront/${fx.slug}`
const TOKEN = 'fixture-order-token-0123456789abcdefghij'
let order = structuredClone(fx.order_request)

// A 1x1 PNG, built here so the fixture holds no binary.
function png(r, g, b) {
  const crc = buf => {
    let c = ~0
    for (const byte of buf) { c ^= byte; for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1)) }
    return ~c >>> 0
  }
  const chunk = (type, data) => {
    const body = Buffer.concat([Buffer.from(type), data])
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length)
    const sum = Buffer.alloc(4); sum.writeUInt32BE(crc(body))
    return Buffer.concat([len, body, sum])
  }
  const ihdr = Buffer.from([0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0])
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr), chunk('IDAT', deflateSync(Buffer.from([0, r, g, b]))), chunk('IEND', Buffer.alloc(0)),
  ])
}
const IMAGE = png(200, 160, 60)

function send(res, status, body, headers = {}) {
  const isBuf = Buffer.isBuffer(body)
  res.writeHead(status, {
    'Content-Type': isBuf ? 'image/png' : 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, X-Order-Token',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    ...headers,
  })
  res.end(isBuf ? body : JSON.stringify(body))
}

createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`)
  const p = url.pathname
  if (req.method === 'OPTIONS') return send(res, 204, '')
  if (!p.startsWith(BASE)) return send(res, 404, { detail: 'store not found' })
  const rest = p.slice(BASE.length)
  const tokenOk = req.headers['x-order-token'] === TOKEN

  if (req.method === 'GET' && rest === '') return send(res, 200, fx.store)
  if (req.method === 'GET' && rest === '/catalog/ucp') return send(res, 200, fx.feed)
  if (req.method === 'GET' && rest.startsWith('/images/')) return send(res, 200, IMAGE)
  if (req.method === 'GET' && rest === '/shipping/quote') {
    return send(res, 200, { ...fx.quote, country: (url.searchParams.get('country') || 'DE').toUpperCase() })
  }
  if (req.method === 'POST' && rest === '/order-requests') {
    order = structuredClone(fx.order_request)
    return send(res, 201, { ...order, buyer_token: TOKEN })
  }
  if (rest === `/order-requests/${order.id}`) {
    return tokenOk ? send(res, 200, order) : send(res, 404, { detail: 'order request not found' })
  }
  if (req.method === 'POST' && rest === `/order-requests/${order.id}/cancel`) {
    if (!tokenOk) return send(res, 404, { detail: 'order request not found' })
    order = { ...order, status: 'CANCELLED',
              history: [...order.history, { status: 'CANCELLED', at: new Date().toISOString(), by: 'buyer' }] }
    return send(res, 200, order)
  }
  return send(res, 404, { detail: 'Not Found' })
}).listen(PORT, '127.0.0.1', () => console.log(`mock gateway on 127.0.0.1:${PORT}`))

