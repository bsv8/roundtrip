/**
 * The smallest useful deployment: one service and one client over plain HTTP.
 *
 * Run it with:
 *   npm run example:http
 *
 * What this example shows:
 *   - the application holds the key, and only the signer ever sees it;
 *   - `body.op` is the only business input, the URL decides nothing;
 *   - a business failure comes back as a signed 200, not as an HTTP error;
 *   - a repeated request is refused instead of executed twice.
 *
 * The key below is generated for this run and thrown away when the process
 * exits. Nothing here is a production key, and a real deployment supplies the
 * key from its own trusted boundary instead of generating one at startup.
 */
import { createServer } from 'node:http'
import { once } from 'node:events'
import type { AddressInfo } from 'node:net'
import {
  LocalRoundtripSigner,
  RoundtripCore,
  createHttpEndpoint,
  httpExchange,
  toNodeHandler,
  type HandlerOutcome,
  type JsonObject
} from '../dist/index.js'

/** A throw away identity for the demo. Never reuse, never store, never ship. */
function ephemeralKey (label: string): Uint8Array {
  const bytes = new Uint8Array(32)
  globalThis.crypto.getRandomValues(bytes)
  // Keep it in 1..n-1. A zero or out of range scalar is not a key.
  bytes[0] = (bytes[0] % 0x7f) + 1
  return bytes
}

const serviceKey = ephemeralKey('service')
const callerKey = ephemeralKey('caller')

/** The application decides what a call means, and who is allowed to make it. */
async function handleCall (context: { callerPublicKey: Uint8Array, body: unknown }): Promise<HandlerOutcome> {
  const body = context.body as JsonObject
  const op = body.op
  if (op === 'get_balance') {
    return { ok: true, result: { confirmed: 42, satoshis: '1050000000' } }
  }
  if (op === 'transfer') {
    const args = body.args as JsonObject | undefined
    return { ok: false, error: { code: 'INSUFFICIENT_FUNDS', message: `cannot send ${String(args?.amount ?? '?')} BSV` } }
  }
  // Unknown operations are a business answer, signed like any other.
  return { ok: false, error: { code: 'UNKNOWN_OP', message: `no such operation: ${String(op)}` } }
}

const service = new RoundtripCore({ signer: new LocalRoundtripSigner(serviceKey), handler: handleCall })
const server = createServer(toNodeHandler(createHttpEndpoint(service)))
server.listen(0, '127.0.0.1')
await once(server, 'listening')
const port = (server.address() as AddressInfo).port
const url = `http://127.0.0.1:${port}/roundtrip`

const caller = new RoundtripCore({ signer: new LocalRoundtripSigner(callerKey) })
const call = async (body: JsonObject): Promise<string> => {
  const outcome = await caller.call({ to: service.publicKey(), body, exchange: httpExchange(url) })
  return outcome.ok
    ? `ok ${JSON.stringify(outcome.result)}`
    : `business error ${outcome.error.code}: ${outcome.error.message}`
}

console.log('service public key', Buffer.from(service.publicKey()).toString('base64url'))
console.log('roundtrip ->', await call({ op: 'get_balance', args: { asset: 'BSV' } }))
console.log('transfer  ->', await call({ op: 'transfer', args: { amount: '2.00000000' } }))
console.log('unknown   ->', await call({ op: 'drop_tables' }))

// The same request delivered twice runs the business once. A retransmission
// keeps its id, so the second delivery is recognised instead of repeated.
const prepared = await caller.buildRequest(service.publicKey(), { op: 'get_balance', args: { asset: 'BSV' } })
const exchange = httpExchange(url)
const first = await caller.send(prepared, exchange)
const second = await caller.send(prepared, exchange)
console.log('delivered twice ->', first.ok ? 'first executed' : 'failed', '/', second.ok ? 'executed again' : second.error.code)

server.closeAllConnections()
server.close()
await once(server, 'close')
