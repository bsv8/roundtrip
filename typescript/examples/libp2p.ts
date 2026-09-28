/**
 * The same signed shell over both libp2p transports.
 *
 * Run it with:
 *   npm run example:libp2p
 *
 * What this example shows:
 *   - the application holds one key and configures both the upstream libp2p
 *     identity and the roundtrip signer with it, so the transport identity and
 *     the business identity are the same public key;
 *   - WebSocket and WebRTC Direct carry the identical shell, one stream per call;
 *   - the responder checks that the request `from` is the authenticated peer, so
 *     a relay cannot forward someone else's signed request.
 *
 * Both keys are generated for this run and thrown away when the process exits.
 * A real deployment loads the key from its own trusted boundary.
 */
import { multiaddr } from '@multiformats/multiaddr'
import { webRTCDirect } from '@libp2p/webrtc'
import { peerIdFromPublicKeyBytes } from 'bitcoin-libp2p/identity'
import { createHost } from 'bitcoin-libp2p/libp2p'
import { LocalSigner } from 'bitcoin-libp2p/signer'
import type { Libp2p } from '@libp2p/interface'
import {
  LocalRoundtripSigner,
  RoundtripCore,
  libp2pExchange,
  publicKeyToString,
  serveLibp2p,
  type HandlerOutcome,
  type JsonObject
} from '../dist/index.js'

/** A throw away identity for the demo. Never reuse, never store, never ship. */
function ephemeralKey (): Uint8Array {
  const bytes = new Uint8Array(32)
  globalThis.crypto.getRandomValues(bytes)
  bytes[0] = (bytes[0] % 0x7f) + 1
  return bytes
}

const serviceKey = ephemeralKey()
const callerKey = ephemeralKey()

const service = new RoundtripCore({
  signer: new LocalRoundtripSigner(serviceKey),
  handler: ({ body, callerPublicKey }): HandlerOutcome => ({
    ok: true,
    result: {
      op: (body as JsonObject).op,
      caller: publicKeyToString(callerPublicKey).slice(0, 12),
      at: 'service'
    }
  })
})
const caller = new RoundtripCore({ signer: new LocalRoundtripSigner(callerKey) })

// The upstream host gets a TypedSigner view of the same key. It never sees the
// private key, and the roundtrip signer never sees anything but a message to
// sign.
const serviceSigner = new LocalSigner(serviceKey)
const callerSigner = new LocalSigner(callerKey)
console.log('service public key', publicKeyToString(service.publicKey()))
console.log('same key for the transport identity:', publicKeyToString(serviceSigner.publicKey()) === publicKeyToString(service.publicKey()))

async function run (label: string, listenAddrs: Parameters<typeof createHost>[0]['listenAddrs'], transports: Parameters<typeof createHost>[0]['transports']): Promise<void> {
  const serviceNode: Libp2p = await createHost({ signer: serviceSigner, listenAddrs, ...(transports == null ? {} : { transports }) })
  const callerNode: Libp2p = await createHost({ signer: callerSigner, ...(transports == null ? {} : { transports }) })
  try {
    const serving = await serveLibp2p(serviceNode, service)
    const address = serviceNode.getMultiaddrs().find((entry) => label === 'websocket' ? entry.toString().includes('/ws') : entry.toString().includes('/webrtc-direct'))
    if (address == null) throw new Error(`no ${label} address was announced`)
    // The adapter dials by business public key, so the address that belongs to
    // that key has to be known. A deployment gets it from a directory, a peer
    // record or a peer it has met before.
    await callerNode.peerStore.save(peerIdFromPublicKeyBytes(service.publicKey()), { multiaddrs: [address] })

    const outcome = await caller.call({
      to: service.publicKey(),
      body: { op: 'get_balance', args: { asset: 'BSV' } },
      exchange: libp2pExchange(callerNode, service.publicKey())
    })
    console.log(`${label} ->`, outcome.ok ? JSON.stringify(outcome.result) : `business error ${outcome.error.code}`)

    // A retransmission keeps its id, so the business does not run twice.
    const prepared = await caller.buildRequest(service.publicKey(), { op: 'transfer', args: { amount: '1.00000000' } })
    const exchange = libp2pExchange(callerNode, service.publicKey())
    await caller.send(prepared, exchange)
    const again = await caller.send(prepared, exchange)
    console.log(`${label} -> delivered twice:`, again.ok ? 'executed again' : again.error.code)
    await serving.unregister()
  } finally {
    await callerNode.stop()
    await serviceNode.stop()
  }
}

// WebSocket, then WebRTC Direct: same shell, same identities, same rules.
await run('websocket', [multiaddr('/ip4/127.0.0.1/tcp/0/ws')], undefined)
await run('webrtc-direct', [multiaddr('/ip4/127.0.0.1/udp/0/webrtc-direct')], [webRTCDirect({ rtcConfiguration: { iceServers: [] } })])
