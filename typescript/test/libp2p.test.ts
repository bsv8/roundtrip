import { multiaddr } from '@multiformats/multiaddr'
import { webRTCDirect } from '@libp2p/webrtc'
import type { Libp2p } from '@libp2p/interface'
import { peerIdFromPublicKeyBytes } from 'bitcoin-libp2p/identity'
import { createHost } from 'bitcoin-libp2p/libp2p'
import { LocalSigner } from 'bitcoin-libp2p/signer'
import { readUvarintFrames, writeUvarintFrame } from 'bitcoin-libp2p/stream'
import { afterEach, describe, expect, it } from 'vitest'
import {
  LocalRoundtripSigner,
  ROUNDTRIP_PROTOCOL,
  RoundtripCore,
  libp2pExchange,
  publicKeyToString,
  serveLibp2p,
  type HandlerOutcome
} from '../src/index.js'
import { TEST_NOW, fixedRandom, testPrivateKey, testPublicKey, testSigner } from './fixtures.js'

/**
 * Stage 4, on real transports.
 *
 * WebSocket and WebRTC Direct are two different libp2p transports underneath,
 * and the same signed shell has to work over both. Nothing here is simulated:
 * every test opens a real UDP port or a real TCP socket.
 */

const TRANSPORT_TIMEOUT_MS = 60_000

interface Harness {
  serverNode: Libp2p
  clientNode: Libp2p
  serverCore: RoundtripCore
  clientCore: RoundtripCore
  calls: Array<{ op: string, from: string }>
  /** Removes the `/roundtrip/1` handler without stopping the nodes. */
  unregister: () => Promise<void>
  stop: () => Promise<void>
}

const running: Array<() => Promise<void>> = []

afterEach(async () => {
  while (running.length > 0) {
    const stop = running.pop()
    if (stop != null) await stop().catch(() => undefined)
  }
})

/**
 * One pair of nodes, both identities wired the way the construction order
 * requires: the application holds the key, configures the upstream host with a
 * TypedSigner view of it, and hands the same key to the roundtrip local signer.
 */
async function harness (transport: 'websocket' | 'webrtc-direct', options: { serverName?: string, clientName?: string, clientTransportName?: string, handler?: () => HandlerOutcome, maxMessageBytes?: number } = {}): Promise<Harness> {
  const serverName = options.serverName ?? 'bob'
  const clientName = options.clientName ?? 'alice'
  const serverKey = testPrivateKey(serverName)
  const clientKey = testPrivateKey(options.clientTransportName ?? clientName)
  const calls: Array<{ op: string, from: string }> = []

  const serverCore = new RoundtripCore({
    signer: testSigner(serverName),
    nowSeconds: () => TEST_NOW,
    maxMessageBytes: options.maxMessageBytes,
    handler: ({ body, callerPublicKey }) => {
      calls.push({ op: (body as { op: string }).op, from: publicKeyToString(callerPublicKey) })
      return options.handler == null ? { ok: true, result: { op: (body as { op: string }).op } } : options.handler()
    }
  })
  const clientCore = new RoundtripCore({ signer: testSigner(clientName), nowSeconds: () => TEST_NOW, randomBytes: fixedRandom(3) })

  const serverSigner = new LocalSigner(serverKey)
  // The upstream identity and the roundtrip business identity are the same key.
  expect(publicKeyToString(serverSigner.publicKey())).toBe(publicKeyToString(serverCore.publicKey()))

  const serverNode = transport === 'websocket'
    ? await createHost({ signer: serverSigner, listenAddrs: [multiaddr('/ip4/127.0.0.1/tcp/0/ws')] })
    : await createHost({
        signer: serverSigner,
        listenAddrs: [multiaddr('/ip4/127.0.0.1/udp/0/webrtc-direct')],
        transports: [webRTCDirect({ rtcConfiguration: { iceServers: [] } })]
      })
  const clientNode = transport === 'websocket'
    ? await createHost({ signer: new LocalSigner(clientKey) })
    : await createHost({ signer: new LocalSigner(clientKey), transports: [webRTCDirect({ rtcConfiguration: { iceServers: [] } })] })

  const serving = await serveLibp2p(serverNode, serverCore)
  // The adapter dials by business public key, so the address of the node that
  // owns that key has to be discoverable. In production that comes from a
  // directory, a peer record, or a previously seen peer.
  const serverPeer = peerIdFromPublicKeyBytes(serverCore.publicKey())
  const serverAddr = serverNode.getMultiaddrs().find((address) => transport === 'websocket'
    ? address.toString().includes('/ws')
    : address.toString().includes('/webrtc-direct'))
  if (serverAddr == null) throw new Error(`no ${transport} listen address`)
  await clientNode.peerStore.save(serverPeer, { multiaddrs: [serverAddr] })

  const unregister = async (): Promise<void> => {
    await serving.unregister()
  }
  const stop = async (): Promise<void> => {
    await unregister().catch(() => undefined)
    // stop() is typed as void or a promise depending on the state, so it is
    // wrapped before a catch can be attached.
    await Promise.resolve(clientNode.stop()).catch(() => undefined)
    await Promise.resolve(serverNode.stop()).catch(() => undefined)
  }
  running.push(stop)
  return { serverNode, clientNode, serverCore, clientCore, calls, unregister, stop }
}

const transportNames = ['websocket', 'webrtc-direct'] as const

describe('stage 4: the same signed shell over both transports', () => {
  for (const transport of transportNames) {
    it(`answers one call over ${transport}`, async () => {
      const { clientNode, serverCore, clientCore, calls } = await harness(transport)
      const outcome = await clientCore.call({
        to: serverCore.publicKey(),
        body: { op: 'get_balance', args: { asset: 'BSV' } },
        exchange: libp2pExchange(clientNode, serverCore.publicKey())
      })
      expect(outcome.ok).toBe(true)
      expect(outcome.ok === true ? outcome.result : null).toEqual({ op: 'get_balance' })
      expect(calls).toHaveLength(1)
      expect(calls[0].from).toBe(publicKeyToString(clientCore.publicKey()))
    }, TRANSPORT_TIMEOUT_MS)

    it(`serves concurrent calls on separate streams over ${transport}`, async () => {
      const { clientNode, serverCore, clientCore, calls } = await harness(transport)
      const outcomes = await Promise.all(Array.from({ length: 4 }, async (_value, index) =>
        await clientCore.call({
          to: serverCore.publicKey(),
          body: { op: `op_${index}` },
          exchange: libp2pExchange(clientNode, serverCore.publicKey())
        })))
      expect(outcomes.filter((outcome) => outcome.ok === true)).toHaveLength(4)
      expect(new Set(outcomes.map((outcome) => outcome.requestId)).size).toBe(4)
      expect(calls.map((entry) => entry.op).sort()).toEqual(['op_0', 'op_1', 'op_2', 'op_3'])
    }, TRANSPORT_TIMEOUT_MS)

    it(`refuses a duplicate delivery of the same request over ${transport}`, async () => {
      const { clientNode, serverCore, clientCore, calls } = await harness(transport)
      const prepared = await clientCore.buildRequest(serverCore.publicKey(), { op: 'transfer', args: { amount: '1.00000000' } })
      const exchange = libp2pExchange(clientNode, serverCore.publicKey())
      const first = await clientCore.send(prepared, exchange)
      const second = await clientCore.send(prepared, exchange)
      expect(first.ok).toBe(true)
      expect(second.ok === false ? second.error.code : '').toBe('REQUEST_ALREADY_SEEN')
      // Two deliveries of the same bytes, one execution.
      expect(calls).toHaveLength(1)
    }, TRANSPORT_TIMEOUT_MS)

    it(`refuses a request whose from is not the authenticated transport peer over ${transport}`, async () => {
      // The client node speaks as alice at the transport layer, but its roundtrip
      // signer claims to be carol. Connection authentication is not message
      // identity, and the adapter requires both to agree.
      const { clientNode, serverCore, calls } = await harness(transport, { clientTransportName: 'alice' })
      const impostor = new RoundtripCore({ signer: testSigner('carol'), nowSeconds: () => TEST_NOW })
      await expect(impostor.call({
        to: serverCore.publicKey(),
        body: { op: 'get_balance' },
        exchange: libp2pExchange(clientNode, impostor.publicKey())
      })).rejects.toThrow()
      expect(calls).toHaveLength(0)
    }, TRANSPORT_TIMEOUT_MS)

    it(`refuses to answer a call addressed to a peer it cannot authenticate over ${transport}`, async () => {
      const { clientNode, calls } = await harness(transport)
      // The target is carol's business key, but the node being dialled is bob.
      // A connection authenticated as somebody else must never answer a call
      // addressed to someone else.
      const exchange = libp2pExchange(clientNode, testPublicKey('carol'))
      const core = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW })
      await expect(core.call({ to: testPublicKey('carol'), body: { op: 'get_balance' }, exchange })).rejects.toThrow()
      expect(calls).toHaveLength(0)
    }, TRANSPORT_TIMEOUT_MS)

    it(`releases the stream after every call over ${transport}`, async () => {
      const { clientNode, serverNode, serverCore, clientCore } = await harness(transport)
      const exchange = libp2pExchange(clientNode, serverCore.publicKey())
      await clientCore.call({ to: serverCore.publicKey(), body: { op: 'one' }, exchange })
      await clientCore.call({ to: serverCore.publicKey(), body: { op: 'two' }, exchange })
      const peer = peerIdFromPublicKeyBytes(serverCore.publicKey())
      // One stream per call, and every one of them closed: no stream is left
      // open and no second request is multiplexed onto a used one.
      await waitFor(() => {
        const open = serverNode.getConnections(peer).flatMap((connection) => connection.streams)
          .filter((stream) => stream.status === 'open')
        return open.length === 0
      })
      const clientStreams = clientNode.getConnections(peer).flatMap((connection) => connection.streams)
      expect(clientStreams.filter((stream) => stream.status === 'open')).toHaveLength(0)
    }, TRANSPORT_TIMEOUT_MS)

    it(`refuses a message above the local frame limit over ${transport}`, async () => {
      const { clientNode, serverCore, clientCore, calls } = await harness(transport, { maxMessageBytes: 4096 })
      const outcome = await clientCore.call({
        to: serverCore.publicKey(),
        // Comfortably above both the 4 KiB core limit and nothing else: the
        // receiver must refuse it on its own local rule, with no negotiation.
        body: { op: 'upload', args: { blob: 'x'.repeat(16_384) } },
        exchange: libp2pExchange(clientNode, serverCore.publicKey())
      }).catch((error: Error) => error as Error)
      expect(outcome instanceof Error || outcome.ok === false).toBe(true)
      expect(calls).toHaveLength(0)
    }, TRANSPORT_TIMEOUT_MS)
  }
})

describe('stage 4: the stream carries exactly one request and one response', () => {
  it('treats a second frame on the same stream as a protocol error', async () => {
    const { clientNode, serverCore, calls } = await harness('websocket')
    const connection = await clientNode.dial(peerIdFromPublicKeyBytes(serverCore.publicKey()))
    const stream = await connection.newStream(ROUNDTRIP_PROTOCOL)
    const client = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW, randomBytes: fixedRandom(6) })
    const first = await client.buildRequest(serverCore.publicKey(), { op: 'first' })
    const second = await client.buildRequest(serverCore.publicKey(), { op: 'second' })
    writeUvarintFrame(stream, first.bytes)
    writeUvarintFrame(stream, second.bytes)
    // Half close, so the responder reaches the end of the request and finds the
    // second frame it must refuse.
    await stream.close()
    // The responder refuses the stream instead of answering the first request:
    // a stream that carries two requests is not a valid exchange, so the caller
    // gets no response at all.
    const received: Uint8Array[] = []
    const read = async (): Promise<void> => {
      for await (const frame of readUvarintFrames(stream)) {
        received.push(frame)
      }
    }
    await expect(read()).rejects.toThrow()
    expect(received).toHaveLength(0)
    expect(calls).toHaveLength(0)
  }, TRANSPORT_TIMEOUT_MS)

  it('answers exactly one frame on a well formed stream', async () => {
    const { clientNode, serverCore, calls } = await harness('websocket')
    const connection = await clientNode.dial(peerIdFromPublicKeyBytes(serverCore.publicKey()))
    const stream = await connection.newStream(ROUNDTRIP_PROTOCOL)
    const client = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW, randomBytes: fixedRandom(6) })
    const request = await client.buildRequest(serverCore.publicKey(), { op: 'get_balance' })
    writeUvarintFrame(stream, request.bytes)
    await stream.close()
    const received: Uint8Array[] = []
    for await (const frame of readUvarintFrames(stream)) {
      received.push(frame)
    }
    expect(received).toHaveLength(1)
    const outcome = client.verifyResponse(received[0], request)
    expect(outcome.ok).toBe(true)
    expect(calls).toHaveLength(1)
  }, TRANSPORT_TIMEOUT_MS)
})

describe('stage 4: the serving handler can be removed', () => {
  it('stops answering once the protocol is unregistered', async () => {
    const { clientNode, serverCore, clientCore, unregister } = await harness('websocket')
    const exchange = libp2pExchange(clientNode, serverCore.publicKey())
    expect((await clientCore.call({ to: serverCore.publicKey(), body: { op: 'ping' }, exchange })).ok).toBe(true)
    // Unregistering is what a deployment does when it stops offering the
    // protocol; the stream handler must not keep running afterwards.
    await unregister()
    const after = await clientCore.call({ to: serverCore.publicKey(), body: { op: 'ping' }, exchange }).catch((error: Error) => error as Error)
    expect(after instanceof Error).toBe(true)
  }, TRANSPORT_TIMEOUT_MS)
})

/** Waits for a condition, so stream teardown is observed instead of assumed. */
async function waitFor (condition: () => boolean, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (condition()) return
    await new Promise((resolve) => setTimeout(resolve, 20))
  }
  throw new Error('condition was not met before the deadline')
}

/** Kept for symmetry with the harness: the local signer and the upstream signer agree. */
it('uses the same key for the transport identity and the business identity', () => {
  const signer = new LocalRoundtripSigner(testPrivateKey('alice'))
  expect(publicKeyToString(signer.publicKey())).toBe(publicKeyToString(new LocalSigner(testPrivateKey('alice')).publicKey()))
})
