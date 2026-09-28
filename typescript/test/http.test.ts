import { createServer, type Server } from 'node:http'
import { once } from 'node:events'
import type { AddressInfo } from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'
import {
  HTTP_PATH,
  LocalRoundtripSigner,
  MemoryReplayGuard,
  RoundtripCore,
  createHttpEndpoint,
  encodeBase64Url,
  httpExchange,
  isRoundtripError,
  parseJsonText,
  parseResponse,
  publicKeyToString,
  toNodeHandler,
  type HandlerOutcome,
  type HttpResponseView,
  type ReplayGuard
} from '../src/index.js'
import {
  TEST_NOW,
  fixedRandom,
  signedRequestBytes,
  testPrivateKey,
  testPublicKey,
  testSigner,
  unsignedResponse,
  wireOf
} from './fixtures.js'

/**
 * Stage 5 over real HTTP.
 *
 * HTTP already pairs a request with a response, which is exactly why the shell
 * still carries `reply_to`: an attacker on a plain HTTP path can substitute an
 * older validly signed response, and only the correlation field stops it.
 */

const text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes)

async function codeOf (body: () => Promise<unknown>): Promise<string> {
  try {
    await body()
    return ''
  } catch (error) {
    return isRoundtripError(error) ? error.code : 'NOT_A_ROUNDTRIP_ERROR'
  }
}

interface Service {
  core: RoundtripCore
  calls: Array<{ op: string, from: string }>
  url: string
  close: () => Promise<void>
}

const running: Array<() => Promise<void>> = []

afterEach(async () => {
  while (running.length > 0) {
    const close = running.pop()
    if (close != null) await close().catch(() => undefined)
  }
})

/** A real node:http server in front of a real core, plus the URL to reach it. */
async function service (options: { name?: string, handler?: () => HandlerOutcome | Promise<HandlerOutcome>, replay?: ReplayGuard, maxBodyBytes?: number, path?: string } = {}): Promise<Service> {
  const calls: Array<{ op: string, from: string }> = []
  const core = new RoundtripCore({
    signer: testSigner(options.name ?? 'bob'),
    nowSeconds: () => TEST_NOW,
    replay: options.replay,
    handler: async ({ body, callerPublicKey }) => {
      calls.push({ op: (body as { op: string }).op, from: publicKeyToString(callerPublicKey) })
      return options.handler == null ? { ok: true, result: { op: (body as { op: string }).op } } : await options.handler()
    }
  })
  const endpoint = createHttpEndpoint(core, options.path == null ? {} : { path: options.path })
  const server: Server = createServer(toNodeHandler(endpoint, options.maxBodyBytes ?? 1024 * 1024))
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const port = (server.address() as AddressInfo).port
  const close = async (): Promise<void> => {
    server.closeAllConnections()
    server.close()
    await once(server, 'close')
  }
  running.push(close)
  return { core, calls, url: `http://127.0.0.1:${port}${options.path ?? HTTP_PATH}`, close }
}

const client = (name = 'alice'): RoundtripCore => new RoundtripCore({ signer: testSigner(name), nowSeconds: () => TEST_NOW, randomBytes: fixedRandom(3) })

describe('stage 5: a signed shell over POST', () => {
  it('answers one signed request with one signed response', async () => {
    const server = await service({ handler: () => ({ ok: true, result: { confirmed: 42 } }) })
    const caller = client()
    const outcome = await caller.call({ to: server.core.publicKey(), body: { op: 'get_balance', args: { asset: 'BSV' } }, exchange: httpExchange(server.url) })
    expect(outcome.ok).toBe(true)
    expect(outcome.ok === true ? outcome.result : null).toEqual({ confirmed: 42 })
    expect(server.calls).toHaveLength(1)
    expect(server.calls[0].from).toBe(publicKeyToString(caller.publicKey()))
  })

  it('returns a signed business failure as 200, not as an HTTP error', async () => {
    const server = await service({ handler: () => ({ ok: false, error: { code: 'UNKNOWN_ASSET', message: '没有这个资产' } }) })
    const outcome = await client().call({ to: server.core.publicKey(), body: { op: 'get_balance' }, exchange: httpExchange(server.url) })
    expect(outcome.ok).toBe(false)
    expect(outcome.ok === false ? outcome.error : null).toEqual({ code: 'UNKNOWN_ASSET', message: '没有这个资产' })
  })

  it('takes the operation from the signed body only', async () => {
    const server = await service()
    const caller = client()
    // A URL query and unsigned headers are transport decoration. The signed
    // body decides what runs, so a header cannot switch the operation.
    const response = await fetch(`${server.url}?op=delete_everything`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-op': 'delete_everything' },
      body: await caller.buildRequest(server.core.publicKey(), { op: 'get_balance' }).then((prepared) => prepared.bytes)
    })
    expect(response.status).toBe(200)
    expect(server.calls).toEqual([{ op: 'get_balance', from: publicKeyToString(caller.publicKey()) }])
  })

  it('serves concurrent calls, each with its own answer', async () => {
    const server = await service()
    const caller = client()
    const outcomes = await Promise.all(Array.from({ length: 4 }, async (_value, index) =>
      await caller.call({ to: server.core.publicKey(), body: { op: `op_${index}` }, exchange: httpExchange(server.url) })))
    expect(outcomes.every((outcome) => outcome.ok === true)).toBe(true)
    expect(new Set(outcomes.map((outcome) => outcome.requestId)).size).toBe(4)
  })

  it('refuses a request addressed to another identity', async () => {
    const server = await service()
    const response = await fetch(server.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: signedRequestBytes({ to: testPublicKey('carol') })
    })
    expect(response.status).toBe(403)
    expect(server.calls).toHaveLength(0)
  })
})

describe('stage 5: an entry error is never a business result', () => {
  const post = async (url: string, body: Uint8Array, method = 'POST'): Promise<{ status: number, body: string }> => {
    const response = await fetch(url, { method, headers: { 'content-type': 'application/json' }, body })
    return { status: response.status, body: await response.text() }
  }

  it('uses 4xx for entry problems and never signs them', async () => {
    const server = await service()
    const caller = client()
    const request = (await caller.buildRequest(server.core.publicKey(), { op: 'ping' })).bytes
    expect((await post(`${server.url}x`, request)).status).toBe(404)
    expect((await fetch(server.url, { method: 'GET' })).status).toBe(405)
    const wrongType = await fetch(server.url, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: request })
    expect(wrongType.status).toBe(415)
    // Malformed input is an entry error.
    expect((await post(server.url, new TextEncoder().encode('{"from":'))).status).toBe(400)
    // A body that was changed after signing is an entry error too: it is a
    // correctly shaped message whose signature does not verify.
    const tampered = wireOf(signedRequestBytes())
    const changed = { ...tampered, body: { op: 'transfer', args: { amount: '1000.00000000' } } }
    expect((await post(server.url, new TextEncoder().encode(JSON.stringify(changed)))).status).toBe(400)
    expect((await post(server.url, request, 'PUT')).status).toBe(405)
    expect(server.calls).toHaveLength(0)
  })

  it('rejects a body above the local limit with 413', async () => {
    const server = await service({ maxBodyBytes: 512 })
    const caller = client()
    const request = (await caller.buildRequest(server.core.publicKey(), { op: 'upload', args: { blob: 'x'.repeat(4096) } })).bytes
    const response = await fetch(server.url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: request })
    expect([413, 400]).toContain(response.status)
    expect(server.calls).toHaveLength(0)
  })

  it('makes the client treat a non 2xx status as a transport failure', async () => {
    const server = await service()
    const caller = client()
    // The entry refuses the request with an unsigned 403. The client must report
    // a transport failure, because a status code is not a signed business result.
    const exchange = httpExchange(server.url, {
      fetch: async (_url, init) => await fetch(server.url, init as RequestInit)
    })
    const prepared = await caller.buildRequest(testPublicKey('carol'), { op: 'ping' })
    expect(await codeOf(async () => await caller.send({ ...prepared, unsigned: { ...prepared.unsigned, to: testPublicKey('carol') } }, exchange))).toBe('ERR_HTTP_STATUS')
  })

  it('refuses a proxy error page dressed up as a 200', async () => {
    const caller = client()
    // An intermediary that answers 200 with an HTML error page is a transport
    // failure, never a business result the caller can act on.
    const exchange = httpExchange('http://127.0.0.1:1/roundtrip', {
      fetch: async () => await Promise.resolve(new Response('<html>502 Bad Gateway</html>', { status: 200, headers: { 'content-type': 'text/html' } }))
    })
    // It fails while reading the body, long before any result could be trusted.
    expect(await codeOf(async () => await caller.call({ to: testPublicKey('bob'), body: { op: 'ping' }, exchange }))).toBe('ERR_JSON_SYNTAX')
  })

  it('bounds the response it reads from the network', async () => {
    const caller = client()
    const prepared = await caller.buildRequest(testPublicKey('bob'), { op: 'ping' })
    const big = 'x'.repeat(4096)
    const exchange = httpExchange('http://127.0.0.1:1/roundtrip', {
      maxResponseBytes: 128,
      fetch: async () => await Promise.resolve(new Response(big, { status: 200 }))
    })
    expect(await codeOf(async () => await caller.send(prepared, exchange))).toBe('ERR_RESPONSE_SIZE')
  })
})

describe('stage 5: HTTP does not replace the signed correlation', () => {
  it('refuses an older validly signed response substituted into the current call', async () => {
    const server = await service()
    const caller = client()
    const exchange = httpExchange(server.url)
    // A first call, answered honestly.
    const first = await caller.call({ to: server.core.publicKey(), body: { op: 'op_first' }, exchange })
    expect(first.ok).toBe(true)
    // A second, different call. The attacker replays the saved answer to the
    // first one, which is perfectly signed and comes from the right peer.
    const second = await caller.buildRequest(server.core.publicKey(), { op: 'op_second' })
    const savedFirst = await exchange((await caller.buildRequest(server.core.publicKey(), { op: 'op_first' })).bytes, new AbortController().signal)
    // The stale answer has a reply_to for a different request id.
    expect(await codeOf(async () => await caller.verifyResponse(savedFirst, second))).toBe('ERR_RESPONSE_REPLY_TO')
    expect(server.calls).toHaveLength(2)
  })

  it('refuses a response from the wrong peer on the same path', async () => {
    const caller = client()
    const prepared = await caller.buildRequest(testPublicKey('bob'), { op: 'ping' })
    // Carol answers a request that was addressed to Bob. It is signed, it is
    // addressed to Alice, and it is still not an answer to this call.
    const carol = new RoundtripCore({
      signer: testSigner('carol'),
      nowSeconds: () => TEST_NOW,
      handler: () => ({ ok: true, result: { stolen: true } })
    })
    const carolResponse = await carol.handle(signedRequestBytes({ from: caller.publicKey(), to: testPublicKey('carol') }))
    expect(await codeOf(async () => await caller.verifyResponse(carolResponse, prepared))).toBe('ERR_RESPONSE_FROM')
  })

  it('refuses a trimmed response without reply_to, which is not a base response', async () => {
    const caller = client()
    // The optional trusted HTTPS shape drops reply_to and signs with its own
    // prefix. A base receiver must refuse it: dropping the field also drops the
    // proof that the response answers this call.
    const signer = new LocalRoundtripSigner(testPrivateKey('bob'))
    const signature = await signer.signRoundtrip(unsignedResponse({
      from: testPublicKey('bob'),
      to: caller.publicKey(),
      replyTo: new Uint8Array(32),
      body: { ok: true, result: { stolen: true } }
    }))
    const trimmed = {
      from: publicKeyToString(testPublicKey('bob')),
      to: publicKeyToString(caller.publicKey()),
      body: { ok: true, result: { stolen: true } },
      sig: encodeBase64Url(signature)
    }
    // The base parser refuses the shape on its own.
    expect(() => { parseResponse(JSON.parse(JSON.stringify(trimmed)) as never) }).toThrow()
    // And a call in flight cannot be completed with it either.
    const prepared = await caller.buildRequest(testPublicKey('bob'), { op: 'ping' })
    expect(await codeOf(async () => await caller.verifyResponse(new TextEncoder().encode(JSON.stringify(trimmed)), prepared))).toBe('ERR_ENVELOPE_FIELD_MISSING')
  })
})

describe('stage 5: one dedup store covers both transports', () => {
  it('refuses a request captured on one transport when it is replayed on the other', async () => {
    // The application shares one handler and one guard, so a message captured
    // from the libp2p path and delivered over HTTP is still the same request.
    const shared = new MemoryReplayGuard(() => TEST_NOW)
    const server = await service({ replay: shared })
    const caller = client()
    const exchange = httpExchange(server.url)
    const prepared = await caller.buildRequest(server.core.publicKey(), { op: 'transfer', args: { amount: '1.00000000' } })
    expect((await caller.send(prepared, exchange)).ok).toBe(true)
    // Same bytes, delivered again over the same endpoint, and also straight
    // into the core the way the libp2p adapter would deliver it.
    const viaHttp = await exchange(prepared.bytes, new AbortController().signal)
    expect((JSON.parse(text(viaHttp)) as { body: { error: { code: string } } }).body.error.code).toBe('REQUEST_ALREADY_SEEN')
    const viaCore = await server.core.handle(prepared.bytes)
    expect((JSON.parse(text(viaCore)) as { body: { error: { code: string } } }).body.error.code).toBe('REQUEST_ALREADY_SEEN')
    // One execution in total.
    expect(server.calls).toHaveLength(1)
  })

  it('refuses a request addressed to another identity even when it is validly signed', async () => {
    const server = await service()
    // A request captured for Bob, replayed to the same service as if it were
    // for Carol. Only Bob's node may run it.
    const response = await fetch(server.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: signedRequestBytes({ to: testPublicKey('bob'), from: testPublicKey('alice') })
    })
    expect(response.status).toBe(200)
    expect(server.calls).toHaveLength(1)
    const caller = client()
    const carolService = await service({ name: 'carol' })
    const refused = await fetch(carolService.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: signedRequestBytes({ to: testPublicKey('bob'), from: testPublicKey('alice') })
    })
    expect(refused.status).toBe(403)
    expect(carolService.calls).toHaveLength(0)
  })
})

describe('stage 5: a timeout is not a statement about the business', () => {
  it('does not retry, and lets the business finish exactly once', async () => {
    let finished = 0
    const server = await service({
      handler: async (): Promise<HandlerOutcome> => {
        await new Promise((resolve) => setTimeout(resolve, 300))
        finished++
        return { ok: true, result: { done: true } }
      }
    })
    const caller = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW, randomBytes: fixedRandom(3), callTimeoutMs: 40 })
    expect(await codeOf(async () => await caller.call({ to: server.core.publicKey(), body: { op: 'slow' }, exchange: httpExchange(server.url) }))).toBe('ERR_CALL_TIMEOUT')
    // Exactly one delivery: a timeout must not turn into an automatic retry,
    // which would be a second call pretending to be the first.
    await new Promise((resolve) => setTimeout(resolve, 400))
    expect(server.calls).toHaveLength(1)
    expect(finished).toBe(1)
  })
})

describe('stage 5: the endpoint is transport neutral', () => {
  it('can be driven directly, without a socket', async () => {
    const core = new RoundtripCore({ signer: testSigner('bob'), nowSeconds: () => TEST_NOW, handler: () => ({ ok: true, result: { via: 'direct' } }) })
    const endpoint = createHttpEndpoint(core)
    const caller = client()
    const prepared = await caller.buildRequest(core.publicKey(), { op: 'ping' })
    const view: HttpResponseView = await endpoint({
      method: 'POST',
      path: HTTP_PATH,
      // A charset parameter must not change the decision.
      contentType: 'application/json; charset=utf-8',
      body: prepared.bytes
    })
    expect(view.status).toBe(200)
    expect(caller.verifyResponse(view.body, prepared).ok).toBe(true)
  })
})
